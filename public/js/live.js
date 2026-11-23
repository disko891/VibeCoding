// 공격 관제 맵
// 1) 최근 이벤트를 시간 순서대로 빠르게 재생 (REPLAY)
// 2) 재생이 끝나면 15초마다 새 이벤트를 받아서 표시 (LIVE)
// 해결(RESOLVED)된 공격 → 방어선에서 차단 / 미처리·조사중 공격 → 대상 서버 피격
(() => {
  const canvas = document.getElementById('liveCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const stage = document.getElementById('liveStage');
  const $ = (id) => document.getElementById(id);

  // 위험도별 색/점수 가중치/점 크기 (style.css 색과 동일)
  const SEV = {
    LOW: { color: '#5a8fc9', weight: 1, size: 3 },
    MEDIUM: { color: '#c4a13a', weight: 2, size: 3.6 },
    HIGH: { color: '#d0782f', weight: 3, size: 4.2 },
    CRITICAL: { color: '#d04444', weight: 5, size: 5.2 },
  };
  const C = {
    grid: 'rgba(122, 134, 150, 0.09)',
    dim: '#7a8696',
    text: '#c8d0da',
    bright: '#e6edf3',
    panel: '#12161c',
    line: '#2e3843',
    shield: '#4d9de0',
    hit: '#d04444',
    internal: '#c4a13a',
  };
  const MONO = '"Cascadia Mono", Consolas, monospace';
  const SANS = getComputedStyle(document.body).fontFamily;

  const FLIGHT_SEC = 1.8;            // 공격 하나가 날아가는 시간 (1x 기준)
  const INTERCEPT_AT = 0.8;          // 방어선에서 막히는 지점 (경로의 80%)
  const POLL_MS = 15 * 1000;         // LIVE 모드 갱신 주기
  const IDLE_PAUSE_MS = 10 * 60 * 1000; // 10분 동안 입력 없으면 갱신 멈춤 (자동 로그아웃이 동작하도록)
  const FEED_MAX = 80;
  const REPLAY_MAX = 200;
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ---- 상태 ----
  const groups = new Map();  // 출발지 국가별 노드
  const targets = new Map(); // 공격 대상 서버 노드
  const core = { x: 0, y: 0 };
  let W = 0;
  let H = 0;
  let shieldRx = 0;
  let shieldRy = 0;
  let needLayout = true;

  let allEvents = [];
  let schedule = [];
  let missiles = [];
  let effects = [];
  let floats = [];
  let replayLabel = '';
  let statsDirty = true;

  const st = {
    mode: 'loading', playing: true, speed: 1, clock: 0, qi: 0, lastId: 0, open: null,
    shake: 0, shieldFlash: 0, sweep: 0,
    detected: 0, blocked: 0, hit: 0, score: 0, combo: 0, best: 0,
  };

  // ---- 유틸 ----
  const hash = (s) => {
    let h = 0;
    for (const ch of String(s)) h = (h * 31 + ch.charCodeAt(0)) | 0;
    return Math.abs(h);
  };
  const parseTime = (s) => new Date(String(s).replace(' ', 'T'));
  const shortHost = (h) => String(h).split('.')[0];
  const groupKey = (ev) => (ev.cc ? ev.cc : '_' + (ev.country || '내부망'));
  const sevOf = (ev) => SEV[ev.sev] || SEV.LOW;
  const pad = (n) => String(n).padStart(2, '0');
  const nowLabel = () => {
    const d = new Date();
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };
  function alpha(hex, a) {
    const n = parseInt(hex.slice(1), 16);
    return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
  }
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text; // DB 값은 항상 textContent로 (XSS 방지)
    return e;
  }

  // ---- 노드 등록 / 배치 ----
  function addEvent(ev) {
    const key = groupKey(ev);
    let g = groups.get(key);
    if (!g) {
      g = { key, name: ev.country || ev.cc || '미상', internal: !ev.cc, ips: new Map(), count: 0, flash: 0, x: 0, y: 0 };
      groups.set(key, g);
      needLayout = true;
    }
    g.ips.set(ev.ip, !!ev.blocked);

    if (!targets.has(ev.host)) {
      targets.set(ev.host, { host: ev.host, count: 0, hits: 0, flash: 0, x: 0, y: 0 });
      needLayout = true;
    }
    st.lastId = Math.max(st.lastId, ev.id);
  }

  function layout() {
    core.x = W / 2;
    core.y = H / 2;
    const outRx = W / 2 - (W > 560 ? 70 : 44);
    const outRy = H / 2 - 30;

    // 대상 서버: 안쪽 타원
    const ts = [...targets.values()].sort((a, b) => a.host.localeCompare(b.host));
    const tRx = Math.min(outRx * 0.5, W * 0.24);
    const tRy = outRy * 0.52;
    ts.forEach((t, i) => {
      const a = -Math.PI / 2 + ((i + 0.5) / ts.length) * Math.PI * 2;
      t.x = core.x + Math.cos(a) * tRx;
      t.y = core.y + Math.sin(a) * tRy;
    });
    shieldRx = tRx + 34;
    shieldRy = tRy + 28;

    // 해외 출발지: 바깥 타원, 국가별로 고정 위치
    const outer = [...groups.values()].filter((g) => !g.internal).sort((a, b) => a.name.localeCompare(b.name, 'ko'));
    outer.forEach((g, i) => {
      const a = -Math.PI / 2 + (i / outer.length) * Math.PI * 2 + Math.PI / outer.length;
      g.x = core.x + Math.cos(a) * outRx;
      g.y = core.y + Math.sin(a) * outRy;
    });

    // 내부망 출발지: 방어선 안쪽 (내부 위협)
    const inner = [...groups.values()].filter((g) => g.internal);
    inner.forEach((g, i) => {
      g.x = core.x + (i - (inner.length - 1) / 2) * 70;
      g.y = core.y + tRy * 0.5;
    });
  }

  // ---- 공격 발사 / 결과 ----
  function launch(ev) {
    const g = groups.get(groupKey(ev));
    const t = targets.get(ev.host);
    if (!g || !t) return;
    const h = hash(ev.ip);
    missiles.push({
      ev, g, t, p: 0,
      jx: (h % 17) - 8,
      jy: ((h >> 5) % 17) - 8,
      bend: (ev.id % 2 ? 1 : -1) * (0.12 + (h % 10) / 100),
      defended: ev.st === 'RESOLVED',
    });
    g.flash = 1;
    g.count++;
    t.count++;
    st.detected++;
    statsDirty = true;
  }

  // 2차 베지어 곡선 위의 점
  function pathPoint(m, p) {
    const sx = m.g.x + m.jx;
    const sy = m.g.y + m.jy;
    const tx = m.t.x;
    const ty = m.t.y;
    const qx = (sx + tx) / 2 - (ty - sy) * m.bend;
    const qy = (sy + ty) / 2 + (tx - sx) * m.bend;
    const u = 1 - p;
    return [u * u * sx + 2 * u * p * qx + p * p * tx, u * u * sy + 2 * u * p * qy + p * p * ty];
  }

  function resolve(m) {
    const sev = sevOf(m.ev);
    if (m.defended) {
      const [x, y] = pathPoint(m, INTERCEPT_AT);
      st.blocked++;
      st.combo++;
      st.best = Math.max(st.best, st.combo);
      const pts = Math.round(10 * sev.weight * (1 + Math.min(st.combo, 10) * 0.1));
      st.score += pts;
      st.shieldFlash = 1;
      effects.push({ x, y, r: 2, max: 16 + sev.weight * 3, color: C.shield, life: 1 });
      floats.push({ x, y: y - 8, text: `차단 +${pts}`, color: C.shield, life: 1 });
    } else {
      st.hit++;
      st.combo = 0;
      m.t.hits++;
      m.t.flash = 1;
      effects.push({ x: m.t.x, y: m.t.y, r: 4, max: 22 + sev.weight * 4, color: sev.color, life: 1 });
      floats.push({ x: m.t.x, y: m.t.y - 14, text: '피격', color: '#e06a6a', life: 1 });
      if (m.ev.sev === 'CRITICAL' && !reduceMotion) st.shake = 7;
    }
    addFeed(m.ev, m.defended);
    statsDirty = true;
  }

  // ---- 재생 일정 ----
  // 실제 시간 간격을 압축 (실제 10시간 = 1초, 최소 0.25초 ~ 최대 2초)
  function buildSchedule() {
    const list = allEvents.slice(-REPLAY_MAX);
    schedule = [];
    let at = 0.6;
    list.forEach((ev, i) => {
      if (i > 0) {
        const gapMin = (parseTime(ev.t) - parseTime(list[i - 1].t)) / 60000;
        at += Math.min(2, Math.max(0.25, gapMin / 600));
      }
      schedule.push({ at, ev });
    });
  }

  function resetReplay() {
    missiles = [];
    effects = [];
    floats = [];
    groups.forEach((g) => { g.count = 0; g.flash = 0; });
    targets.forEach((t) => { t.count = 0; t.hits = 0; t.flash = 0; });
    Object.assign(st, { clock: 0, qi: 0, detected: 0, blocked: 0, hit: 0, score: 0, combo: 0, best: 0, shake: 0 });
    replayLabel = '';
    const feed = $('feed');
    feed.replaceChildren(el('div', 'text-muted small p-3', '재생이 시작되면 여기에 표시됩니다.'));
    feed.firstChild.id = 'feedEmpty';
    buildSchedule();
    setMode(schedule.length ? 'replay' : 'live');
    statsDirty = true;
  }

  function setMode(mode) {
    st.mode = mode;
    const badge = $('modeBadge');
    badge.textContent = mode === 'live' ? 'LIVE' : 'REPLAY';
    badge.className = 'badge ' + (mode === 'live' ? 'mode-live' : 'mode-replay');
    if (mode === 'live') {
      $('liveProgress').style.width = '100%';
      $('liveClock').textContent = nowLabel();
      setPollStatus();
      poll();
    } else {
      setPollStatus();
    }
  }

  // ---- 메인 루프 ----
  let last = performance.now();
  function frame(now) {
    const dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    const sim = st.playing ? dt * st.speed : 0;

    if (needLayout) {
      layout();
      needLayout = false;
    }

    if (st.mode === 'replay') {
      st.clock += sim;
      while (st.qi < schedule.length && schedule[st.qi].at <= st.clock) {
        const ev = schedule[st.qi++].ev;
        launch(ev);
        replayLabel = String(ev.t).slice(0, 16);
      }
      if (st.qi >= schedule.length && !missiles.length) setMode('live');
    }

    missiles.forEach((m) => { m.p += sim / FLIGHT_SEC; });
    missiles = missiles.filter((m) => {
      if (m.p >= (m.defended ? INTERCEPT_AT : 1)) {
        resolve(m);
        return false;
      }
      return true;
    });

    effects.forEach((e) => {
      e.life -= sim * 1.4;
      e.r += (e.max - e.r) * Math.min(1, sim * 6);
    });
    effects = effects.filter((e) => e.life > 0);
    floats.forEach((f) => {
      f.life -= sim * 0.9;
      f.y -= sim * 18;
    });
    floats = floats.filter((f) => f.life > 0);
    groups.forEach((g) => { g.flash = Math.max(0, g.flash - sim * 1.5); });
    targets.forEach((t) => { t.flash = Math.max(0, t.flash - sim * 1.2); });
    st.shieldFlash = Math.max(0, st.shieldFlash - sim * 2);
    st.shake = Math.max(0, st.shake - dt * 30);
    if (!reduceMotion) st.sweep += dt * 0.6;

    draw();
    updateHud();
    requestAnimationFrame(frame);
  }

  // ---- 그리기 ----
  function draw() {
    ctx.clearRect(0, 0, W, H);
    if (!W || !H) return;
    ctx.save();
    if (st.shake > 0) ctx.translate((Math.random() - 0.5) * st.shake, (Math.random() - 0.5) * st.shake);

    const gRx = W / 2 - 16;
    const gRy = H / 2 - 8;

    // 레이더 격자
    ctx.strokeStyle = C.grid;
    ctx.lineWidth = 1;
    for (let i = 1; i <= 4; i++) {
      ctx.beginPath();
      ctx.ellipse(core.x, core.y, (gRx * i) / 4, (gRy * i) / 4, 0, 0, Math.PI * 2);
      ctx.stroke();
    }
    ctx.beginPath();
    ctx.moveTo(core.x, core.y - gRy);
    ctx.lineTo(core.x, core.y + gRy);
    ctx.moveTo(core.x - gRx, core.y);
    ctx.lineTo(core.x + gRx, core.y);
    ctx.stroke();

    // 레이더 스윕
    if (!reduceMotion && ctx.createConicGradient) {
      const a = st.sweep % (Math.PI * 2);
      const grad = ctx.createConicGradient(a - 0.6, core.x, core.y);
      grad.addColorStop(0, 'rgba(77, 157, 224, 0)');
      grad.addColorStop(0.095, 'rgba(77, 157, 224, 0.07)');
      grad.addColorStop(0.0955, 'rgba(77, 157, 224, 0)');
      grad.addColorStop(1, 'rgba(77, 157, 224, 0)');
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.ellipse(core.x, core.y, gRx, gRy, 0, 0, Math.PI * 2);
      ctx.fill();
    }

    // 방어선
    ctx.setLineDash([4, 6]);
    ctx.strokeStyle = alpha(C.shield, 0.28 + 0.5 * st.shieldFlash);
    ctx.lineWidth = 1 + st.shieldFlash * 1.5;
    ctx.beginPath();
    ctx.ellipse(core.x, core.y, shieldRx, shieldRy, 0, 0, Math.PI * 2);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.font = `10px ${MONO}`;
    ctx.fillStyle = alpha(C.shield, 0.6);
    ctx.textAlign = 'left';
    ctx.textBaseline = 'bottom';
    ctx.fillText('방어선', core.x + shieldRx * 0.72 + 4, core.y - shieldRy * 0.72);

    // 관제센터
    ctx.beginPath();
    ctx.arc(core.x, core.y, 16, 0, Math.PI * 2);
    ctx.fillStyle = C.panel;
    ctx.fill();
    ctx.strokeStyle = alpha(C.bright, 0.55);
    ctx.lineWidth = 1.2;
    ctx.stroke();
    ctx.fillStyle = C.bright;
    ctx.font = `600 10px ${MONO}`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('SOC', core.x, core.y);

    // 대상 서버
    const showHostLabel = W > 520;
    targets.forEach((t) => {
      const s = 9;
      ctx.fillStyle = t.flash > 0 ? alpha(C.hit, 0.25 + 0.65 * t.flash) : C.panel;
      ctx.fillRect(t.x - s / 2, t.y - s / 2, s, s);
      ctx.strokeStyle = t.hits > 0 ? C.hit : C.dim;
      ctx.lineWidth = 1.2;
      ctx.strokeRect(t.x - s / 2, t.y - s / 2, s, s);
      if (showHostLabel) {
        ctx.font = `10px ${MONO}`;
        ctx.fillStyle = C.dim;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillText(shortHost(t.host), t.x, t.y + 8);
      }
      if (t.hits > 0) {
        ctx.font = `600 10px ${MONO}`;
        ctx.fillStyle = '#e06a6a';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        ctx.fillText(`×${t.hits}`, t.x + 8, t.y - 7);
      }
    });

    // 출발지 (국가)
    groups.forEach((g) => {
      const r = 5 + Math.min(g.count, 25) * 0.3;
      const allBlocked = g.ips.size > 0 && [...g.ips.values()].every(Boolean);
      ctx.beginPath();
      ctx.arc(g.x, g.y, r, 0, Math.PI * 2);
      ctx.fillStyle = C.panel;
      ctx.fill();
      ctx.strokeStyle = g.internal ? C.internal : allBlocked ? C.shield : C.dim;
      ctx.lineWidth = 1.2;
      ctx.stroke();
      if (g.flash > 0) {
        ctx.beginPath();
        ctx.arc(g.x, g.y, r + 8 * (1 - g.flash), 0, Math.PI * 2);
        ctx.strokeStyle = alpha(C.bright, 0.5 * g.flash);
        ctx.stroke();
      }
      // 이름은 바깥쪽으로
      const right = g.x >= core.x + 4;
      const left = g.x <= core.x - 4;
      ctx.textBaseline = 'middle';
      ctx.textAlign = g.internal ? 'center' : right ? 'left' : left ? 'right' : 'center';
      const lx = g.internal ? g.x : right ? g.x + r + 6 : left ? g.x - r - 6 : g.x;
      const ly = g.internal ? g.y + r + 9 : !right && !left ? g.y - r - 9 : g.y;
      ctx.font = `11px ${SANS}`;
      ctx.fillStyle = g.internal ? C.internal : C.text;
      ctx.fillText(g.name, lx, ly);
      if (g.count) {
        ctx.font = `10px ${MONO}`;
        ctx.fillStyle = C.dim;
        ctx.fillText(String(g.count), lx, ly + 12);
      }
    });

    // 날아가는 공격
    missiles.forEach((m) => {
      const sev = sevOf(m.ev);
      let prev = pathPoint(m, Math.max(0, m.p - 0.16));
      for (let k = 7; k >= 0; k--) {
        const p = Math.max(0, m.p - k * 0.02);
        const pt = pathPoint(m, p);
        ctx.strokeStyle = alpha(sev.color, 0.08 + (0.5 * (8 - k)) / 8);
        ctx.lineWidth = 1 + (sev.size * (8 - k)) / 16;
        ctx.beginPath();
        ctx.moveTo(prev[0], prev[1]);
        ctx.lineTo(pt[0], pt[1]);
        ctx.stroke();
        prev = pt;
      }
      const [x, y] = pathPoint(m, m.p);
      ctx.beginPath();
      ctx.arc(x, y, sev.size, 0, Math.PI * 2);
      ctx.fillStyle = sev.color;
      ctx.fill();
    });

    // 폭발 / 차단 효과
    effects.forEach((e) => {
      ctx.beginPath();
      ctx.arc(e.x, e.y, e.r, 0, Math.PI * 2);
      ctx.strokeStyle = alpha(e.color, Math.max(0, e.life));
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });
    floats.forEach((f) => {
      ctx.font = `600 11px ${MONO}`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = alpha(f.color, Math.max(0, f.life));
      ctx.fillText(f.text, f.x, f.y);
    });

    ctx.restore();
  }

  // ---- 화면 숫자 / 로그 ----
  let shownLabel = '';
  function updateHud() {
    if (st.mode === 'replay') {
      if (replayLabel !== shownLabel) {
        $('liveClock').textContent = replayLabel || '-';
        shownLabel = replayLabel;
      }
      $('liveProgress').style.width = schedule.length ? `${(st.qi / schedule.length) * 100}%` : '0%';
    }
    if (!statsDirty) return;
    statsDirty = false;
    $('hudScore').textContent = st.score.toLocaleString('ko-KR');
    $('hudCombo').textContent = st.combo;
    $('hudBest').textContent = st.best;
    $('hudDetected').textContent = st.detected;
    $('hudBlocked').textContent = st.blocked;
    $('hudHit').textContent = st.hit;
    const done = st.blocked + st.hit;
    $('hudRate').textContent = done ? `${Math.round((st.blocked / done) * 100)}%` : '-';
    $('hudOpen').textContent = st.open == null ? '-' : `${st.open}건`;
  }

  function addFeed(ev, defended) {
    const feed = $('feed');
    const empty = $('feedEmpty');
    if (empty) empty.remove();

    const a = el('a', 'feed-item feed-new');
    a.href = `/events/${ev.id}`;
    const top = el('div', 'd-flex align-items-center gap-2');
    top.append(
      el('span', 'mono text-muted', String(ev.t).slice(5, 16)),
      el('span', `badge sev-${String(ev.sev).toLowerCase()}`, ev.sev),
      el('span', `ms-auto ${defended ? 'res-block' : 'res-hit'}`, defended ? '차단' : '피격'),
    );
    const mid = el('div', 'mono', `${ev.ip} → ${shortHost(ev.host)}${ev.port ? ':' + ev.port : ''}`);
    const bottom = el('div', 'text-muted', `${ev.type} · ${ev.country || '미상'}`);
    a.append(top, mid, bottom);
    feed.prepend(a);
    while (feed.children.length > FEED_MAX) feed.lastElementChild.remove();
  }

  let alertTimer = null;
  function showAlert(ev) {
    const box = $('liveAlert');
    box.textContent = `신규 탐지 · ${ev.sev} · ${ev.type} · ${ev.ip} → ${shortHost(ev.host)}`;
    box.style.borderLeftColor = sevOf(ev).color;
    box.hidden = false;
    clearTimeout(alertTimer);
    alertTimer = setTimeout(() => { box.hidden = true; }, 5000);
  }

  // ---- LIVE 갱신 ----
  let lastInput = Date.now();
  let pollPaused = false;
  let pollStopped = false;
  let polling = false;
  let pollError = '';

  function setPollStatus() {
    const s = $('pollStatus');
    if (st.mode !== 'live') s.textContent = '재생 중';
    else if (pollStopped) s.textContent = '갱신 중지';
    else if (pollPaused) s.textContent = '자동 갱신 일시정지';
    else if (pollError) s.textContent = pollError;
    else s.textContent = '15초마다 갱신';
  }

  async function poll() {
    if (st.mode !== 'live' || pollStopped || pollPaused || polling) return;
    polling = true;
    try {
      const r = await fetch(`/live/data?after=${st.lastId}`, { headers: { Accept: 'application/json' }, cache: 'no-store' });
      const ct = r.headers.get('content-type') || '';
      // 로그인이 풀리면 로그인 화면(HTML)으로 넘어감
      if (r.redirected || (r.ok && !ct.includes('application/json')) || r.status === 403) {
        pollStopped = true;
        showMessage('로그인 세션이 만료되었습니다. 새로고침 후 다시 로그인하세요.');
        return;
      }
      if (!r.ok) throw new Error(r.status);
      const d = await r.json();
      st.open = Number(d.open_count);
      if (d.events.length) showMessage('');
      d.events.forEach((ev) => {
        addEvent(ev);
        allEvents.push(ev);
        launch(ev);
        showAlert(ev);
      });
      pollError = '';
      statsDirty = true;
    } catch (e) {
      pollError = '연결 실패 · 다시 시도 중';
    } finally {
      polling = false;
      setPollStatus();
    }
  }

  setInterval(() => {
    if (st.mode === 'live') $('liveClock').textContent = nowLabel();
  }, 1000);

  setInterval(() => {
    if (st.mode !== 'live' || pollStopped) return;
    if (Date.now() - lastInput > IDLE_PAUSE_MS) {
      if (!pollPaused) {
        pollPaused = true;
        setPollStatus();
      }
      return;
    }
    poll();
  }, POLL_MS);

  ['pointermove', 'pointerdown', 'keydown', 'wheel', 'touchstart'].forEach((type) => {
    window.addEventListener(type, () => {
      lastInput = Date.now();
      if (pollPaused) {
        pollPaused = false;
        setPollStatus();
        poll();
      }
    }, { passive: true });
  });

  // ---- 툴팁 ----
  const tip = $('liveTip');
  canvas.addEventListener('pointermove', (e) => {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    let lines = null;

    groups.forEach((g) => {
      const r = 5 + Math.min(g.count, 25) * 0.3;
      if (!lines && Math.hypot(g.x - x, g.y - y) < r + 6) {
        lines = [`${g.name}${g.internal ? ' (내부 위협)' : ''}`, `출발지 IP ${g.ips.size}개 · 공격 ${g.count}건`];
        [...g.ips.entries()].slice(0, 5).forEach(([ip, blocked]) => lines.push(`${ip}${blocked ? '  [차단]' : ''}`));
      }
    });
    targets.forEach((t) => {
      if (!lines && Math.hypot(t.x - x, t.y - y) < 11) lines = [t.host, `공격 ${t.count}건 · 피격 ${t.hits}건`];
    });
    if (!lines && Math.hypot(core.x - x, core.y - y) < 18) {
      lines = ['SOC 관제센터', `현재 미처리 ${st.open == null ? '-' : st.open}건`];
    }

    if (!lines) {
      tip.hidden = true;
      canvas.style.cursor = '';
      return;
    }
    tip.replaceChildren(...lines.map((l, i) => el('div', i === 0 ? 'fw-semibold text-body' : 'mono', l)));
    tip.hidden = false;
    canvas.style.cursor = 'help';
    const tx = Math.min(x + 14, W - tip.offsetWidth - 6);
    const ty = Math.min(y + 14, H - tip.offsetHeight - 6);
    tip.style.left = `${Math.max(6, tx)}px`;
    tip.style.top = `${Math.max(6, ty)}px`;
  });
  canvas.addEventListener('pointerleave', () => { tip.hidden = true; });

  // ---- 버튼 ----
  $('btnPlay').addEventListener('click', (e) => {
    st.playing = !st.playing;
    e.currentTarget.textContent = st.playing ? '일시정지' : '재생';
  });
  document.querySelectorAll('.speed-btn').forEach((b) => {
    b.addEventListener('click', () => {
      st.speed = Number(b.dataset.speed);
      document.querySelectorAll('.speed-btn').forEach((x) => x.classList.toggle('active', x === b));
    });
  });
  $('btnRestart').addEventListener('click', () => {
    st.playing = true;
    $('btnPlay').textContent = '일시정지';
    resetReplay();
  });

  // ---- 캔버스 크기 (고해상도 화면 대응) ----
  function resize() {
    const r = stage.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = r.width;
    H = r.height;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    needLayout = true;
  }
  new ResizeObserver(resize).observe(stage);
  resize();

  function showMessage(msg) {
    const m = $('liveMsg');
    m.textContent = msg;
    m.hidden = !msg;
  }

  // ---- 시작 ----
  fetch('/live/data', { headers: { Accept: 'application/json' }, cache: 'no-store' })
    .then((r) => {
      const ct = r.headers.get('content-type') || '';
      if (!r.ok || !ct.includes('application/json')) throw new Error('bad response');
      return r.json();
    })
    .then((d) => {
      allEvents = d.events;
      allEvents.forEach(addEvent);
      st.open = Number(d.open_count);
      showMessage(allEvents.length ? '' : '아직 탐지된 이벤트가 없습니다. 새 이벤트를 기다리는 중…');
      resetReplay();
      requestAnimationFrame(frame);
    })
    .catch(() => showMessage('데이터를 불러오지 못했습니다. 새로고침해 주세요.'));
})();
