const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const pool = require('../db/pool');

const router = express.Router();

const MAX_FAILS = 10;                      // 이 횟수만큼 틀리면 차단
const UNLOCK_CODE = process.env.LOGIN_UNLOCK_CODE || '1234';
const MAX_UNLOCK_FAILS = 5;                // 해제 비번도 계속 틀리면 잠깐 막음
const UNLOCK_COOLDOWN = 15 * 60 * 1000;
const IDLE_RESET = 60 * 60 * 1000;         // 차단 안 된 상태로 1시간 지나면 실패 횟수 초기화

const SIGNUP_CODE = process.env.SIGNUP_CODE || '1234';
const ADMIN_SIGNUP_CODE = process.env.ADMIN_SIGNUP_CODE || 'P@ssw0rd'; // 관리자 계정 만들 때 추가로 필요
const MAX_SIGNUP_FAILS = 5;                // 가입 비번 5번 틀리면 15분 대기
const signupFails = new Map();             // ip -> { fails, blockedUntil }

// 접속 IP별 로그인 실패 기록 (서버 재시작하면 초기화됨)
// { fails, locked, unlockFails, unlockBlockedUntil, lastAt }
const attempts = new Map();

function getRecord(ip) {
  let r = attempts.get(ip);
  if (!r || (!r.locked && Date.now() - r.lastAt > IDLE_RESET)) {
    r = { fails: 0, locked: false, unlockFails: 0, unlockBlockedUntil: 0, lastAt: Date.now() };
    attempts.set(ip, r);
  }
  return r;
}

// 오래된 기록 정리
setInterval(() => {
  const now = Date.now();
  for (const [ip, r] of attempts) {
    if (!r.locked && now - r.lastAt > IDLE_RESET) attempts.delete(ip);
  }
  for (const [ip, r] of signupFails) {
    if (r.blockedUntil < now && now - r.lastAt > IDLE_RESET) signupFails.delete(ip);
  }
}, 10 * 60 * 1000).unref();

const IDLE_MIN = Number(process.env.SESSION_IDLE_MIN) || 30;

// 계정별 현재 로그인된 세션 (중복 로그인 막기용)
// adminId -> { sid, pendingAt }  (pendingAt: 로그인 처리 중일 때만)
const activeLogins = new Map();

const getSession = (store, sid) => new Promise((resolve) => {
  store.get(sid, (err, s) => resolve(err ? null : s));
});

// 다른 곳에서 이 계정으로 로그인해 있으면 true
async function isLoggedInElsewhere(req, adminId) {
  const cur = activeLogins.get(adminId);
  if (!cur) return false;
  if (cur.pendingAt) return Date.now() - cur.pendingAt < 10 * 1000; // 동시에 로그인 시도 중
  if (cur.sid === req.sessionID) return false;
  const s = await getSession(req.sessionStore, cur.sid);
  // 세션이 만료/삭제됐으면 로그인 상태 아님
  return !!(s && s.admin && s.admin.id === adminId);
}

const safeEqual = (a, b) => {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
};

function renderLogin(res, opts = {}) {
  res.status(opts.status || 200).render('login', {
    title: '로그인', error: null, info: null, username: '', locked: false, ...opts,
  });
}

function renderLocked(res, record, error) {
  let msg = error || null;
  if (record.unlockBlockedUntil > Date.now()) {
    const min = Math.ceil((record.unlockBlockedUntil - Date.now()) / 60000);
    msg = `해제 비밀번호를 ${MAX_UNLOCK_FAILS}회 틀렸습니다. ${min}분 후에 다시 시도하세요.`;
  }
  renderLogin(res, { status: 423, locked: true, error: msg });
}

router.get('/login', (req, res) => {
  if (req.session.admin) return res.redirect('/');
  const record = attempts.get(req.ip);
  if (record && record.locked) return renderLocked(res, record);
  renderLogin(res, { info: res.locals.flash ? res.locals.flash.msg : null });
});

router.post('/login', async (req, res, next) => {
  const record = getRecord(req.ip);
  if (record.locked) return renderLocked(res, record);

  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  const [rows] = await pool.query(
    'SELECT id, username, password_hash, name, role FROM admins WHERE username = ?',
    [username]
  );
  const admin = rows[0];
  const ok = admin && await bcrypt.compare(password, admin.password_hash);

  if (!ok) {
    record.fails++;
    record.lastAt = Date.now();
    if (record.fails >= MAX_FAILS) {
      record.locked = true;
      console.warn(`[로그인 차단] ${req.ip} - ${MAX_FAILS}회 실패`);
      return renderLocked(res, record, `로그인을 ${MAX_FAILS}회 실패해서 차단되었습니다.`);
    }
    return renderLogin(res, {
      status: 401,
      error: `아이디 또는 비밀번호가 올바르지 않습니다. (남은 시도 ${MAX_FAILS - record.fails}회)`,
      username,
    });
  }

  attempts.delete(req.ip);

  // 이미 다른 곳에서 로그인 중이면 거절 (비번은 맞았으니 실패 횟수에는 안 넣음)
  const before = activeLogins.get(admin.id);
  if (await isLoggedInElsewhere(req, admin.id) || activeLogins.get(admin.id) !== before) {
    console.warn(`[중복 로그인 거절] ${admin.username} (${req.ip})`);
    return renderLogin(res, {
      status: 409,
      error: `이 계정은 다른 곳에서 이미 로그인 중입니다. 기존 접속에서 로그아웃한 뒤 다시 시도하세요. (${IDLE_MIN}분 동안 사용하지 않으면 자동 로그아웃됩니다)`,
      username,
    });
  }
  activeLogins.set(admin.id, { pendingAt: Date.now() });

  try {
    await pool.query('UPDATE admins SET last_login_at = NOW() WHERE id = ?', [admin.id]);
  } catch (err) {
    activeLogins.delete(admin.id);
    throw err;
  }

  // 세션 고정 공격 방지용으로 세션 새로 발급
  req.session.regenerate((err) => {
    if (err) {
      activeLogins.delete(admin.id);
      return next(err);
    }
    req.session.admin = { id: admin.id, username: admin.username, name: admin.name, role: admin.role };
    activeLogins.set(admin.id, { sid: req.sessionID });
    req.session.save((err2) => (err2 ? next(err2) : res.redirect('/')));
  });
});

// 차단 해제
router.post('/login/unlock', (req, res) => {
  const record = attempts.get(req.ip);
  if (!record || !record.locked) return res.redirect('/login');
  if (record.unlockBlockedUntil > Date.now()) return renderLocked(res, record);

  if (!safeEqual(req.body.unlock_code || '', UNLOCK_CODE)) {
    record.unlockFails++;
    if (record.unlockFails >= MAX_UNLOCK_FAILS) {
      record.unlockFails = 0;
      record.unlockBlockedUntil = Date.now() + UNLOCK_COOLDOWN;
    }
    return renderLocked(res, record, `해제 비밀번호가 올바르지 않습니다. (남은 시도 ${MAX_UNLOCK_FAILS - record.unlockFails}회)`);
  }

  attempts.delete(req.ip);
  console.warn(`[로그인 차단 해제] ${req.ip}`);
  req.flash('success', '차단이 해제되었습니다. 다시 로그인하세요.');
  res.redirect('/login');
});

// 회원가입
function renderSignup(res, opts = {}) {
  res.status(opts.status || 200).render('signup', {
    title: '계정 만들기', errors: [], form: {}, ...opts,
  });
}

router.get('/signup', (req, res) => {
  if (req.session.admin) return res.redirect('/');
  renderSignup(res);
});

router.post('/signup', async (req, res) => {
  if (req.session.admin) return res.redirect('/');

  const form = {
    username: (req.body.username || '').trim(),
    name: (req.body.name || '').trim(),
    email: (req.body.email || '').trim(),
    role: req.body.role === 'ADMIN' ? 'ADMIN' : 'ANALYST',
  };
  const password = req.body.password || '';
  const password2 = req.body.password2 || '';

  // 가입 비밀번호 먼저 확인 (틀리면 횟수 제한)
  const sf = signupFails.get(req.ip) || { fails: 0, blockedUntil: 0, lastAt: 0 };
  if (sf.blockedUntil > Date.now()) {
    const min = Math.ceil((sf.blockedUntil - Date.now()) / 60000);
    return renderSignup(res, { status: 429, form, errors: [`가입 비밀번호를 여러 번 틀렸습니다. ${min}분 후에 다시 시도하세요.`] });
  }
  // 가입 비번, 관리자 암호 둘 다 틀린 횟수에 포함
  let codeError = null;
  if (!safeEqual(req.body.signup_code || '', SIGNUP_CODE)) {
    codeError = '가입 비밀번호가 올바르지 않습니다.';
  } else if (form.role === 'ADMIN' && !safeEqual(req.body.admin_code || '', ADMIN_SIGNUP_CODE)) {
    codeError = '관리자 암호가 올바르지 않습니다.';
  }
  if (codeError) {
    sf.fails++;
    sf.lastAt = Date.now();
    if (sf.fails >= MAX_SIGNUP_FAILS) {
      sf.fails = 0;
      sf.blockedUntil = Date.now() + UNLOCK_COOLDOWN;
    }
    signupFails.set(req.ip, sf);
    return renderSignup(res, { status: 403, form, errors: [codeError] });
  }
  signupFails.delete(req.ip);

  const errors = [];
  if (!/^[A-Za-z0-9_]{4,20}$/.test(form.username)) errors.push('아이디는 영문/숫자/_ 4~20자로 입력하세요.');
  if (!form.name || form.name.length > 50) errors.push('이름을 1~50자로 입력하세요.');
  if (form.email && (form.email.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))) errors.push('이메일 형식이 올바르지 않습니다.');
  if (password.length < 8 || password.length > 72) errors.push('비밀번호는 8~72자로 입력하세요.');
  if (password !== password2) errors.push('비밀번호 확인이 일치하지 않습니다.');
  if (errors.length) return renderSignup(res, { status: 400, form, errors });

  const hash = await bcrypt.hash(password, 10);
  try {
    await pool.query(
      'INSERT INTO admins (username, password_hash, name, email, role) VALUES (?, ?, ?, ?, ?)',
      [form.username, hash, form.name, form.email || null, form.role]
    );
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return renderSignup(res, { status: 400, form, errors: ['이미 사용 중인 아이디입니다.'] });
    throw err;
  }

  const roleName = form.role === 'ADMIN' ? '관리자' : '조회';
  console.log(`[계정 생성] ${form.username} / ${form.role} (${req.ip})`);
  req.flash('success', `${roleName} 계정 '${form.username}'이(가) 만들어졌습니다. 로그인하세요.`);
  res.redirect('/login');
});

router.post('/logout', (req, res) => {
  const admin = req.session.admin;
  if (admin) {
    const cur = activeLogins.get(admin.id);
    if (cur && cur.sid === req.sessionID) activeLogins.delete(admin.id);
  }
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

module.exports = router;
