const express = require('express');
const pool = require('../db/pool');
const { createIfNoOpen } = require('../lib/autoEvent');

const NEW_EVENT_MSG = (newId) => ` 미처리 이벤트가 모두 처리되어 새 이벤트 #${newId}가 탐지되었습니다.`;
const { cached } = require('../lib/cache');

const router = express.Router();

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const STATUSES = ['OPEN', 'INVESTIGATING', 'RESOLVED'];
const PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS'];
const ACTION_TYPES = ['INVESTIGATE', 'BLOCK_IP', 'ESCALATE', 'RESOLVE', 'NOTE'];
const PAGE_SIZE = 15;

// id가 숫자가 아니면 404로
router.param('id', (req, res, next, id) => (/^\d+$/.test(id) ? next() : next('route')));

// 셀렉트박스용 목록 (잘 안 바뀌므로 캐시, 등록/수정 시 자동으로 비워짐)
const OPTIONS_TTL = 5 * 60 * 1000;
const getAttackTypeOptions = () => cached('opt:attackTypes', OPTIONS_TTL, async () => {
  const [rows] = await pool.query('SELECT id, name FROM attack_types ORDER BY name');
  return rows;
});
const getIpOptions = () => cached('opt:ips', OPTIONS_TTL, async () => {
  const [rows] = await pool.query('SELECT id, ip_address, country_name FROM source_ips ORDER BY ip_address');
  return rows;
});

async function loadOptions() {
  const [attackTypes, ips] = await Promise.all([getAttackTypeOptions(), getIpOptions()]);
  return { attackTypes, ips };
}

// 폼 입력 검사. 문제 없으면 errors 빈 배열
function parseEventForm(body) {
  const errors = [];
  const data = {
    attack_type_id: parseInt(body.attack_type_id, 10),
    source_ip_id: parseInt(body.source_ip_id, 10),
    target_host: (body.target_host || '').trim(),
    target_port: body.target_port === '' || body.target_port == null ? null : parseInt(body.target_port, 10),
    protocol: body.protocol,
    severity: body.severity,
    status: body.status,
    description: (body.description || '').trim(),
    detected_at: (body.detected_at || '').replace('T', ' '),
  };

  if (!data.attack_type_id) errors.push('공격 유형을 선택하세요.');
  if (!data.source_ip_id) errors.push('출발지 IP를 선택하세요.');
  if (!data.target_host) errors.push('대상 호스트를 입력하세요.');
  if (data.target_host.length > 100) errors.push('대상 호스트는 100자 이하로 입력하세요.');
  if (data.target_port !== null && (isNaN(data.target_port) || data.target_port < 1 || data.target_port > 65535)) {
    errors.push('포트는 1~65535 사이로 입력하세요.');
  }
  if (!PROTOCOLS.includes(data.protocol)) errors.push('프로토콜이 올바르지 않습니다.');
  if (!SEVERITIES.includes(data.severity)) errors.push('위험도가 올바르지 않습니다.');
  if (!STATUSES.includes(data.status)) errors.push('상태가 올바르지 않습니다.');
  if (!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(data.detected_at)) errors.push('탐지 시각을 입력하세요.');

  return { data, errors };
}

// datetime-local 입력값 형식으로 변환 (2026-11-17 10:20:00 -> 2026-11-17T10:20)
const toInputDate = (s) => (s ? s.slice(0, 16).replace(' ', 'T') : '');

// 목록
router.get('/', async (req, res) => {
  const filter = {
    severity: SEVERITIES.includes(req.query.severity) ? req.query.severity : '',
    status: STATUSES.includes(req.query.status) ? req.query.status : '',
    attack_type_id: parseInt(req.query.attack_type_id, 10) || '',
  };

  const where = [];
  const params = [];
  if (filter.severity) { where.push('e.severity = ?'); params.push(filter.severity); }
  if (filter.status) { where.push('e.status = ?'); params.push(filter.status); }
  if (filter.attack_type_id) { where.push('e.attack_type_id = ?'); params.push(filter.attack_type_id); }
  const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

  const [[[{ total }]], attackTypes] = await Promise.all([
    pool.query(`SELECT COUNT(*) AS total FROM events e ${whereSql}`, params),
    getAttackTypeOptions(),
  ]);
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const page = Math.min(Math.max(parseInt(req.query.page, 10) || 1, 1), totalPages);

  const [events] = await pool.query(
    `SELECT e.id, e.severity, e.status, e.target_host, e.target_port, e.protocol, e.detected_at,
            t.name AS attack_type, s.ip_address
       FROM events e
       JOIN attack_types t ON t.id = e.attack_type_id
       JOIN source_ips s ON s.id = e.source_ip_id
       ${whereSql}
      ORDER BY e.detected_at DESC, e.id DESC
      LIMIT ? OFFSET ?`,
    [...params, PAGE_SIZE, (page - 1) * PAGE_SIZE]
  );

  // 페이지 링크에 필터 유지
  const qs = new URLSearchParams();
  Object.entries(filter).forEach(([k, v]) => { if (v) qs.set(k, v); });
  const pageUrl = (p) => { qs.set('page', p); return '/events?' + qs.toString(); };

  res.render('events/list', {
    title: '이벤트', events, attackTypes, filter, page, totalPages, total, pageUrl,
    SEVERITIES, STATUSES,
  });
});

// 등록 폼
router.get('/new', async (req, res) => {
  const options = await loadOptions();
  res.render('events/form', {
    title: '이벤트 등록', ...options, errors: [], isEdit: false,
    event: { severity: 'MEDIUM', status: 'OPEN', protocol: 'TCP', detected_at: '' },
    toInputDate, SEVERITIES, STATUSES, PROTOCOLS,
  });
});

router.post('/', async (req, res) => {
  const { data, errors } = parseEventForm(req.body);
  if (errors.length) {
    const options = await loadOptions();
    return res.status(400).render('events/form', {
      title: '이벤트 등록', ...options, errors, isEdit: false,
      event: { ...data, detected_at: data.detected_at },
      toInputDate, SEVERITIES, STATUSES, PROTOCOLS,
    });
  }

  const [result] = await pool.query(
    `INSERT INTO events (attack_type_id, source_ip_id, target_host, target_port, protocol, severity, status, description, detected_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [data.attack_type_id, data.source_ip_id, data.target_host, data.target_port, data.protocol,
      data.severity, data.status, data.description || null, data.detected_at]
  );
  req.flash('success', '이벤트를 등록했습니다.');
  res.redirect(`/events/${result.insertId}`);
});

// 상세 + 조치 내역
router.get('/:id', async (req, res, next) => {
  const id = parseInt(req.params.id, 10);
  const [rows] = await pool.query(
    `SELECT e.*, t.name AS attack_type, t.code AS attack_code,
            s.ip_address, s.country_name, s.is_blocked
       FROM events e
       JOIN attack_types t ON t.id = e.attack_type_id
       JOIN source_ips s ON s.id = e.source_ip_id
      WHERE e.id = ?`,
    [id]
  );
  if (!rows.length) return next();

  const [actions] = await pool.query(
    `SELECT a.*, ad.name AS admin_name
       FROM actions a
       JOIN admins ad ON ad.id = a.admin_id
      WHERE a.event_id = ?
      ORDER BY a.created_at DESC, a.id DESC`,
    [id]
  );

  res.render('events/detail', { title: `이벤트 #${id}`, event: rows[0], actions, ACTION_TYPES, STATUSES });
});

// 수정 폼
router.get('/:id/edit', async (req, res, next) => {
  const [rows] = await pool.query('SELECT * FROM events WHERE id = ?', [parseInt(req.params.id, 10)]);
  if (!rows.length) return next();
  const options = await loadOptions();
  res.render('events/form', {
    title: '이벤트 수정', ...options, errors: [], isEdit: true, event: rows[0],
    toInputDate, SEVERITIES, STATUSES, PROTOCOLS,
  });
});

router.post('/:id/edit', async (req, res, next) => {
  const id = parseInt(req.params.id, 10);
  const { data, errors } = parseEventForm(req.body);
  if (errors.length) {
    const options = await loadOptions();
    return res.status(400).render('events/form', {
      title: '이벤트 수정', ...options, errors, isEdit: true, event: { ...data, id },
      toInputDate, SEVERITIES, STATUSES, PROTOCOLS,
    });
  }

  const [result] = await pool.query(
    `UPDATE events
        SET attack_type_id = ?, source_ip_id = ?, target_host = ?, target_port = ?, protocol = ?,
            severity = ?, status = ?, description = ?, detected_at = ?
      WHERE id = ?`,
    [data.attack_type_id, data.source_ip_id, data.target_host, data.target_port, data.protocol,
      data.severity, data.status, data.description || null, data.detected_at, id]
  );
  if (!result.affectedRows) return next();

  let msg = '이벤트를 수정했습니다.';
  if (data.status !== 'OPEN') {
    const newId = await createIfNoOpen(pool);
    if (newId) msg += NEW_EVENT_MSG(newId);
  }
  req.flash('success', msg);
  res.redirect(`/events/${id}`);
});

// 삭제 (조치 내역은 FK CASCADE로 같이 삭제됨)
router.post('/:id/delete', async (req, res) => {
  await pool.query('DELETE FROM events WHERE id = ?', [parseInt(req.params.id, 10)]);
  const newId = await createIfNoOpen(pool);
  req.flash('success', '이벤트를 삭제했습니다.' + (newId ? NEW_EVENT_MSG(newId) : ''));
  res.redirect('/events');
});

// 조치 추가
router.post('/:id/actions', async (req, res, next) => {
  const id = parseInt(req.params.id, 10);
  const actionType = req.body.action_type;
  const description = (req.body.description || '').trim();
  const newStatus = STATUSES.includes(req.body.new_status) ? req.body.new_status : null;

  if (!ACTION_TYPES.includes(actionType)) {
    req.flash('danger', '조치 유형을 선택하세요.');
    return res.redirect(`/events/${id}`);
  }

  let newEventId = null;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [rows] = await conn.query('SELECT id, source_ip_id FROM events WHERE id = ? FOR UPDATE', [id]);
    if (!rows.length) {
      await conn.rollback();
      return next();
    }

    await conn.query(
      'INSERT INTO actions (event_id, admin_id, action_type, description) VALUES (?, ?, ?, ?)',
      [id, req.session.admin.id, actionType, description || null]
    );
    if (newStatus) {
      await conn.query('UPDATE events SET status = ? WHERE id = ?', [newStatus, id]);
    }
    if (actionType === 'BLOCK_IP') {
      await conn.query('UPDATE source_ips SET is_blocked = 1 WHERE id = ?', [rows[0].source_ip_id]);
    }
    if (newStatus && newStatus !== 'OPEN') {
      newEventId = await createIfNoOpen(conn);
    }

    await conn.commit();
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }

  let msg = '조치를 등록했습니다.';
  if (actionType === 'BLOCK_IP') msg += ' 출발지 IP를 차단 상태로 변경했습니다.';
  if (newEventId) msg += NEW_EVENT_MSG(newEventId);
  req.flash('success', msg);
  res.redirect(`/events/${id}`);
});

module.exports = router;
