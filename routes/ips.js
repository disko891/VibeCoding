const express = require('express');
const net = require('net');
const pool = require('../db/pool');

const router = express.Router();

router.param('id', (req, res, next, id) => (/^\d+$/.test(id) ? next() : next('route')));

function parseForm(body) {
  const data = {
    ip_address: (body.ip_address || '').trim(),
    country_code: (body.country_code || '').trim().toUpperCase(),
    country_name: (body.country_name || '').trim(),
    is_blocked: body.is_blocked === '1' ? 1 : 0,
    memo: (body.memo || '').trim(),
  };
  const errors = [];
  if (!net.isIP(data.ip_address)) errors.push('올바른 IPv4/IPv6 주소를 입력하세요.');
  if (data.country_code && !/^[A-Z]{2}$/.test(data.country_code)) errors.push('국가 코드는 영문 2자리로 입력하세요. (예: KR)');
  if (data.country_name.length > 50) errors.push('국가명은 50자 이하로 입력하세요.');
  if (data.memo.length > 255) errors.push('메모는 255자 이하로 입력하세요.');
  return { data, errors };
}

function renderForm(res, opts) {
  res.status(opts.status || 200).render('ips/form', {
    title: opts.isEdit ? 'IP 수정' : 'IP 등록', errors: [], ...opts,
  });
}

const DUP_MSG = '이미 등록된 IP 주소입니다.';

router.get('/', async (req, res) => {
  const [ips] = await pool.query(
    `SELECT s.*, COUNT(e.id) AS attack_count, MAX(e.detected_at) AS last_seen
       FROM source_ips s
       LEFT JOIN events e ON e.source_ip_id = s.id
      GROUP BY s.id
      ORDER BY attack_count DESC, s.ip_address`
  );
  res.render('ips/list', { title: 'IP 관리', ips });
});

router.get('/new', (req, res) => {
  renderForm(res, { isEdit: false, item: { is_blocked: 0 } });
});

router.post('/', async (req, res) => {
  const { data, errors } = parseForm(req.body);
  if (errors.length) return renderForm(res, { status: 400, isEdit: false, item: data, errors });

  try {
    await pool.query(
      'INSERT INTO source_ips (ip_address, country_code, country_name, is_blocked, memo) VALUES (?, ?, ?, ?, ?)',
      [data.ip_address, data.country_code || null, data.country_name || null, data.is_blocked, data.memo || null]
    );
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return renderForm(res, { status: 400, isEdit: false, item: data, errors: [DUP_MSG] });
    throw err;
  }
  req.flash('success', `${data.ip_address}을(를) 등록했습니다.`);
  res.redirect('/ips');
});

router.get('/:id/edit', async (req, res, next) => {
  const [rows] = await pool.query('SELECT * FROM source_ips WHERE id = ?', [req.params.id]);
  if (!rows.length) return next();
  renderForm(res, { isEdit: true, item: rows[0] });
});

router.post('/:id/edit', async (req, res, next) => {
  const id = parseInt(req.params.id, 10);
  const { data, errors } = parseForm(req.body);
  if (errors.length) return renderForm(res, { status: 400, isEdit: true, item: { ...data, id }, errors });

  try {
    const [result] = await pool.query(
      'UPDATE source_ips SET ip_address = ?, country_code = ?, country_name = ?, is_blocked = ?, memo = ? WHERE id = ?',
      [data.ip_address, data.country_code || null, data.country_name || null, data.is_blocked, data.memo || null, id]
    );
    if (!result.affectedRows) return next();
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return renderForm(res, { status: 400, isEdit: true, item: { ...data, id }, errors: [DUP_MSG] });
    throw err;
  }
  req.flash('success', 'IP 정보를 수정했습니다.');
  res.redirect('/ips');
});

// 차단 / 해제 토글
router.post('/:id/toggle', async (req, res, next) => {
  const [result] = await pool.query('UPDATE source_ips SET is_blocked = 1 - is_blocked WHERE id = ?', [req.params.id]);
  if (!result.affectedRows) return next();

  const [[ip]] = await pool.query('SELECT ip_address, is_blocked FROM source_ips WHERE id = ?', [req.params.id]);
  req.flash(ip.is_blocked ? 'danger' : 'success', `${ip.ip_address} ${ip.is_blocked ? '차단' : '차단 해제'} 완료`);
  res.redirect('/ips');
});

router.post('/:id/delete', async (req, res) => {
  try {
    await pool.query('DELETE FROM source_ips WHERE id = ?', [req.params.id]);
    req.flash('success', 'IP를 삭제했습니다.');
  } catch (err) {
    if (err.code !== 'ER_ROW_IS_REFERENCED_2') throw err;
    req.flash('warning', '이 IP에서 발생한 이벤트가 있어서 삭제할 수 없습니다. 대신 차단 처리를 사용하세요.');
  }
  res.redirect('/ips');
});

module.exports = router;
