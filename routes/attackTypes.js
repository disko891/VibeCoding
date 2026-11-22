const express = require('express');
const pool = require('../db/pool');
const { requireAdmin } = require('../lib/auth');

const router = express.Router();
const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

router.param('id', (req, res, next, id) => (/^\d+$/.test(id) ? next() : next('route')));

// 목록(GET /)만 조회 계정도 가능
router.use((req, res, next) => {
  if (req.method === 'GET' && req.path === '/') return next();
  requireAdmin(req, res, next);
});

function parseForm(body) {
  const data = {
    name: (body.name || '').trim(),
    code: (body.code || '').trim().toUpperCase(),
    description: (body.description || '').trim(),
    default_severity: body.default_severity,
  };
  const errors = [];
  if (!data.name || data.name.length > 100) errors.push('유형명을 1~100자로 입력하세요.');
  if (!/^[A-Z0-9_]{1,30}$/.test(data.code)) errors.push('코드는 영문 대문자/숫자/_ 30자 이내로 입력하세요.');
  if (!SEVERITIES.includes(data.default_severity)) errors.push('기본 위험도를 선택하세요.');
  return { data, errors };
}

function renderForm(res, opts) {
  res.status(opts.status || 200).render('attackTypes/form', {
    title: opts.isEdit ? '공격 유형 수정' : '공격 유형 등록',
    errors: [], SEVERITIES, ...opts,
  });
}

router.get('/', async (req, res) => {
  const [types] = await pool.query(
    `SELECT t.*, COUNT(e.id) AS event_count
       FROM attack_types t
       LEFT JOIN events e ON e.attack_type_id = t.id
      GROUP BY t.id
      ORDER BY event_count DESC, t.name`
  );
  res.render('attackTypes/list', { title: '공격 유형', types });
});

router.get('/new', (req, res) => {
  renderForm(res, { isEdit: false, item: { default_severity: 'MEDIUM' } });
});

router.post('/', async (req, res) => {
  const { data, errors } = parseForm(req.body);
  if (errors.length) return renderForm(res, { status: 400, isEdit: false, item: data, errors });

  try {
    await pool.query(
      'INSERT INTO attack_types (name, code, description, default_severity) VALUES (?, ?, ?, ?)',
      [data.name, data.code, data.description || null, data.default_severity]
    );
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return renderForm(res, { status: 400, isEdit: false, item: data, errors: ['이미 같은 이름이나 코드의 공격 유형이 있습니다.'] });
    }
    throw err;
  }
  req.flash('success', `공격 유형 '${data.name}'을(를) 등록했습니다.`);
  res.redirect('/attack-types');
});

router.get('/:id/edit', async (req, res, next) => {
  const [rows] = await pool.query('SELECT * FROM attack_types WHERE id = ?', [req.params.id]);
  if (!rows.length) return next();
  renderForm(res, { isEdit: true, item: rows[0] });
});

router.post('/:id/edit', async (req, res, next) => {
  const id = parseInt(req.params.id, 10);
  const { data, errors } = parseForm(req.body);
  if (errors.length) return renderForm(res, { status: 400, isEdit: true, item: { ...data, id }, errors });

  try {
    const [result] = await pool.query(
      'UPDATE attack_types SET name = ?, code = ?, description = ?, default_severity = ? WHERE id = ?',
      [data.name, data.code, data.description || null, data.default_severity, id]
    );
    if (!result.affectedRows) return next();
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return renderForm(res, { status: 400, isEdit: true, item: { ...data, id }, errors: ['이미 같은 이름이나 코드의 공격 유형이 있습니다.'] });
    }
    throw err;
  }
  req.flash('success', '공격 유형을 수정했습니다.');
  res.redirect('/attack-types');
});

router.post('/:id/delete', async (req, res) => {
  try {
    await pool.query('DELETE FROM attack_types WHERE id = ?', [req.params.id]);
    req.flash('success', '공격 유형을 삭제했습니다.');
  } catch (err) {
    if (err.code !== 'ER_ROW_IS_REFERENCED_2') throw err;
    req.flash('warning', '이 공격 유형으로 등록된 이벤트가 있어서 삭제할 수 없습니다. 해당 이벤트를 먼저 정리하세요.');
  }
  res.redirect('/attack-types');
});

module.exports = router;
