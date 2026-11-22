const express = require('express');
const pool = require('../db/pool');

const router = express.Router();

const ACTION_TYPES = ['INVESTIGATE', 'BLOCK_IP', 'ESCALATE', 'RESOLVE', 'NOTE'];
const PAGE_SIZE = 20;

// 조치 내역 전체 목록 (조회 전용)
router.get('/', async (req, res) => {
  const type = ACTION_TYPES.includes(req.query.action_type) ? req.query.action_type : '';
  const where = type ? 'WHERE a.action_type = ?' : '';
  const params = type ? [type] : [];

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total FROM actions a ${where}`, params);
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const page = Math.min(Math.max(parseInt(req.query.page, 10) || 1, 1), totalPages);

  const [actions] = await pool.query(
    `SELECT a.id, a.event_id, a.action_type, a.description, a.created_at,
            ad.name AS admin_name, t.name AS attack_type, e.severity
       FROM actions a
       JOIN admins ad ON ad.id = a.admin_id
       JOIN events e ON e.id = a.event_id
       JOIN attack_types t ON t.id = e.attack_type_id
       ${where}
      ORDER BY a.created_at DESC, a.id DESC
      LIMIT ? OFFSET ?`,
    [...params, PAGE_SIZE, (page - 1) * PAGE_SIZE]
  );

  const pageUrl = (p) => '/actions?' + new URLSearchParams({ ...(type && { action_type: type }), page: p });

  res.render('actions/list', {
    title: '조치 내역', actions, total, page, totalPages, pageUrl, type, ACTION_TYPES,
  });
});

module.exports = router;
