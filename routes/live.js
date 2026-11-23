const express = require('express');
const pool = require('../db/pool');
const { cached } = require('../lib/cache');

const router = express.Router();

const REPLAY_LIMIT = 150; // 처음 재생할 최근 이벤트 수
const POLL_LIMIT = 50;    // 한 번에 받아갈 새 이벤트 최대 수

const EVENT_SQL = `
  SELECT e.id, e.detected_at AS t, e.severity AS sev, e.status AS st,
         e.target_host AS host, e.target_port AS port, t.name AS type,
         s.ip_address AS ip, s.country_code AS cc, s.country_name AS country, s.is_blocked AS blocked
    FROM events e
    JOIN attack_types t ON t.id = e.attack_type_id
    JOIN source_ips s ON s.id = e.source_ip_id`;

const OPEN_SQL = "SELECT COUNT(*) AS open_count FROM events WHERE status = 'OPEN'";

// 공격 관제 맵 화면
router.get('/', (req, res) => {
  res.render('live', { title: '공격 관제 맵' });
});

// 화면에서 쓰는 데이터
// - /live/data          : 재생용 최근 이벤트 (오래된 순)
// - /live/data?after=ID : ID 이후 새로 생긴 이벤트 (15초마다 호출, PK로 찾으므로 가벼움)
router.get('/data', async (req, res) => {
  const after = parseInt(req.query.after, 10);

  if (after >= 0) {
    const [[events], [[{ open_count }]]] = await Promise.all([
      pool.query(`${EVENT_SQL} WHERE e.id > ? ORDER BY e.id LIMIT ?`, [after, POLL_LIMIT]),
      pool.query(OPEN_SQL),
    ]);
    return res.json({ events, open_count });
  }

  const data = await cached('live:init', 30 * 1000, async () => {
    const [[events], [[{ open_count }]]] = await Promise.all([
      pool.query(`${EVENT_SQL} ORDER BY e.detected_at DESC, e.id DESC LIMIT ?`, [REPLAY_LIMIT]),
      pool.query(OPEN_SQL),
    ]);
    return { events: events.reverse(), open_count };
  });
  res.json(data);
});

module.exports = router;
