const express = require('express');
const pool = require('../db/pool');
const { isAdmin } = require('../lib/auth');
const { cached } = require('../lib/cache');

const router = express.Router();

// 로컬 기준 YYYY-MM-DD
function ymd(d) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

const DASHBOARD_TTL = 30 * 1000; // 30초 (그 사이 등록/수정이 있으면 바로 갱신됨)

// 대시보드 통계 쿼리 (요약 + 위험도별 건수는 events를 한 번만 읽도록 합침)
async function loadDashboard() {
  const [
    [[summary]],
    [byType],
    [daily],
    [topIps],
    [recent],
  ] = await Promise.all([
    pool.query(
      `SELECT COUNT(*) AS total,
              SUM(detected_at >= CURDATE()) AS today,
              SUM(status = 'OPEN') AS open_count,
              SUM(severity = 'LOW') AS low,
              SUM(severity = 'MEDIUM') AS medium,
              SUM(severity = 'HIGH') AS high,
              SUM(severity = 'CRITICAL') AS critical
         FROM events`
    ),
    pool.query(
      `SELECT t.name, COUNT(e.id) AS cnt
         FROM attack_types t
         JOIN events e ON e.attack_type_id = t.id
        GROUP BY t.id
        ORDER BY cnt DESC`
    ),
    pool.query(
      `SELECT DATE_FORMAT(detected_at, '%Y-%m-%d') AS day, COUNT(*) AS cnt
         FROM events
        WHERE detected_at >= CURDATE() - INTERVAL 6 DAY
        GROUP BY day`
    ),
    pool.query(
      `SELECT s.id, s.ip_address, s.country_name, s.is_blocked, COUNT(*) AS cnt
         FROM events e
         JOIN source_ips s ON s.id = e.source_ip_id
        GROUP BY s.id
        ORDER BY cnt DESC
        LIMIT 5`
    ),
    pool.query(
      `SELECT e.id, e.severity, e.status, e.detected_at, t.name AS attack_type, s.ip_address
         FROM events e
         JOIN attack_types t ON t.id = e.attack_type_id
         JOIN source_ips s ON s.id = e.source_ip_id
        ORDER BY e.detected_at DESC, e.id DESC
        LIMIT 10`
    ),
  ]);
  return { summary, byType, daily, topIps, recent };
}

router.get('/', async (req, res) => {
  if (!isAdmin(req)) return res.redirect('/attack-types');

  const { summary, byType, daily, topIps, recent } = await cached('dashboard', DASHBOARD_TTL, loadDashboard);

  // SUM() 결과는 문자열로 오므로 숫자로 변환 (이벤트가 0건이면 NULL)
  const severityCount = {
    LOW: Number(summary.low) || 0,
    MEDIUM: Number(summary.medium) || 0,
    HIGH: Number(summary.high) || 0,
    CRITICAL: Number(summary.critical) || 0,
  };

  // 최근 7일, 이벤트 없는 날은 0으로 채움
  const dailyMap = Object.fromEntries(daily.map((r) => [r.day, r.cnt]));
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    days.push(ymd(d));
  }

  const chartData = {
    types: { labels: byType.map((r) => r.name), data: byType.map((r) => r.cnt) },
    daily: { labels: days.map((d) => d.slice(5)), data: days.map((d) => dailyMap[d] || 0) },
  };

  res.render('dashboard', {
    title: '대시보드',
    useChart: true,
    summary: {
      today: Number(summary.today) || 0,
      open: Number(summary.open_count) || 0,
      total: summary.total,
    },
    severityCount,
    topIps,
    recent,
    // </script> 같은 문자열이 들어가도 깨지지 않게 < 이스케이프
    chartJson: JSON.stringify(chartData).replace(/</g, '\\u003c'),
  });
});

module.exports = router;
