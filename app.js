require('dotenv').config();

const os = require('os');
const path = require('path');
const express = require('express');
const session = require('express-session');

const authRouter = require('./routes/auth');
const statsRouter = require('./routes/stats');
const eventsRouter = require('./routes/events');
const attackTypesRouter = require('./routes/attackTypes');
const ipsRouter = require('./routes/ips');
const actionsRouter = require('./routes/actions');
const { requireAdmin } = require('./lib/auth');

const app = express();
const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.error('.env에 SESSION_SECRET 없음');
  process.exit(1);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// nginx 같은 프록시 뒤에서 돌릴 때만 켤 것.
// 프록시 없이 켜면 X-Forwarded-For 헤더로 IP를 속여서 로그인 차단을 피할 수 있음
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  rolling: true, // 요청할 때마다 만료시간 연장 → 일정 시간 아무것도 안 하면 로그아웃
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === 'true', // https 붙이면 true
    maxAge: (Number(process.env.SESSION_IDLE_MIN) || 30) * 60 * 1000,
  },
}));

// 화면 표시용 라벨/색상
const SEVERITY_BADGE = { LOW: 'sev-low', MEDIUM: 'sev-medium', HIGH: 'sev-high', CRITICAL: 'sev-critical' };
const STATUS_LABEL = { OPEN: '미처리', INVESTIGATING: '조사중', RESOLVED: '해결' };
const STATUS_BADGE = { OPEN: 'st-open', INVESTIGATING: 'st-investigating', RESOLVED: 'st-resolved' };
const ACTION_LABEL = { INVESTIGATE: '조사 착수', BLOCK_IP: 'IP 차단', ESCALATE: '상위 보고', RESOLVE: '해결 처리', NOTE: '메모' };

app.use((req, res, next) => {
  res.locals.currentAdmin = req.session.admin || null;
  res.locals.isAdmin = !!(req.session.admin && req.session.admin.role === 'ADMIN');
  res.locals.currentPath = req.path;
  res.locals.SEVERITY_BADGE = SEVERITY_BADGE;
  res.locals.STATUS_LABEL = STATUS_LABEL;
  res.locals.STATUS_BADGE = STATUS_BADGE;
  res.locals.ACTION_LABEL = ACTION_LABEL;

  // 플래시 메시지: 한 번 보여주고 삭제
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  req.flash = (type, msg) => { req.session.flash = { type, msg }; };
  next();
});

app.use(authRouter);

// 여기부터는 로그인 필요
app.use((req, res, next) => {
  if (!req.session.admin) return res.redirect('/login');
  next();
});

// 조회 계정(ANALYST)은 공격 유형 / 조치 내역만. 나머지는 관리자만
app.use('/', statsRouter);                    // 대시보드 (조회 계정은 공격 유형으로 보냄)
app.use('/attack-types', attackTypesRouter);  // 목록은 둘 다, 등록/수정/삭제는 관리자
app.use('/actions', actionsRouter);
app.use('/events', requireAdmin, eventsRouter);
app.use('/ips', requireAdmin, ipsRouter);

app.use((req, res) => {
  res.status(404).render('error', { title: '404', status: 404, message: '페이지를 찾을 수 없습니다.' });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', { title: '오류', status: 500, message: '서버 오류가 발생했습니다.' });
});

// HOST 비워두면 모든 네트워크(IPv4+IPv6)에서 접속 받음 = 다른 PC에서도 접속 가능
// 이 PC에서만 쓰려면 .env에 HOST=127.0.0.1
const HOST = process.env.HOST || undefined;

const server = app.listen(PORT, HOST, (err) => {
  if (err) return; // 아래 error 핸들러에서 처리
  console.log(`server start : http://localhost:${PORT}`);
  if (!HOST || HOST === '0.0.0.0' || HOST === '::') {
    const addrs = Object.values(os.networkInterfaces()).flat()
      .filter((a) => a && a.family === 'IPv4' && !a.internal);
    addrs.forEach((a) => console.log(`  다른 PC에서 접속 : http://${a.address}:${PORT}`));
  }
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`${PORT}번 포트를 이미 다른 프로그램(이미 실행 중인 서버 등)이 쓰고 있습니다.`);
    process.exit(1);
  }
  throw err;
});
