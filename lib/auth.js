// 권한 체크
// ADMIN   : 전체 기능
// ANALYST : 공격 유형, 조치 내역 조회만

const isAdmin = (req) => req.session.admin && req.session.admin.role === 'ADMIN';

function requireAdmin(req, res, next) {
  if (isAdmin(req)) return next();
  res.status(403).render('error', {
    title: '권한 없음',
    status: 403,
    message: '이 메뉴는 관리자 계정만 사용할 수 있습니다.',
  });
}

module.exports = { isAdmin, requireAdmin };
