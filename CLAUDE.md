# 프로젝트: 보안 이벤트(침입 탐지) 로그 대시보드

## 기술 스택 (반드시 지킬 것)
- Node.js + Express + EJS + mysql2(promise 방식)
- ORM(Sequelize, Prisma 등)과 프론트 프레임워크(React 등)는 사용 금지
- 스타일은 Bootstrap 5 CDN만 사용, 차트는 Chart.js CDN
- 로그인: express-session + bcrypt
- 환경변수: dotenv (.env), .env는 절대 git에 올리지 않는다

## 데이터베이스 (DB 이름: security_db)
- admins: 관제 관리자
- attack_types: 공격 유형
- source_ips: 공격 출발지 IP
- events: 보안 이벤트 (attack_type_id, source_ip_id 외래키)
- actions: 이벤트 조치 내역 (event_id, admin_id 외래키)

## 폴더 구조
- app.js (진입점, 포트 3000)
- db/pool.js, db/schema.sql, db/seed.sql
- routes/ (auth.js, events.js, attackTypes.js, ips.js, stats.js)
- views/ (EJS), views/partials/ (header, footer, nav)
- public/ (css, js)

## 규칙
- SQL은 반드시 ? 플레이스홀더 사용 (SQL Injection 방지)
- 모든 외래키는 FOREIGN KEY로 명시
- 배포 대상: AWS EC2 Ubuntu, pm2로 실행
- 코드 주석과 화면 문구는 한국어
- 로컬 MySQL 접속: mysql 명령어 사용 가능 (root 계정)