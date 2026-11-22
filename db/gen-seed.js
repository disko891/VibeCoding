// seed.sql 만드는 스크립트
// node db/gen-seed.js db/seed.sql "<admin 비번 bcrypt 해시>"
// 시드값 고정이라 돌릴 때마다 같은 데이터 나옴
const fs = require('fs');
const out = process.argv[2];
const HASH = process.argv[3];

let s = 20261117;
const rnd = () => ((s = (s * 1103515245 + 12345) % 2147483648) / 2147483648);
const pick = (a) => a[Math.floor(rnd() * a.length)];
const int = (a, b) => a + Math.floor(rnd() * (b - a + 1));
const q = (v) => "'" + String(v).replace(/\\/g, '\\\\').replace(/'/g, "''") + "'";

const types = [
  // name, code, desc, default severity, ports/proto, 설명 템플릿
  ['SQL 인젝션', 'SQLI', '웹 요청 파라미터에 SQL 구문을 삽입해 DB를 조작하려는 공격', 'HIGH',
    [[443, 'HTTPS'], [80, 'HTTP']],
    ["로그인 폼 id 파라미터에 ' OR 1=1-- 패턴 탐지", "/board/view?no= 파라미터에 UNION SELECT 구문 탐지", "검색어 파라미터에 SLEEP(5) 기반 Blind SQLi 시도", "/api/products?sort= 파라미터에 information_schema 조회 시도"]],
  ['XSS', 'XSS', '스크립트를 삽입해 사용자 브라우저에서 실행시키는 공격', 'MEDIUM',
    [[443, 'HTTPS'], [80, 'HTTP']],
    ['게시판 본문에 <script> 태그 삽입 시도', 'URL 파라미터에 javascript: 스킴 삽입 탐지', '댓글 입력값에 onerror 이벤트 핸들러 삽입 시도']],
  ['무차별 대입 공격', 'BRUTE', '계정 비밀번호를 반복 대입해 로그인을 시도하는 공격', 'HIGH',
    [[22, 'TCP'], [3389, 'TCP'], [443, 'HTTPS']],
    ['SSH 로그인 실패 {n}회 (1분 이내)', 'RDP 로그인 실패 {n}회 반복 탐지', '관리자 페이지 로그인 실패 {n}회 (계정: admin)']],
  ['포트 스캔', 'SCAN', '열린 포트와 서비스를 탐색하는 정찰 행위', 'LOW',
    [[0, 'TCP'], [0, 'UDP']],
    ['SYN 스캔으로 {n}개 포트 탐색', 'Nmap 서비스 버전 탐지 패턴 확인', 'UDP 포트 {n}개 대상 순차 스캔']],
  ['DDoS', 'DDOS', '대량 트래픽으로 서비스를 마비시키는 분산 서비스 거부 공격', 'CRITICAL',
    [[443, 'HTTPS'], [80, 'HTTP'], [53, 'UDP']],
    ['SYN Flood 초당 {n}k 패킷 유입', 'HTTP GET Flood 초당 {n}k 요청 탐지', 'DNS 증폭 공격 트래픽 급증']],
  ['악성코드 통신', 'MALWARE', '감염된 내부 호스트가 C&C 서버와 통신하는 행위', 'CRITICAL',
    [[443, 'HTTPS'], [8080, 'TCP'], [4444, 'TCP']],
    ['알려진 C&C 서버로 비콘 통신 탐지', '내부 호스트에서 비정상 주기의 외부 접속 반복', '악성 도메인 질의 후 대용량 데이터 전송']],
  ['경로 탐색', 'PATH_TRAV', '../ 등을 이용해 웹 루트 밖의 파일에 접근하려는 공격', 'HIGH',
    [[443, 'HTTPS'], [80, 'HTTP']],
    ['/download?file=../../etc/passwd 요청 탐지', 'URL 인코딩된 %2e%2e%2f 경로 탐색 시도', '/static/..%5c..%5cwindows/win.ini 접근 시도']],
  ['원격 코드 실행', 'RCE', '취약점을 이용해 서버에서 임의 명령을 실행하려는 공격', 'CRITICAL',
    [[443, 'HTTPS'], [8080, 'TCP']],
    ['Log4Shell(${jndi:ldap://}) 패턴 헤더 탐지', '파라미터에 ;cat /etc/passwd 명령 삽입 시도', '역직렬화 취약점 공격 페이로드 탐지']],
  ['웹셸 업로드', 'WEBSHELL', '파일 업로드 기능을 악용해 서버에 웹셸을 올리려는 공격', 'CRITICAL',
    [[443, 'HTTPS'], [80, 'HTTP']],
    ['이미지 업로드에 .jsp 웹셸 업로드 시도', 'shell.php.jpg 이중 확장자 파일 업로드 탐지', '업로드 디렉터리 내 cmd= 파라미터 요청 탐지']],
  ['피싱 메일', 'PHISHING', '악성 링크나 첨부파일로 계정 정보를 탈취하려는 메일', 'MEDIUM',
    [[25, 'TCP'], [587, 'TCP']],
    ['사칭 도메인에서 비밀번호 재설정 메일 {n}건 수신', '매크로 포함 .docm 첨부파일 메일 탐지', '단축 URL로 위장한 로그인 페이지 링크 탐지']],
  ['랜섬웨어', 'RANSOM', '파일을 암호화하고 금전을 요구하는 악성코드 활동', 'CRITICAL',
    [[445, 'TCP'], [443, 'HTTPS']],
    ['공유 폴더에서 파일 {n}개 연속 확장자 변경 탐지', 'vssadmin 섀도 복사본 삭제 명령 실행 탐지', '랜섬노트(README_DECRYPT.txt) 생성 탐지']],
  ['DNS 터널링', 'DNS_TUNNEL', 'DNS 질의에 데이터를 숨겨 외부로 유출하는 행위', 'HIGH',
    [[53, 'UDP']],
    ['비정상적으로 긴 서브도메인 DNS 질의 {n}건', '단일 도메인 대상 TXT 레코드 질의 급증', 'Base32 인코딩 패턴의 DNS 질의 탐지']],
  ['크리덴셜 스터핑', 'CRED_STUFF', '유출된 계정 목록으로 여러 계정에 로그인을 시도하는 공격', 'HIGH',
    [[443, 'HTTPS']],
    ['서로 다른 계정 {n}개로 로그인 시도 (10분 이내)', '유출 계정 목록과 일치하는 로그인 시도 탐지', '자동화 도구 User-Agent로 로그인 API 반복 호출']],
  ['ARP 스푸핑', 'ARP_SPOOF', '내부망에서 ARP 응답을 위조해 트래픽을 가로채는 공격', 'MEDIUM',
    [[0, 'TCP']],
    ['게이트웨이 MAC 주소 변경 ARP 응답 탐지', '동일 IP에 대한 서로 다른 MAC 응답 반복', '요청 없는 ARP Reply {n}건 탐지']],
];

// 테스트/문서용 대역(RFC 5737)과 사설 대역만 사용
const ips = [
  ['203.0.113.15', 'CN', '중국', 1, 'SSH 무차별 대입 반복'],
  ['203.0.113.47', 'CN', '중국', 0, null],
  ['203.0.113.88', 'RU', '러시아', 1, 'C&C 서버로 확인됨'],
  ['203.0.113.121', 'RU', '러시아', 0, null],
  ['198.51.100.23', 'US', '미국', 0, '클라우드 호스팅 대역'],
  ['198.51.100.77', 'US', '미국', 0, null],
  ['198.51.100.142', 'KP', '북한', 1, '위협 인텔리전스 등록 IP'],
  ['198.51.100.200', 'BR', '브라질', 0, null],
  ['192.0.2.34', 'NL', '네덜란드', 0, 'VPN 출구 노드 추정'],
  ['192.0.2.66', 'IR', '이란', 0, null],
  ['192.0.2.101', 'VN', '베트남', 0, null],
  ['192.0.2.189', 'KR', '대한민국', 0, '국내 IDC 대역'],
  ['192.0.2.250', 'IN', '인도', 0, null],
  ['10.10.20.57', null, '내부망', 0, '내부 PC (악성코드 감염 의심)'],
  ['10.10.30.112', null, '내부망', 0, '개발팀 서버'],
];

const hosts = ['web-01.corp.local', 'web-02.corp.local', 'api.corp.local', 'mail.corp.local', 'vpn.corp.local', 'db-01.corp.local', 'erp.corp.local'];
const sevs = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

// 공격 유형별로 주로 등장하는 IP (index)
const typeIps = {
  0: [1, 4, 5, 8, 9, 12], 1: [4, 7, 10, 11, 12], 2: [0, 1, 3, 6, 9, 10],
  3: [0, 2, 3, 5, 7, 8, 14], 4: [2, 3, 6, 7], 5: [13, 14, 2],
  6: [4, 8, 9, 12], 7: [2, 6, 3], 8: [1, 6, 9, 10], 9: [5, 7, 10, 11],
  10: [13, 14], 11: [13, 14], 12: [0, 3, 4, 8, 10], 13: [13, 14],
};
const typeWeights = [10, 8, 12, 14, 4, 5, 4, 3, 3, 5, 2, 3, 5, 2]; // 합 80

// 내부 PC에서 발생하는 유형 (대상이 업무용 PC)
const INTERNAL_TYPES = ['MALWARE', 'RANSOM', 'DNS_TUNNEL', 'ARP_SPOOF'];

let sql = `-- 샘플 데이터 (db/gen-seed.js로 생성)
-- 날짜는 NOW() 기준이라 넣을 때마다 최근 30일로 들어감
-- IP는 테스트용 대역(203.0.113.x 등) + 사설 IP만 씀

USE security_db;

SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE actions;
TRUNCATE TABLE events;
TRUNCATE TABLE source_ips;
TRUNCATE TABLE attack_types;
TRUNCATE TABLE admins;
SET FOREIGN_KEY_CHECKS = 1;

-- 관리자 (admin / admin1234, bcrypt cost 10)
INSERT INTO admins (id, username, password_hash, name, email, role) VALUES
  (1, 'admin', ${q(HASH)}, '관제 관리자', 'admin@corp.local', 'ADMIN');

-- 공격 유형
INSERT INTO attack_types (id, name, code, description, default_severity) VALUES
${types.map((t, i) => `  (${i + 1}, ${q(t[0])}, ${q(t[1])}, ${q(t[2])}, ${q(t[3])})`).join(',\n')};

-- 출발지 IP
INSERT INTO source_ips (id, ip_address, country_code, country_name, is_blocked, memo, created_at) VALUES
${ips.map((p, i) => `  (${i + 1}, ${q(p[0])}, ${p[1] ? q(p[1]) : 'NULL'}, ${q(p[2])}, ${p[3]}, ${p[4] ? q(p[4]) : 'NULL'}, NOW() - INTERVAL ${int(31, 60)} DAY)`).join(',\n')};
`;

// 이벤트 생성
const evs = [];
typeWeights.forEach((w, ti) => { for (let k = 0; k < w; k++) evs.push(ti); });
const events = evs.map((ti) => {
  const t = types[ti];
  const ago = int(5, 30 * 24 * 60 - 1); // 분 단위, 최근 30일
  const [port0, proto] = pick(t[4]);
  const port = port0 === 0 ? 'NULL' : port0;
  // 기본 위험도에서 ±1 흔들기
  let si = sevs.indexOf(t[3]);
  const r = rnd();
  if (r < 0.2) si = Math.max(0, si - 1); else if (r > 0.8) si = Math.min(3, si + 1);
  const desc = pick(t[5]).replace('{n}', int(12, 950));
  let host = pick(hosts);
  if (INTERNAL_TYPES.includes(t[1])) host = pick(['ws-dev-031', 'ws-hr-012', 'ws-fin-007']) + '.corp.local';
  if (t[1] === 'PHISHING') host = 'mail.corp.local';
  return { ti, ip: pick(typeIps[ti]), host, port, proto, sev: sevs[si], desc, ago };
}).sort((a, b) => b.ago - a.ago); // 오래된 순으로 id 부여

// 상태: 오래될수록 해결 확률 높음
events.forEach((e) => {
  const day = e.ago / 1440;
  const r = rnd();
  e.status = day > 7 ? (r < 0.85 ? 'RESOLVED' : r < 0.95 ? 'INVESTIGATING' : 'OPEN')
    : day > 2 ? (r < 0.45 ? 'RESOLVED' : r < 0.8 ? 'INVESTIGATING' : 'OPEN')
    : (r < 0.15 ? 'RESOLVED' : r < 0.45 ? 'INVESTIGATING' : 'OPEN');
});

sql += `
-- 보안 이벤트 (${events.length}건)
INSERT INTO events (id, attack_type_id, source_ip_id, target_host, target_port, protocol, severity, status, description, detected_at) VALUES
${events.map((e, i) => `  (${i + 1}, ${e.ti + 1}, ${e.ip + 1}, ${q(e.host)}, ${e.port}, ${q(e.proto)}, ${q(e.sev)}, ${q(e.status)}, ${q(e.desc)}, NOW() - INTERVAL ${e.ago} MINUTE)`).join(',\n')};
`;

// 조치 내역
const acts = [];
events.forEach((e, i) => {
  if (e.status === 'OPEN') return;
  let t = e.ago - int(3, Math.min(40, e.ago - 1)); // 탐지 후 수 분 내 착수
  const add = (type, d) => { acts.push([i + 1, type, d, Math.max(t, 1)]); };
  add('INVESTIGATE', '이벤트 확인 및 분석 착수');
  const ipBlocked = ips[e.ip][3] === 1;
  if (e.sev === 'CRITICAL') { t -= int(1, Math.min(30, Math.max(1, t - 1))); add('ESCALATE', '보안팀장 및 인프라팀에 보고'); }
  if (e.status === 'RESOLVED') {
    t -= int(1, Math.min(240, Math.max(1, t - 1)));
    if (ipBlocked || e.sev === 'HIGH' || e.sev === 'CRITICAL') {
      add('BLOCK_IP', `방화벽에 ${ips[e.ip][0]} 차단 정책 적용`);
      t -= int(1, Math.min(20, Math.max(1, t - 1)));
    }
    add('RESOLVE', pick(['추가 시도 없음 확인 후 종결', '오탐 아님 확인, 차단 조치 완료로 종결', 'WAF 룰 업데이트 후 종결', '대상 서버 영향 없음 확인 후 종결']));
  } else if (rnd() < 0.5) {
    t -= int(1, Math.min(60, Math.max(1, t - 1)));
    add('NOTE', pick(['동일 IP 추가 로그 수집 중', '대상 서버 접근 로그 확인 요청', '위협 인텔리전스 조회 결과 대기']));
  }
});

sql += `
-- 조치 내역 (${acts.length}건)
INSERT INTO actions (event_id, admin_id, action_type, description, created_at) VALUES
${acts.map((a) => `  (${a[0]}, 1, ${q(a[1])}, ${q(a[2])}, NOW() - INTERVAL ${a[3]} MINUTE)`).join(',\n')};

-- 차단 조치가 있었던 IP는 차단 상태로 반영
UPDATE source_ips s
  JOIN (SELECT DISTINCT e.source_ip_id
          FROM actions a JOIN events e ON e.id = a.event_id
         WHERE a.action_type = 'BLOCK_IP') b ON b.source_ip_id = s.id
   SET s.is_blocked = 1;
`;

fs.writeFileSync(out, sql);
console.log(`events=${events.length} actions=${acts.length}`);
