// 미처리(OPEN) 이벤트가 하나도 안 남으면 새 미처리 이벤트를 하나 만든다
// (상태 변경, 이벤트 삭제, 서버 시작 때 호출)
// db에는 pool이나 트랜잭션 중인 connection 아무거나 넘기면 됨

const HOSTS = ['web-01.corp.local', 'web-02.corp.local', 'api.corp.local', 'mail.corp.local', 'vpn.corp.local', 'erp.corp.local'];

// 공격 유형 코드별 포트/프로토콜, 탐지 문구
const TEMPLATES = {
  SQLI: { targets: [[443, 'HTTPS'], [80, 'HTTP']], msgs: ['로그인 폼 파라미터에 UNION SELECT 구문 탐지', '검색 파라미터에 SLEEP() 기반 Blind SQLi 시도'] },
  XSS: { targets: [[443, 'HTTPS'], [80, 'HTTP']], msgs: ['게시판 본문에 <script> 태그 삽입 시도', '댓글 입력값에 onerror 핸들러 삽입 시도'] },
  BRUTE: { targets: [[22, 'TCP'], [3389, 'TCP']], msgs: ['SSH 로그인 실패 {n}회 반복', 'RDP 로그인 실패 {n}회 반복'] },
  SCAN: { targets: [[null, 'TCP'], [null, 'UDP']], msgs: ['SYN 스캔으로 {n}개 포트 탐색', '서비스 버전 탐지 패턴 확인'] },
  DDOS: { targets: [[443, 'HTTPS'], [53, 'UDP']], msgs: ['SYN Flood 초당 {n}k 패킷 유입', 'HTTP GET Flood 초당 {n}k 요청'] },
  MALWARE: { targets: [[443, 'HTTPS'], [4444, 'TCP']], msgs: ['알려진 C&C 서버로 비콘 통신 탐지', '비정상 주기의 외부 접속 반복'] },
  PATH_TRAV: { targets: [[443, 'HTTPS'], [80, 'HTTP']], msgs: ['/download?file=../../etc/passwd 요청 탐지', '%2e%2e%2f 인코딩 경로 탐색 시도'] },
  RCE: { targets: [[443, 'HTTPS'], [8080, 'TCP']], msgs: ['Log4Shell(${jndi:ldap://}) 패턴 헤더 탐지', '파라미터에 OS 명령 삽입 시도'] },
  WEBSHELL: { targets: [[443, 'HTTPS'], [80, 'HTTP']], msgs: ['이중 확장자 파일(shell.php.jpg) 업로드 탐지', '업로드 디렉터리 내 cmd= 요청 탐지'] },
  PHISHING: { targets: [[25, 'TCP'], [587, 'TCP']], msgs: ['사칭 도메인 비밀번호 재설정 메일 {n}건 수신', '매크로 포함 첨부파일 메일 탐지'] },
  RANSOM: { targets: [[445, 'TCP']], msgs: ['공유 폴더 파일 {n}개 연속 확장자 변경', '섀도 복사본 삭제 명령 실행 탐지'] },
  DNS_TUNNEL: { targets: [[53, 'UDP']], msgs: ['비정상적으로 긴 서브도메인 질의 {n}건', 'TXT 레코드 질의 급증'] },
  CRED_STUFF: { targets: [[443, 'HTTPS']], msgs: ['서로 다른 계정 {n}개로 로그인 시도', '유출 계정 목록과 일치하는 로그인 시도'] },
  ARP_SPOOF: { targets: [[null, 'TCP']], msgs: ['게이트웨이 MAC 주소 변경 ARP 응답 탐지', '요청 없는 ARP Reply {n}건 탐지'] },
};
const DEFAULT_TEMPLATE = { targets: [[443, 'HTTPS'], [80, 'HTTP'], [22, 'TCP']], msgs: ['이상 트래픽 탐지'] };

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

// 새 이벤트를 만들었으면 id, 아니면 null
async function createIfNoOpen(db) {
  const [[{ pending }]] = await db.query("SELECT COUNT(*) AS pending FROM events WHERE status = 'OPEN'");
  if (pending > 0) return null;

  const [types] = await db.query('SELECT id, code, default_severity FROM attack_types');
  const [ips] = await db.query('SELECT id FROM source_ips');
  if (!types.length || !ips.length) return null;

  const type = pick(types);
  const tpl = TEMPLATES[type.code] || DEFAULT_TEMPLATE;
  const [port, protocol] = pick(tpl.targets);
  const description = pick(tpl.msgs).replace('{n}', 10 + Math.floor(Math.random() * 900));

  // 동시에 두 명이 마지막 미처리 이벤트를 처리해도 하나만 생기도록 조건부 INSERT
  const [result] = await db.query(
    `INSERT INTO events (attack_type_id, source_ip_id, target_host, target_port, protocol, severity, status, description, detected_at)
     SELECT ?, ?, ?, ?, ?, ?, 'OPEN', ?, NOW() FROM DUAL
      WHERE NOT EXISTS (SELECT 1 FROM (SELECT id FROM events WHERE status = 'OPEN' LIMIT 1) AS p)`,
    [type.id, pick(ips).id, pick(HOSTS), port, protocol, type.default_severity, description]
  );
  return result.affectedRows ? result.insertId : null;
}

module.exports = { createIfNoOpen };
