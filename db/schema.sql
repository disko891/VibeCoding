-- security_db 스키마

CREATE DATABASE IF NOT EXISTS security_db DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE security_db;

DROP TABLE IF EXISTS actions;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS source_ips;
DROP TABLE IF EXISTS attack_types;
DROP TABLE IF EXISTS admins;

-- 관리자
CREATE TABLE admins (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(50) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  name VARCHAR(50) NOT NULL,
  email VARCHAR(100),
  role ENUM('ADMIN','ANALYST') NOT NULL DEFAULT 'ANALYST',
  last_login_at DATETIME,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_admins_username (username)
) ENGINE=InnoDB;

-- 공격 유형
CREATE TABLE attack_types (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(100) NOT NULL,
  code VARCHAR(30) NOT NULL,          -- SQLI, XSS ...
  description TEXT,
  default_severity ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL DEFAULT 'MEDIUM',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_attack_types_name (name),
  UNIQUE KEY uq_attack_types_code (code)
) ENGINE=InnoDB;

-- 출발지 IP
CREATE TABLE source_ips (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  ip_address VARCHAR(45) NOT NULL,    -- ipv6까지 고려
  country_code CHAR(2),
  country_name VARCHAR(50),
  is_blocked TINYINT(1) NOT NULL DEFAULT 0,
  memo VARCHAR(255),
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_source_ips_ip (ip_address),
  KEY idx_source_ips_blocked (is_blocked)
) ENGINE=InnoDB;

-- 보안 이벤트
CREATE TABLE events (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  attack_type_id INT UNSIGNED NOT NULL,
  source_ip_id INT UNSIGNED NOT NULL,
  target_host VARCHAR(100) NOT NULL,
  target_port SMALLINT UNSIGNED,
  protocol ENUM('TCP','UDP','ICMP','HTTP','HTTPS') NOT NULL DEFAULT 'TCP',
  severity ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
  status ENUM('OPEN','INVESTIGATING','RESOLVED') NOT NULL DEFAULT 'OPEN',
  description TEXT,
  detected_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_events_detected_at (detected_at),
  -- 필터 + 최신순 정렬을 인덱스만으로 처리 (filesort 방지)
  KEY idx_events_severity_detected (severity, detected_at),
  KEY idx_events_status_detected (status, detected_at),
  KEY idx_events_type_detected (attack_type_id, detected_at),
  CONSTRAINT fk_events_attack_type FOREIGN KEY (attack_type_id) REFERENCES attack_types (id),
  CONSTRAINT fk_events_source_ip FOREIGN KEY (source_ip_id) REFERENCES source_ips (id)
) ENGINE=InnoDB;

-- 조치 내역 (이벤트 지우면 같이 삭제)
CREATE TABLE actions (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  event_id INT UNSIGNED NOT NULL,
  admin_id INT UNSIGNED NOT NULL,
  action_type ENUM('INVESTIGATE','BLOCK_IP','ESCALATE','RESOLVE','NOTE') NOT NULL,
  description TEXT,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_actions_created_at (created_at),
  KEY idx_actions_event_created (event_id, created_at),
  KEY idx_actions_type_created (action_type, created_at),
  CONSTRAINT fk_actions_event FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE,
  CONSTRAINT fk_actions_admin FOREIGN KEY (admin_id) REFERENCES admins (id)
) ENGINE=InnoDB;
