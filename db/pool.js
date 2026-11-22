const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'security_db',
  charset: 'utf8mb4',
  connectionLimit: 10,
  maxIdle: 3,              // 한가할 때는 연결 3개만 유지 (MySQL 메모리 절약)
  idleTimeout: 60 * 1000,  // 1분 이상 안 쓴 연결은 닫음
  enableKeepAlive: true,   // 오래 쉬다가 끊긴 연결 때문에 생기는 오류 방지
  dateStrings: true, // 날짜가 타임존 때문에 밀리는 문제 있어서 문자열로 받음
});

module.exports = pool;
