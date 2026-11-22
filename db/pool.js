const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'security_db',
  charset: 'utf8mb4',
  connectionLimit: 10,
  dateStrings: true, // 날짜가 타임존 때문에 밀리는 문제 있어서 문자열로 받음
});

module.exports = pool;
