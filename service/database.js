const { Pool } = require('pg');


const pool = new Pool({
  host: 'localhost',
  port: 5432,
  user: 'postgres',
  password: 'ebac',
  database: 'postgres',
});

module.exports = pool