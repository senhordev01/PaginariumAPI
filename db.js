
require("dotenv").config();

const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

pool.on("connect", () => {
  console.log("Conectado ao PostgreSQL");
});

pool.on("error", (err) => {
  console.error("Erro PostgreSQL:", err);
});

module.exports = pool;
