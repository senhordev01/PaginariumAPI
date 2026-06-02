import pg from "pg";
import "dotenv/config";

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

pool.on("connect", () => {
  console.log("Conectado ao PostgreSQL");
});

pool.on("error", (err) => {
  console.error("Erro PostgreSQL:", err);
});

export default pool;