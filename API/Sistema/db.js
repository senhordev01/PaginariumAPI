import pg from "pg";
import "dotenv/config";

const { Pool } = pg;

const connectionString =
  process.env.ENV === "prod"
    ? process.env.DATABASE_URL_SUPA
    : process.env.DATABASE_URL;

const pool = new Pool({
  connectionString,
});

pool.on("connect", () => {
  console.log("Conectado ao PostgreSQL");
});

pool.on("error", (err) => {
  console.error("Erro PostgreSQL:", err);
});

export default pool;