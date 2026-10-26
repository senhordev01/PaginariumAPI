import pg from "pg";
import "dotenv/config";

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,

  // Evita muitas conexões simultâneas no Supabase
  max: 3,

  // Fecha conexões que ficaram paradas
  idleTimeoutMillis: 30000,

  // Tempo máximo para conseguir uma conexão
  connectionTimeoutMillis: 10000,

  // Mantém a conexão TCP ativa
  keepAlive: true,
});

pool.on("connect", () => {
  console.log("Conectado ao PostgreSQL");
});

pool.on("error", (err) => {
  console.error("Erro PostgreSQL:", err);
});

export default pool;