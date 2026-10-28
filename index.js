import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import pool from "./db.js";

const app = express();
const porta = process.env.PORT || 8080;

const CHAVE_TOKEN = process.env.CHAVE_TOKEN;
if (!CHAVE_TOKEN) {
  console.error("Defina CHAVE_TOKEN no .env");
  process.exit(1);
}

const TOKEN_EXPIRA = process.env.TOKEN_EXPIRA || "7d";
const REEMBOLSO_SEGUNDOS = Number(process.env.REEMBOLSO_SEGUNDOS) || 300;
const CREDITO_MAXIMO = 1000;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.set("trust proxy", 1);
app.use(cors());
app.use(express.json());

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 30 * 1024 * 1024 },
});
const uploadLivro = upload.fields([
  { name: "capa", maxCount: 1 },
  { name: "pdf", maxCount: 1 },
]);

/* ===================== HELPERS ===================== */

function baseUrl(req) {
  return (process.env.API_URL || `${req.protocol}://${req.get("host")}`).replace(/\/$/, "");
}

function usuarioPublico(u, tipo = "normal") {
  return {
    id: u.id,
    nome: u.nome,
    email: u.email,
    credito: Number(u.credito ?? 0),
    tipo,
  };
}

/* Capa: se foi enviada pelo app usa a rota interna; senão usa a URL antiga salva. */
function urlCapa(req, id, temCapa, capaUrl, versao) {
  if (temCapa) return `${baseUrl(req)}/livros/${id}/capa?v=${versao}`;
  return capaUrl || null;
}

function livroPublico(req, l) {
  return {
    id: l.id,
    nome: l.nome,
    genero: l.genero,
    valor: Number(l.valor),
    capa_url: urlCapa(req, l.id, l.tem_capa, l.capa_url, l.versao),
    tem_pdf: !!(l.tem_pdf || l.pdf_url),
  };
}

const SELECT_LIVRO = `
  SELECT id, nome, genero, valor::float8 AS valor, capa_url, pdf_url,
         (capa_dados IS NOT NULL) AS tem_capa,
         (pdf_dados  IS NOT NULL) AS tem_pdf,
         EXTRACT(EPOCH FROM atualizado_em)::bigint AS versao
  FROM livros
`;

function erroServidor(res, erro, rotulo = "ERRO") {
  console.log(`${rotulo}:`, erro.message);
  return res.status(500).json("Erro no servidor");
}

function lerBearer(req) {
  const h = req.headers.authorization;
  if (!h) return null;
  const [tipo, token] = h.split(" ");
  return tipo === "Bearer" && token ? token : null;
}

/* Um e-mail não pode existir em usuarios nem em administradores. */
async function emailEmUso(email, ignorarUsuarioId = null) {
  const u = await pool.query("SELECT id FROM usuarios WHERE email = $1", [email]);
  if (u.rows.length > 0 && Number(u.rows[0].id) !== Number(ignorarUsuarioId)) return true;
  const a = await pool.query("SELECT 1 FROM administradores WHERE email = $1", [email]);
  return a.rows.length > 0;
}

/* ===================== MIDDLEWARES ===================== */

function checar_token(req, res, next) {
  const token = lerBearer(req);
  if (!token) return res.status(401).json("Token não enviado");

  try {
    const decoded = jwt.verify(token, CHAVE_TOKEN);
    if (decoded.pdf) return res.status(401).json("Token inválido");
    req.usuario = decoded;
    next();
  } catch {
    return res.status(401).json("Token inválido ou expirado");
  }
}

function somenteAdmin(req, res, next) {
  if (req.usuario?.tipo !== "admin") {
    return res.status(403).json("Acesso restrito a administradores");
  }
  next();
}

/* Rotas de conta/aluguel valem só para usuários comuns (ids de admin vêm de outra tabela). */
function somenteUsuario(req, res, next) {
  if (req.usuario?.tipo === "admin") {
    return res.status(403).json("Rota disponível apenas para usuários");
  }
  next();
}

function verificarAcesso(req, id) {
  return Number(req.usuario.id) === Number(id);
}

/* ===================== SAÚDE ===================== */

app.get("/", (req, res) => res.json({ ok: true, api: "Paginarium" }));

/* ===================== CADASTRO / LOGIN ===================== */

app.post("/cadastro", async (req, res) => {
  try {
    const { nome, senha } = req.body || {};
    const email = String(req.body?.email || "").trim().toLowerCase();

    if (!nome?.trim() || !email || !senha) {
      return res.status(422).json("Campos obrigatórios faltando");
    }
    if (!EMAIL_REGEX.test(email)) {
      return res.status(422).json("E-mail inválido");
    }
    if (String(senha).length < 6) {
      return res.status(422).json("A senha deve ter pelo menos 6 caracteres");
    }
    if (await emailEmUso(email)) {
      return res.status(409).json("Esse usuário já foi cadastrado");
    }

    const senhaHash = await bcrypt.hash(String(senha), 12);

    // O saldo inicial vem do DEFAULT da coluna credito.
    const resultado = await pool.query(
      `INSERT INTO usuarios (nome, email, senha)
       VALUES ($1, $2, $3)
       RETURNING id, nome, email, credito`,
      [nome.trim(), email, senhaHash]
    );

    res.status(201).json({
      usuario: usuarioPublico(resultado.rows[0]),
      msg: "Usuário cadastrado com sucesso",
    });
  } catch (erro) {
    if (erro.code === "23505") return res.status(409).json("Esse usuário já foi cadastrado");
    erroServidor(res, erro, "ERRO CADASTRO");
  }
});

app.post("/login", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const senha = req.body?.senha;

    if (!email || !senha) {
      return res.status(422).json("Email e senha obrigatórios");
    }

    let tipo = "normal";
    let r = await pool.query(
      "SELECT id, nome, email, senha, credito FROM usuarios WHERE email = $1",
      [email]
    );

    if (r.rows.length === 0) {
      r = await pool.query(
        "SELECT id, nome, email, senha FROM administradores WHERE email = $1",
        [email]
      );
      tipo = "admin";
    }

    const conta = r.rows[0];
    const senhaValida = conta && (await bcrypt.compare(String(senha), conta.senha));
    if (!senhaValida) {
      return res.status(401).json("E-mail ou senha incorretos.");
    }

    const token = jwt.sign(
      { id: conta.id, email: conta.email, tipo },
      CHAVE_TOKEN,
      { expiresIn: TOKEN_EXPIRA }
    );

    res.json({
      mensagem: "Login realizado",
      token,
      usuario: usuarioPublico(conta, tipo),
    });
  } catch (erro) {
    erroServidor(res, erro, "ERRO LOGIN");
  }
});

/* Criação de administradores (protegida por ADMIN_SECRET) */
app.post("/admin/cadastro", async (req, res) => {
  try {
    if (!process.env.ADMIN_SECRET || req.headers["x-admin-secret"] !== process.env.ADMIN_SECRET) {
      return res.status(403).json("Acesso negado");
    }

    const { nome, senha } = req.body || {};
    const email = String(req.body?.email || "").trim().toLowerCase();

    if (!nome?.trim() || !EMAIL_REGEX.test(email) || !senha || String(senha).length < 6) {
      return res.status(422).json("Dados inválidos");
    }
    if (await emailEmUso(email)) {
      return res.status(409).json("Esse e-mail já está cadastrado");
    }

    const senhaHash = await bcrypt.hash(String(senha), 12);
    const resultado = await pool.query(
      `INSERT INTO administradores (nome, email, senha)
       VALUES ($1, $2, $3)
       RETURNING id, nome, email`,
      [nome.trim(), email, senhaHash]
    );

    res.status(201).json({
      usuario: usuarioPublico(resultado.rows[0], "admin"),
      msg: "Administrador cadastrado com sucesso",
    });
  } catch (erro) {
    erroServidor(res, erro, "ERRO ADMIN");
  }
});

/* ===================== USUÁRIOS ===================== */

app.get("/usuarios/:id", checar_token, somenteUsuario, async (req, res) => {
  try {
    if (!verificarAcesso(req, req.params.id)) {
      return res.status(403).json("Acesso negado");
    }

    const resultado = await pool.query(
      "SELECT id, nome, email, credito FROM usuarios WHERE id = $1",
      [req.params.id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json("Usuário não encontrado");
    }

    res.json(usuarioPublico(resultado.rows[0]));
  } catch (erro) {
    erroServidor(res, erro, "ERRO GET USUARIO");
  }
});

app.put("/usuarios/:id", checar_token, somenteUsuario, async (req, res) => {
  try {
    if (!verificarAcesso(req, req.params.id)) {
      return res.status(403).json("Acesso negado");
    }

    const nome = req.body?.nome?.trim() || null;
    const email = req.body?.email ? String(req.body.email).trim().toLowerCase() : null;

    if (!nome && !email) {
      return res.status(422).json("Informe nome ou e-mail");
    }
    if (nome && (nome.length < 2 || nome.length > 100)) {
      return res.status(422).json("O nome deve ter entre 2 e 100 caracteres");
    }
    if (email && !EMAIL_REGEX.test(email)) {
      return res.status(422).json("E-mail inválido");
    }
    if (email && (await emailEmUso(email, req.params.id))) {
      return res.status(409).json("Esse e-mail já está em uso");
    }

    const resultado = await pool.query(
      `UPDATE usuarios
       SET nome = COALESCE($1, nome), email = COALESCE($2, email)
       WHERE id = $3
       RETURNING id, nome, email, credito`,
      [nome, email, req.params.id]
    );

    if (resultado.rowCount === 0) {
      return res.status(404).json("Usuário não encontrado");
    }

    res.status(200).json({
      mensagem: "Usuário atualizado!",
      usuario: usuarioPublico(resultado.rows[0]),
    });
  } catch (erro) {
    if (erro.code === "23505") return res.status(409).json("Esse e-mail já está em uso");
    erroServidor(res, erro, "ERRO PUT USUARIO");
  }
});

app.delete("/usuarios/:id", checar_token, somenteUsuario, async (req, res) => {
  const client = await pool.connect();
  try {
    if (!verificarAcesso(req, req.params.id)) {
      return res.status(403).json("Acesso negado");
    }

    await client.query("BEGIN");
    // alugar.usuario_id não tem ON DELETE CASCADE, então apaga os aluguéis antes.
    await client.query("DELETE FROM alugar WHERE usuario_id = $1", [req.params.id]);
    const resultado = await client.query(
      "DELETE FROM usuarios WHERE id = $1 RETURNING id",
      [req.params.id]
    );

    if (resultado.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json("Usuário não encontrado");
    }

    await client.query("COMMIT");
    res.status(200).json("Usuário deletado");
  } catch (erro) {
    await client.query("ROLLBACK").catch(() => {});
    erroServidor(res, erro, "ERRO DELETE USUARIO");
  } finally {
    client.release();
  }
});

/* Adicionar créditos (simulação: não há gateway de pagamento) */
app.post("/usuarios/:id/creditos", checar_token, somenteUsuario, async (req, res) => {
  try {
    if (!verificarAcesso(req, req.params.id)) {
      return res.status(403).json("Acesso negado");
    }

    const valor = Math.round(Number(req.body?.valor) * 100) / 100;

    if (!Number.isFinite(valor) || valor <= 0 || valor > CREDITO_MAXIMO) {
      return res
        .status(422)
        .json(`Informe um valor entre R$ 0,01 e R$ ${CREDITO_MAXIMO.toFixed(2)}.`);
    }

    const resultado = await pool.query(
      `UPDATE usuarios SET credito = credito + $1
       WHERE id = $2 RETURNING credito::float8 AS credito`,
      [valor, req.params.id]
    );

    if (resultado.rowCount === 0) {
      return res.status(404).json("Usuário não encontrado");
    }

    res.json({ novo_credito: resultado.rows[0].credito, credito: resultado.rows[0].credito });
  } catch (erro) {
    erroServidor(res, erro, "ERRO CREDITOS");
  }
});

/* ===================== LIVROS ===================== */

app.get("/livros", async (req, res) => {
  try {
    const resultado = await pool.query(`${SELECT_LIVRO} ORDER BY id`);
    res.status(200).json(resultado.rows.map((l) => livroPublico(req, l)));
  } catch (erro) {
    erroServidor(res, erro, "ERRO GET LIVROS");
  }
});

app.get("/livros/:id/capa", async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT capa_dados, capa_tipo FROM livros WHERE id = $1",
      [req.params.id]
    );
    const livro = r.rows[0];
    if (!livro?.capa_dados) return res.status(404).json("Capa não encontrada");

    res.set("Content-Type", livro.capa_tipo || "image/jpeg");
    res.set("Cache-Control", "public, max-age=86400");
    res.send(livro.capa_dados);
  } catch (erro) {
    erroServidor(res, erro, "ERRO CAPA");
  }
});

/* PDF enviado pelo app: exige token (?token= ou header) e aluguel ativo (ou admin) */
app.get("/livros/:id/pdf", async (req, res) => {
  try {
    const token = req.query.token || lerBearer(req);
    if (!token) return res.status(401).json("Token não enviado");

    let decoded;
    try {
      decoded = jwt.verify(token, CHAVE_TOKEN);
    } catch {
      return res.status(401).json("Token inválido ou expirado");
    }

    if (decoded.tipo !== "admin") {
      const ativo = await pool.query(
        `SELECT 1 FROM alugar
         WHERE usuario_id = $1 AND livro_id = $2
           AND NOT reembolsado AND data_fim >= CURRENT_DATE`,
        [decoded.id, req.params.id]
      );
      if (ativo.rows.length === 0) {
        return res.status(403).json("Você não possui um aluguel ativo deste livro");
      }
    }

    const r = await pool.query("SELECT pdf_dados FROM livros WHERE id = $1", [req.params.id]);
    if (!r.rows[0]?.pdf_dados) return res.status(404).json("PDF não encontrado");

    res.set("Content-Type", "application/pdf");
    res.set("Content-Disposition", "inline");
    res.set("Cache-Control", "private, no-store");
    res.send(r.rows[0].pdf_dados);
  } catch (erro) {
    erroServidor(res, erro, "ERRO PDF");
  }
});

function lerValor(bruto) {
  const n = Number(String(bruto ?? "").trim().replace(",", "."));
  return Number.isFinite(n) && n >= 0 ? Math.round(n * 100) / 100 : null;
}

app.post("/livros", checar_token, somenteAdmin, uploadLivro, async (req, res) => {
  try {
    const nome = req.body?.nome?.trim();
    const genero = req.body?.genero?.trim();
    const valor = lerValor(req.body?.valor);

    if (!nome || !genero || valor === null) {
      return res.status(422).json("Campos obrigatórios faltando");
    }

    const existe = await pool.query("SELECT 1 FROM livros WHERE LOWER(nome) = LOWER($1)", [nome]);
    if (existe.rows.length > 0) {
      return res.status(409).json("Esse livro ja foi cadastrado!");
    }

    const capa = req.files?.capa?.[0];
    const pdf = req.files?.pdf?.[0];

    // capa_url e pdf_url são NOT NULL no banco: '' indica "usar o arquivo guardado no banco".
    const resultado = await pool.query(
      `INSERT INTO livros (nome, genero, valor, capa_url, pdf_url, capa_dados, capa_tipo, pdf_dados)
       VALUES ($1, $2, $3, '', '', $4, $5, $6)
       RETURNING id`,
      [nome, genero, valor, capa?.buffer ?? null, capa?.mimetype ?? null, pdf?.buffer ?? null]
    );

    const livro = await pool.query(`${SELECT_LIVRO} WHERE id = $1`, [resultado.rows[0].id]);

    res.status(201).json({ banco: livroPublico(req, livro.rows[0]), msg: "livro inserido com sucesso" });
  } catch (erro) {
    erroServidor(res, erro, "ERRO POST LIVRO");
  }
});

app.put("/livros/:id", checar_token, somenteAdmin, uploadLivro, async (req, res) => {
  try {
    const nome = req.body?.nome?.trim();
    const genero = req.body?.genero?.trim();
    const valor = lerValor(req.body?.valor);

    if (!nome || !genero || valor === null) {
      return res.status(422).json("Campos obrigatórios faltando");
    }

    const duplicado = await pool.query(
      "SELECT 1 FROM livros WHERE LOWER(nome) = LOWER($1) AND id <> $2",
      [nome, req.params.id]
    );
    if (duplicado.rows.length > 0) {
      return res.status(409).json("Já existe outro livro com esse nome");
    }

    const capa = req.files?.capa?.[0];
    const pdf = req.files?.pdf?.[0];

    const resultado = await pool.query(
      `UPDATE livros
       SET nome = $1, genero = $2, valor = $3,
           capa_url   = CASE WHEN $4::bytea IS NOT NULL THEN '' ELSE capa_url END,
           capa_dados = COALESCE($4::bytea, capa_dados),
           capa_tipo  = COALESCE($5, capa_tipo),
           pdf_url    = CASE WHEN $6::bytea IS NOT NULL THEN '' ELSE pdf_url END,
           pdf_dados  = COALESCE($6::bytea, pdf_dados),
           atualizado_em = now()
       WHERE id = $7
       RETURNING id`,
      [nome, genero, valor, capa?.buffer ?? null, capa?.mimetype ?? null, pdf?.buffer ?? null, req.params.id]
    );

    if (resultado.rowCount === 0) {
      return res.status(404).json("Livro não encontrado");
    }

    const livro = await pool.query(`${SELECT_LIVRO} WHERE id = $1`, [req.params.id]);
    res.json(livroPublico(req, livro.rows[0]));
  } catch (erro) {
    erroServidor(res, erro, "ERRO PUT LIVRO");
  }
});

app.delete("/livros/:id", checar_token, somenteAdmin, async (req, res) => {
  try {
    const resultado = await pool.query("DELETE FROM livros WHERE id = $1 RETURNING id", [
      req.params.id,
    ]);

    if (resultado.rowCount === 0) {
      return res.status(404).json("Livro não encontrado");
    }

    res.json({ id: resultado.rows[0].id, msg: "Livro removido" });
  } catch (erro) {
    if (erro.code === "23503") {
      return res.status(409).json("Este livro possui aluguéis e não pode ser removido.");
    }
    erroServidor(res, erro, "ERRO DELETE LIVRO");
  }
});

/* ===================== ALUGUÉIS (tabela alugar) ===================== */

/* Lista os aluguéis do usuário logado (sem os reembolsados) */
app.get("/alugueis", checar_token, somenteUsuario, async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT a.id, a.livro_id, l.nome, l.capa_url, l.pdf_url,
              (l.capa_dados IS NOT NULL) AS tem_capa,
              (l.pdf_dados  IS NOT NULL) AS tem_pdf_interno,
              EXTRACT(EPOCH FROM l.atualizado_em)::bigint AS versao,
              a.meses, a.valor_total::float8 AS valor_total,
              to_char(a.data_inicio, 'YYYY-MM-DD"T00:00:00Z"') AS data_inicio,
              to_char(a.data_fim,    'YYYY-MM-DD"T23:59:59Z"') AS data_fim,
              a.criado_em,
              GREATEST(0, CEIL($2::float8 - EXTRACT(EPOCH FROM (now()::timestamp - a.criado_em))))::int
                AS segundos_restantes
       FROM alugar a
       JOIN livros l ON l.id = a.livro_id
       WHERE a.usuario_id = $1 AND NOT a.reembolsado
       ORDER BY a.criado_em DESC`,
      [req.usuario.id, REEMBOLSO_SEGUNDOS]
    );

    const tokenPdf = jwt.sign(
      { id: req.usuario.id, tipo: req.usuario.tipo, pdf: true },
      CHAVE_TOKEN,
      { expiresIn: "2h" }
    );

    res.json(
      resultado.rows.map((a) => ({
        id: a.id,
        livro_id: a.livro_id,
        nome: a.nome,
        capa_url: urlCapa(req, a.livro_id, a.tem_capa, a.capa_url, a.versao) || "",
        pdf_url: a.tem_pdf_interno
          ? `${baseUrl(req)}/livros/${a.livro_id}/pdf?token=${tokenPdf}`
          : a.pdf_url || "",
        meses: a.meses,
        valor_total: String(a.valor_total),
        data_inicio: a.data_inicio,
        data_fim: a.data_fim,
        criado_em: a.criado_em,
        segundos_restantes: a.segundos_restantes,
      }))
    );
  } catch (erro) {
    erroServidor(res, erro, "ERRO GET ALUGUEIS");
  }
});

/* Alugar um livro: body { livro_id, meses } */
app.post("/alugueis", checar_token, somenteUsuario, async (req, res) => {
  const livroId = Number(req.body?.livro_id ?? req.body?.livroId);
  const meses = Number(req.body?.meses ?? 1);

  if (!Number.isInteger(livroId) || !Number.isInteger(meses) || meses < 1 || meses > 24) {
    return res.status(422).json("Informe um livro e um período de 1 a 24 meses");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const livro = await client.query("SELECT id, valor FROM livros WHERE id = $1", [livroId]);
    if (livro.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json("Livro não encontrado");
    }

    // Trava a linha do usuário: serializa compras simultâneas do mesmo usuário.
    const usuario = await client.query(
      "SELECT credito FROM usuarios WHERE id = $1 FOR UPDATE",
      [req.usuario.id]
    );
    if (usuario.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json("Usuário não encontrado");
    }

    const ativo = await client.query(
      `SELECT 1 FROM alugar
       WHERE usuario_id = $1 AND livro_id = $2
         AND NOT reembolsado AND data_fim >= CURRENT_DATE`,
      [req.usuario.id, livroId]
    );
    if (ativo.rows.length > 0) {
      await client.query("ROLLBACK");
      return res.status(409).json("Você já possui um aluguel ativo deste livro");
    }

    const total = Math.round(Number(livro.rows[0].valor) * meses * 100) / 100;

    if (Number(usuario.rows[0].credito) < total) {
      await client.query("ROLLBACK");
      return res.status(402).json("Saldo insuficiente. Adicione créditos no seu perfil.");
    }

    const novo = await client.query(
      "UPDATE usuarios SET credito = credito - $1 WHERE id = $2 RETURNING credito::float8 AS credito",
      [total, req.usuario.id]
    );

    const aluguel = await client.query(
      `INSERT INTO alugar (usuario_id, livro_id, meses, valor_total, data_inicio, data_fim)
       VALUES ($1, $2, $3::integer, $4, CURRENT_DATE,
               (CURRENT_DATE + ($3::integer * INTERVAL '1 month'))::date)
       RETURNING id, livro_id, meses, valor_total::float8 AS valor_total, data_inicio, data_fim`,
      [req.usuario.id, livroId, meses, total]
    );

    await client.query("COMMIT");

    res.status(201).json({
      mensagem: "Livro alugado com sucesso",
      aluguel: aluguel.rows[0],
      novo_credito: novo.rows[0].credito,
    });
  } catch (erro) {
    await client.query("ROLLBACK").catch(() => {});
    erroServidor(res, erro, "ERRO POST ALUGUEL");
  } finally {
    client.release();
  }
});

/* Reembolso: marca reembolsado = true e devolve o valor (dentro da janela) */
app.delete("/alugueis/:id", checar_token, somenteUsuario, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const r = await client.query(
      `SELECT id, valor_total,
              EXTRACT(EPOCH FROM (now()::timestamp - criado_em)) AS decorrido
       FROM alugar
       WHERE id = $1 AND usuario_id = $2 AND NOT reembolsado
       FOR UPDATE`,
      [req.params.id, req.usuario.id]
    );

    if (r.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json("Aluguel não encontrado ou já reembolsado");
    }

    if (Number(r.rows[0].decorrido) > REEMBOLSO_SEGUNDOS) {
      await client.query("ROLLBACK");
      return res.status(403).json("O prazo de reembolso deste aluguel já encerrou.");
    }

    await client.query("UPDATE alugar SET reembolsado = TRUE WHERE id = $1", [req.params.id]);

    const novo = await client.query(
      "UPDATE usuarios SET credito = credito + $1 WHERE id = $2 RETURNING credito::float8 AS credito",
      [r.rows[0].valor_total, req.usuario.id]
    );

    await client.query("COMMIT");

    res.json({ mensagem: "Reembolso realizado", novo_credito: novo.rows[0].credito });
  } catch (erro) {
    await client.query("ROLLBACK").catch(() => {});
    erroServidor(res, erro, "ERRO REEMBOLSO");
  } finally {
    client.release();
  }
});

/* ===================== ERROS GERAIS ===================== */

app.use((erro, req, res, next) => {
  if (erro instanceof multer.MulterError) {
    const msg = erro.code === "LIMIT_FILE_SIZE" ? "Arquivo maior que 30 MB" : erro.message;
    return res.status(413).json(msg);
  }
  console.log("ERRO NÃO TRATADO:", erro.message);
  res.status(500).json("Erro no servidor");
});

app.listen(porta, () => {
  console.log(`rodando na porta ${porta}`);
});