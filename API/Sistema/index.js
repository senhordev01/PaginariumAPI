
import express from "express";
import "dotenv/config";
import cors from "cors";
import bcrypt, { genSalt } from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import pool from "./db.js";
import supabase from "./supabase.js";

const app = express();
const porta = process.env.PORT || 8080;
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors());
app.use(express.json());

const CREDITO_MAXIMO_POR_RECARGA = 1000;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ============================================================
// BANCO DE DADOS
// ============================================================

async function inicializarBanco() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS Usuarios (
      id SERIAL PRIMARY KEY,
      nome VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      senha VARCHAR(255) NOT NULL,
      credito NUMERIC(10,2) DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS Administradores (
      id SERIAL PRIMARY KEY,
      nome VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      senha VARCHAR(255) NOT NULL
    );

    CREATE TABLE IF NOT EXISTS livros (
      id SERIAL PRIMARY KEY,
      nome VARCHAR(255) NOT NULL,
      genero VARCHAR(100),
      capa_url TEXT,
      pdf_url TEXT,
      valor NUMERIC(10,2) NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alugueis (
      id SERIAL PRIMARY KEY,
      usuario_id INT REFERENCES Usuarios(id) ON DELETE CASCADE,
      livro_id INT REFERENCES livros(id) ON DELETE CASCADE,
      meses INT NOT NULL,
      valor_total NUMERIC(10,2) NOT NULL,
      data_inicio DATE DEFAULT CURRENT_DATE,
      data_fim DATE,
      criado_em TIMESTAMP DEFAULT NOW()
    );
  `);

  console.log("Tabelas verificadas/criadas com sucesso.");
}

// ============================================================
// AUTENTICAÇÃO E AUTORIZAÇÃO
// ============================================================

function checar_token(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json("Token não enviado");
    }

    const partes = authHeader.split(" ");

    if (partes.length !== 2 || partes[0] !== "Bearer") {
      return res.status(401).json("Formato do token inválido");
    }

    const token = partes[1];

    const decoded = jwt.verify(token, process.env.CHAVE_TOKEN);

    req.usuario = decoded;
    next();
  } catch (erro) {
    return res.status(403).json("Token inválido ou expirado");
  }
}

function verificarAcesso(req, id) {
  return Number(req.usuario?.id) === Number(id);
}

function ehDonoDaConta(req, id) {
  return (
    req.usuario?.tipo === "normal" &&
    verificarAcesso(req, id)
  );
}

function gerarToken(usuario, tipo) {
  return jwt.sign(
    {
      id: usuario.id,
      email: usuario.email,
      tipo
    },
    process.env.CHAVE_TOKEN,
    { expiresIn: "2h" }
  );
}

function sanitizarNomeArquivo(nome) {
  return nome
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9.-]/g, "-");
}

// ============================================================
// ROTA INICIAL
// ============================================================

app.get("/", (req, res) => {
  res.status(200).json({
    mensagem: "API do Paginarium funcionando!",
    status: "online"
  });
});

// ============================================================
// CADASTRO DE USUÁRIOS
// ============================================================

app.post("/cadastro", async (req, res) => {
  try {
    const { nome, email, senha } = req.body || {};

    if (!nome || !email || !senha) {
      return res.status(422).json("Campos obrigatórios faltando");
    }

    const nomeNormalizado = String(nome).trim();
    const emailNormalizado = String(email).trim().toLowerCase();

    if (nomeNormalizado.length < 2) {
      return res.status(422).json("Nome inválido");
    }

    if (!EMAIL_REGEX.test(emailNormalizado)) {
      return res.status(422).json("E-mail inválido");
    }

    if (String(senha).length < 8) {
      return res.status(422).json("A senha deve ter pelo menos 8 caracteres");
    }

    const usuarioExiste = await pool.query(
      "SELECT 1 FROM Usuarios WHERE email = $1",
      [emailNormalizado]
    );

    if (usuarioExiste.rows.length > 0) {
      return res.status(409).json("Esse usuário já foi cadastrado");
    }

    const salt = await genSalt(12);
    const senhaHash = await bcrypt.hash(senha, salt);

    const resultado = await pool.query(
      `INSERT INTO Usuarios (nome, email, senha)
       VALUES ($1, $2, $3)
       RETURNING id, nome, email, credito`,
      [nomeNormalizado, emailNormalizado, senhaHash]
    );

    return res.status(201).json({
      banco: resultado.rows[0],
      msg: "Usuário cadastrado com sucesso"
    });
  } catch (erro) {
    console.error("ERRO CADASTRO:", erro.message);

    if (erro.code === "23505") {
      return res.status(409).json("Esse e-mail já está cadastrado");
    }

    return res.status(500).json("Erro no servidor");
  }
});

// ============================================================
// LOGIN DE USUÁRIOS E ADMINISTRADORES
// ============================================================

app.post("/login", async (req, res) => {
  try {
    const { email, senha } = req.body || {};

    if (!email || !senha) {
      return res.status(422).json("Email e senha obrigatórios");
    }

    const emailNormalizado = String(email).trim().toLowerCase();

    const usuarioRes = await pool.query(
      "SELECT * FROM Usuarios WHERE email = $1",
      [emailNormalizado]
    );

    let usuario = null;
    let tipo = null;

    if (usuarioRes.rows.length > 0) {
      usuario = usuarioRes.rows[0];
      tipo = "normal";
    } else {
      const adminRes = await pool.query(
        "SELECT * FROM Administradores WHERE email = $1",
        [emailNormalizado]
      );

      if (adminRes.rows.length > 0) {
        usuario = adminRes.rows[0];
        tipo = "admin";
      }
    }

    if (!usuario) {
      return res.status(404).json("Usuário não encontrado");
    }

    const senhaValida = await bcrypt.compare(
      senha,
      usuario.senha
    );

    if (!senhaValida) {
      return res.status(401).json("Senha inválida");
    }

    const token = gerarToken(usuario, tipo);

    const dadosUsuario = {
      id: usuario.id,
      nome: usuario.nome,
      email: usuario.email,
      tipo
    };

    if (tipo === "normal") {
      dadosUsuario.credito = Number(usuario.credito);
    }

    return res.status(200).json({
      mensagem: "Login realizado com sucesso",
      token,
      usuario: dadosUsuario
    });
  } catch (erro) {
    console.error("ERRO LOGIN:", erro.message);
    return res.status(500).json("Erro no servidor");
  }
});

// ============================================================
// CADASTRO DE ADMINISTRADORES
// ============================================================

// Atenção: em produção, restrinja esta rota a um processo
// administrativo autorizado ou a um mecanismo de convite.

app.post("/admin/cadastro", async (req, res) => {
  try {
    const { nome, email, senha } = req.body || {};

    if (!nome || !email || !senha) {
      return res.status(422).json("Campos obrigatórios faltando");
    }

    const nomeNormalizado = String(nome).trim();
    const emailNormalizado = String(email).trim().toLowerCase();

    if (!EMAIL_REGEX.test(emailNormalizado)) {
      return res.status(422).json("E-mail inválido");
    }

    if (String(senha).length < 8) {
      return res.status(422).json("A senha deve ter pelo menos 8 caracteres");
    }

    const admExiste = await pool.query(
      "SELECT 1 FROM Administradores WHERE email = $1",
      [emailNormalizado]
    );

    if (admExiste.rows.length > 0) {
      return res.status(409).json("Esse administrador já foi cadastrado");
    }

    const salt = await genSalt(12);
    const senhaHash = await bcrypt.hash(senha, salt);

    const resultado = await pool.query(
      `INSERT INTO Administradores (nome, email, senha)
       VALUES ($1, $2, $3)
       RETURNING id, nome, email`,
      [nomeNormalizado, emailNormalizado, senhaHash]
    );

    return res.status(201).json({
      banco: resultado.rows[0],
      msg: "Administrador cadastrado com sucesso"
    });
  } catch (erro) {
    console.error("ERRO ADMIN:", erro.message);

    if (erro.code === "23505") {
      return res.status(409).json("Esse e-mail já está cadastrado");
    }

    return res.status(500).json("Erro no servidor");
  }
});

// ============================================================
// CONSULTAR USUÁRIO
// ============================================================

app.get("/usuarios/:id", checar_token, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ehDonoDaConta(req, id)) {
      return res.status(403).json("Acesso negado");
    }

    const resultado = await pool.query(
      `SELECT id, nome, email, credito
       FROM Usuarios
       WHERE id = $1`,
      [id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json("Usuário não encontrado");
    }

    const usuario = resultado.rows[0];

    return res.status(200).json({
      ...usuario,
      credito: Number(usuario.credito)
    });
  } catch (erro) {
    console.error("ERRO GET USUARIO:", erro.message);
    return res.status(500).json("Erro no servidor");
  }
});

// ============================================================
// ATUALIZAR DADOS DO USUÁRIO
// ============================================================

app.put("/usuarios/:id", checar_token, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!ehDonoDaConta(req, id)) {
      return res.status(403).json("Acesso negado");
    }

    let { nome, email } = req.body || {};

    if (nome === undefined && email === undefined) {
      return res.status(422).json(
        "Envie o nome e/ou o e-mail para atualizar"
      );
    }

    if (nome !== undefined) {
      nome = String(nome).trim().replace(/\s+/g, " ");

      if (nome.length < 2 || nome.length > 100) {
        return res.status(422).json(
          "O nome deve ter entre 2 e 100 caracteres"
        );
      }
    }

    if (email !== undefined) {
      email = String(email).trim().toLowerCase();

      if (!EMAIL_REGEX.test(email) || email.length > 150) {
        return res.status(422).json("E-mail inválido");
      }

      const emailEmUso = await pool.query(
        `SELECT 1 FROM Usuarios
         WHERE email = $1 AND id <> $2`,
        [email, id]
      );

      if (emailEmUso.rows.length > 0) {
        return res.status(409).json("Esse e-mail já está em uso");
      }
    }

    const resultado = await pool.query(
      `UPDATE Usuarios
       SET nome = COALESCE($1, nome),
           email = COALESCE($2, email)
       WHERE id = $3
       RETURNING id, nome, email, credito`,
      [nome ?? null, email ?? null, id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json("Usuário não encontrado");
    }

    const atualizado = resultado.rows[0];

    return res.status(200).json({
      msg: "Usuário atualizado com sucesso",
      ...atualizado,
      credito: Number(atualizado.credito)
    });
  } catch (erro) {
    console.error("ERRO PUT USUARIO:", erro.message);

    if (erro.code === "23505") {
      return res.status(409).json("Esse e-mail já está em uso");
    }

    return res.status(500).json("Erro no servidor");
  }
});

// ============================================================
// ADICIONAR CRÉDITOS
// ============================================================

// Este endpoint adiciona saldo diretamente.
// Em produção, só deve creditar após confirmação do pagamento.

app.post("/usuarios/:id/creditos", checar_token, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!ehDonoDaConta(req, id)) {
      return res.status(403).json("Acesso negado");
    }

    const bruto = req.body?.valor;

    if (
      (typeof bruto !== "number" && typeof bruto !== "string") ||
      String(bruto).trim() === ""
    ) {
      return res.status(422).json("Valor inválido");
    }

    const valor = Math.round(Number(bruto) * 100) / 100;

    if (
      !Number.isFinite(valor) ||
      valor <= 0 ||
      valor > CREDITO_MAXIMO_POR_RECARGA
    ) {
      return res.status(422).json(
        `Informe um valor entre 0,01 e ${CREDITO_MAXIMO_POR_RECARGA}`
      );
    }

    const resultado = await pool.query(
      `UPDATE Usuarios
       SET credito = credito + $1
       WHERE id = $2
       RETURNING credito`,
      [valor, id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json("Usuário não encontrado");
    }

    return res.status(200).json({
      msg: "Créditos adicionados com sucesso",
      novo_credito: Number(resultado.rows[0].credito)
    });
  } catch (erro) {
    console.error("ERRO CREDITOS:", erro.message);
    return res.status(500).json("Erro no servidor");
  }
});

// ============================================================
// ROTA LEGADA PARA ATUALIZAÇÃO DE CRÉDITOS
// ============================================================

// Mantida para compatibilidade com clientes que ainda chamam
// PUT /usuarios/:id/creditos.
// Não aceita crédito enviado pelo cliente.

app.put("/usuarios/:id/creditos", checar_token, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!ehDonoDaConta(req, id)) {
      return res.status(403).json("Acesso negado");
    }

    const { nome, email } = req.body || {};

    if (nome === undefined && email === undefined) {
      return res.status(422).json(
        "Envie nome ou email. O saldo não pode ser alterado por esta rota."
      );
    }

    let nomeFinal = null;
    let emailFinal = null;

    if (nome !== undefined) {
      nomeFinal = String(nome).trim().replace(/\s+/g, " ");

      if (nomeFinal.length < 2 || nomeFinal.length > 100) {
        return res.status(422).json("Nome inválido");
      }
    }

    if (email !== undefined) {
      emailFinal = String(email).trim().toLowerCase();

      if (!EMAIL_REGEX.test(emailFinal) || emailFinal.length > 150) {
        return res.status(422).json("E-mail inválido");
      }

      const existente = await pool.query(
        `SELECT 1 FROM Usuarios
         WHERE email = $1 AND id <> $2`,
        [emailFinal, id]
      );

      if (existente.rows.length > 0) {
        return res.status(409).json("Esse e-mail já está em uso");
      }
    }

    const resultado = await pool.query(
      `UPDATE Usuarios
       SET nome = COALESCE($1, nome),
           email = COALESCE($2, email)
       WHERE id = $3
       RETURNING id, nome, email, credito`,
      [nomeFinal, emailFinal, id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json("Usuário não encontrado");
    }

    return res.status(200).json({
      msg: "Dados atualizados com sucesso",
      ...resultado.rows[0],
      credito: Number(resultado.rows[0].credito)
    });
  } catch (erro) {
    console.error("ERRO PUT CREDITOS:", erro.message);

    if (erro.code === "23505") {
      return res.status(409).json("Esse e-mail já está em uso");
    }

    return res.status(500).json("Erro no servidor");
  }
});

// ============================================================
// EXCLUIR USUÁRIO
// ============================================================

app.delete("/usuarios/:id", checar_token, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!ehDonoDaConta(req, id)) {
      return res.status(403).json("Acesso negado");
    }

    const resultado = await pool.query(
      "DELETE FROM Usuarios WHERE id = $1 RETURNING id",
      [id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json("Usuário não encontrado");
    }

    return res.status(200).json("Usuário deletado");
  } catch (erro) {
    console.error("ERRO DELETE USUARIO:", erro.message);
    return res.status(500).json("Erro no servidor");
  }
});

// ============================================================
// ALUGAR LIVRO
// ============================================================

app.post("/alugueis", checar_token, async (req, res) => {
  const client = await pool.connect();
  let transacaoIniciada = false;

  try {
    const usuarioId = Number(req.usuario.id);
    const { livro_id, meses } = req.body || {};
    const livroId = Number(livro_id);
    const quantidadeMeses = Number(meses);

    if (
      !Number.isInteger(livroId) ||
      livroId <= 0 ||
      !Number.isInteger(quantidadeMeses) ||
      quantidadeMeses <= 0 ||
      quantidadeMeses > 120
    ) {
      return res.status(422).json("Dados inválidos");
    }

    await client.query("BEGIN");
    transacaoIniciada = true;

    const aluguelAtivo = await client.query(
      `SELECT 1
       FROM alugueis
       WHERE usuario_id = $1
         AND livro_id = $2
         AND data_fim >= CURRENT_DATE
       LIMIT 1`,
      [usuarioId, livroId]
    );

    if (aluguelAtivo.rows.length > 0) {
      await client.query("ROLLBACK");
      transacaoIniciada = false;

      return res.status(409).json(
        "Você já possui este livro alugado e ainda no prazo."
      );
    }

    const livroRes = await client.query(
      "SELECT * FROM livros WHERE id = $1",
      [livroId]
    );

    if (livroRes.rows.length === 0) {
      await client.query("ROLLBACK");
      transacaoIniciada = false;

      return res.status(404).json("Livro não encontrado");
    }

    const livro = livroRes.rows[0];
    const valorTotal = Math.round(
      Number(livro.valor) * quantidadeMeses * 100
    ) / 100;

    const usuarioRes = await client.query(
      `SELECT credito
       FROM Usuarios
       WHERE id = $1
       FOR UPDATE`,
      [usuarioId]
    );

    if (usuarioRes.rows.length === 0) {
      await client.query("ROLLBACK");
      transacaoIniciada = false;

      return res.status(404).json("Usuário não encontrado");
    }

    const creditoAtual = Number(usuarioRes.rows[0].credito);

    if (creditoAtual < valorTotal) {
      await client.query("ROLLBACK");
      transacaoIniciada = false;

      return res.status(400).json("Saldo insuficiente");
    }

    const atualizacao = await client.query(
      `UPDATE Usuarios
       SET credito = credito - $1
       WHERE id = $2
       RETURNING credito`,
      [valorTotal, usuarioId]
    );

    const resultado = await client.query(
      `INSERT INTO alugueis
       (usuario_id, livro_id, meses, valor_total, data_inicio, data_fim)
       VALUES (
         $1,
         $2,
         $3,
         $4,
         CURRENT_DATE,
         (CURRENT_DATE + ($3 * INTERVAL '1 month'))::date
       )
       RETURNING *`,
      [usuarioId, livroId, quantidadeMeses, valorTotal]
    );

    await client.query("COMMIT");
    transacaoIniciada = false;

    return res.status(201).json({
      aluguel: resultado.rows[0],
      novo_credito: Number(atualizacao.rows[0].credito)
    });
  } catch (erro) {
    if (transacaoIniciada) {
      await client.query("ROLLBACK").catch(() => {});
    }

    console.error("ERRO POST ALUGUEIS:", erro.message);
    return res.status(500).json("Erro no servidor");
  } finally {
    client.release();
  }
});

// ============================================================
// CONSULTAR ALUGUÉIS DO USUÁRIO
// ============================================================

app.get("/alugueis", checar_token, async (req, res) => {
  try {
    const usuarioId = Number(req.usuario.id);

    const resultado = await pool.query(
      `SELECT
         a.id,
         a.usuario_id,
         a.livro_id,
         a.meses,
         a.valor_total,
         a.data_inicio,
         a.data_fim,
         a.criado_em,
         l.nome,
         l.capa_url,
         l.pdf_url,
         GREATEST(
           0,
           300 - EXTRACT(EPOCH FROM (NOW() - a.criado_em))
         )::int AS segundos_restantes
       FROM alugueis a
       JOIN livros l ON l.id = a.livro_id
       WHERE a.usuario_id = $1
       ORDER BY a.data_fim DESC`,
      [usuarioId]
    );

    return res.status(200).json(resultado.rows);
  } catch (erro) {
    console.error("ERRO GET ALUGUEIS:", erro.message);
    return res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ============================================================
// CADASTRAR LIVRO
// ============================================================

app.post("/livros", upload.any(), async (req, res) => {
  try {
    const { nome, genero, valor } = req.body || {};
    const capa = req.files?.find((f) => f.fieldname === "capa");
    const pdf = req.files?.find((f) => f.fieldname === "pdf");
    const valorNumber = Number(valor);

    if (!nome || !genero) {
      return res.status(422).json("Nome e gênero são obrigatórios");
    }

    if (
      valor === undefined ||
      String(valor).trim() === "" ||
      !Number.isFinite(valorNumber) ||
      valorNumber < 0
    ) {
      return res.status(422).json("Valor inválido");
    }

    if (!capa?.buffer || !pdf?.buffer) {
      return res.status(422).json("Capa e PDF são obrigatórios");
    }

    const livroExiste = await pool.query(
      "SELECT 1 FROM livros WHERE nome = $1",
      [String(nome).trim()]
    );

    if (livroExiste.rows.length > 0) {
      return res.status(409).json("Esse livro já foi cadastrado");
    }

    const nomeCapa = `${Date.now()}-${sanitizarNomeArquivo(capa.originalname)}`;
    const nomePdf = `${Date.now()}-${sanitizarNomeArquivo(pdf.originalname)}`;

    const { error: erroCapa } = await supabase.storage
      .from("capas")
      .upload(nomeCapa, capa.buffer, {
        contentType: capa.mimetype
      });

    if (erroCapa) {
      console.error("ERRO UPLOAD CAPA:", erroCapa.message);
      return res.status(500).json("Não foi possível enviar a capa");
    }

    const { error: erroPdf } = await supabase.storage
      .from("Livros")
      .upload(nomePdf, pdf.buffer, {
        contentType: pdf.mimetype
      });

    if (erroPdf) {
      console.error("ERRO UPLOAD PDF:", erroPdf.message);
      return res.status(500).json("Não foi possível enviar o PDF");
    }

    const capaUrl = supabase.storage
      .from("capas")
      .getPublicUrl(nomeCapa).data.publicUrl;

    const pdfUrl = supabase.storage
      .from("Livros")
      .getPublicUrl(nomePdf).data.publicUrl;

    const resultado = await pool.query(
      `INSERT INTO livros (nome, genero, capa_url, pdf_url, valor)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [String(nome).trim(), String(genero).trim(), capaUrl, pdfUrl, valorNumber]
    );

    return res.status(201).json({
      livro: resultado.rows[0],
      msg: "Livro inserido com sucesso"
    });
  } catch (erro) {
    console.error("ERRO POST LIVROS:", erro.message);
    return res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ============================================================
// LISTAR LIVROS
// ============================================================

app.get("/livros", async (req, res) => {
  try {
    const resultado = await pool.query(
      "SELECT * FROM livros ORDER BY id"
    );

    return res.status(200).json(resultado.rows);
  } catch (erro) {
    console.error("ERRO GET LIVROS:", erro.message);
    return res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ============================================================
// ATUALIZAR LIVRO
// ============================================================

app.put("/livros/:id", upload.any(), async (req, res) => {
  try {
    const { id } = req.params;
    const { nome, genero, valor } = req.body || {};
    const capa = req.files?.find((f) => f.fieldname === "capa");
    const pdf = req.files?.find((f) => f.fieldname === "pdf");

    const valorNumber = Number(valor);

    if (
      valor === undefined ||
      String(valor).trim() === "" ||
      !Number.isFinite(valorNumber) ||
      valorNumber < 0
    ) {
      return res.status(422).json("Valor inválido");
    }

    const livroAtual = await pool.query(
      "SELECT * FROM livros WHERE id = $1",
      [id]
    );

    if (livroAtual.rows.length === 0) {
      return res.status(404).json("Livro não encontrado");
    }

    let capaUrl = livroAtual.rows[0].capa_url;
    let pdfUrl = livroAtual.rows[0].pdf_url;

    if (capa) {
      const nomeCapa = `${Date.now()}-${sanitizarNomeArquivo(capa.originalname)}`;

      const { error } = await supabase.storage
        .from("capas")
        .upload(nomeCapa, capa.buffer, {
          contentType: capa.mimetype
        });

      if (error) {
        console.error("ERRO UPLOAD CAPA:", error.message);
        return res.status(500).json("Não foi possível atualizar a capa");
      }

      capaUrl = supabase.storage
        .from("capas")
        .getPublicUrl(nomeCapa).data.publicUrl;
    }

    if (pdf) {
      const nomePdf = `${Date.now()}-${sanitizarNomeArquivo(pdf.originalname)}`;

      const { error } = await supabase.storage
        .from("Livros")
        .upload(nomePdf, pdf.buffer, {
          contentType: pdf.mimetype
        });

      if (error) {
        console.error("ERRO UPLOAD PDF:", error.message);
        return res.status(500).json("Não foi possível atualizar o PDF");
      }

      pdfUrl = supabase.storage
        .from("Livros")
        .getPublicUrl(nomePdf).data.publicUrl;
    }

    const nomeFinal = nome === undefined
      ? livroAtual.rows[0].nome
      : String(nome).trim();

    const generoFinal = genero === undefined
      ? livroAtual.rows[0].genero
      : String(genero).trim();

    const resultado = await pool.query(
      `UPDATE livros
       SET nome = $1,
           genero = $2,
           capa_url = $3,
           pdf_url = $4,
           valor = $5
       WHERE id = $6
       RETURNING *`,
      [nomeFinal, generoFinal, capaUrl, pdfUrl, valorNumber, id]
    );

    return res.status(200).json(resultado.rows[0]);
  } catch (erro) {
    console.error("ERRO PUT LIVROS:", erro.message);
    return res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ============================================================
// EXCLUIR LIVRO
// ============================================================

app.delete("/livros/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const resultado = await pool.query(
      "DELETE FROM livros WHERE id = $1 RETURNING *",
      [id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json("Livro não encontrado");
    }

    return res.status(200).json(resultado.rows[0]);
  } catch (erro) {
    console.error("ERRO DELETE LIVROS:", erro.message);
    return res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ============================================================
// CANCELAR ALUGUEL E REEMBOLSAR
// ============================================================

app.delete("/alugueis/:id", checar_token, async (req, res) => {
  const client = await pool.connect();
  let transacaoIniciada = false;

  try {
    const usuarioId = Number(req.usuario.id);
    const aluguelId = Number(req.params.id);

    await client.query("BEGIN");
    transacaoIniciada = true;

    const aluguelRes = await client.query(
      `SELECT *,
              EXTRACT(EPOCH FROM (NOW() - criado_em)) / 60
              AS minutos_decorridos
       FROM alugueis
       WHERE id = $1 AND usuario_id = $2
       FOR UPDATE`,
      [aluguelId, usuarioId]
    );

    if (aluguelRes.rows.length === 0) {
      await client.query("ROLLBACK");
      transacaoIniciada = false;

      return res.status(404).json("Aluguel não encontrado");
    }

    const aluguel = aluguelRes.rows[0];
    const minutosDecorridos = Number(aluguel.minutos_decorridos);

    if (minutosDecorridos > 5) {
      await client.query("ROLLBACK");
      transacaoIniciada = false;

      return res.status(403).json(
        `Prazo encerrado. Já passaram ${minutosDecorridos.toFixed(2)} minutos.`
      );
    }

    await client.query(
      "DELETE FROM alugueis WHERE id = $1",
      [aluguelId]
    );

    const usuarioRes = await client.query(
      `UPDATE Usuarios
       SET credito = credito + $1
       WHERE id = $2
       RETURNING credito`,
      [Number(aluguel.valor_total), usuarioId]
    );

    if (usuarioRes.rows.length === 0) {
      throw new Error("Usuário não encontrado ao processar reembolso");
    }

    await client.query("COMMIT");
    transacaoIniciada = false;

    return res.status(200).json({
      msg: "Reembolso realizado com sucesso",
      novo_credito: Number(usuarioRes.rows[0].credito)
    });
  } catch (erro) {
    if (transacaoIniciada) {
      await client.query("ROLLBACK").catch(() => {});
    }

    console.error("ERRO DELETE ALUGUEIS:", erro.message);
    return res.status(500).json("Erro no servidor");
  } finally {
    client.release();
  }
});

// ============================================================
// INICIALIZAÇÃO DO SERVIDOR
// ============================================================

async function iniciarServidor() {
  try {
    if (!process.env.CHAVE_TOKEN) {
      throw new Error("A variável CHAVE_TOKEN não foi configurada");
    }

    await inicializarBanco();

    app.listen(porta, "0.0.0.0", () => {
      console.log(`API do Paginarium rodando na porta ${porta}`);
    });
  } catch (erro) {
    console.error("ERRO AO INICIAR A API:", erro.message);
    process.exit(1);
  }
}

iniciarServidor();
