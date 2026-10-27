
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pool from "./db.js";

dotenv.config();

const app = express();
const porta = process.env.PORT || 8080;
const CHAVE_TOKEN = process.env.CHAVE_TOKEN;

// ==========================================
// CONFIGURAÇÃO DO SERVIDOR
// ==========================================

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Cache-Control",
      "Pragma",
    ],
    optionsSuccessStatus: 204,
  })
);

app.use(express.json());

if (!CHAVE_TOKEN) {
  console.error("ERRO: CHAVE_TOKEN não foi definida no ambiente.");
}

// ==========================================
// TRATAMENTO DE ERROS DO POSTGRESQL
// ==========================================

function registrarErro(contexto, erro) {
  console.error(`❌ ${contexto}:`, {
    mensagem: erro?.message,
    codigo: erro?.code,
    detalhe: erro?.detail,
    tabela: erro?.table,
    coluna: erro?.column,
    constraint: erro?.constraint,
    stack: erro?.stack,
  });
}

// ==========================================
// AUTENTICAÇÃO
// ==========================================

function checar_token(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization?.startsWith("Bearer ")) {
    return res.status(401).json({
      erro: "Token de autenticação não informado.",
    });
  }

  const token = authorization.substring(7);

  if (!token || !CHAVE_TOKEN) {
    return res.status(401).json({
      erro: "Token inválido ou autenticação indisponível.",
    });
  }

  try {
    req.usuario = jwt.verify(token, CHAVE_TOKEN);
    return next();
  } catch {
    return res.status(401).json({
      erro: "Token inválido ou expirado. Faça login novamente.",
    });
  }
}

function verificarAcesso(req, id) {
  return Number(req.usuario?.id) === Number(id);
}

// ==========================================
// ROTA INICIAL
// ==========================================

app.get("/", (req, res) => {
  res.status(200).json({
    mensagem: "API do Paginarium funcionando!",
  });
});

// ==========================================
// CADASTRO
// ==========================================

app.post("/cadastro", async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
      return res.status(400).json({
        erro: "Nome, e-mail e senha são obrigatórios.",
      });
    }

    const nomeNormalizado = String(nome).trim();
    const emailNormalizado = String(email).trim().toLowerCase();
    const senhaTexto = String(senha);

    if (!nomeNormalizado || !emailNormalizado.includes("@")) {
      return res.status(400).json({
        erro: "Informe um nome e um e-mail válidos.",
      });
    }

    if (senhaTexto.length < 6) {
      return res.status(400).json({
        erro: "A senha deve ter pelo menos 6 caracteres.",
      });
    }

    const existente = await pool.query(
      `SELECT id FROM usuarios WHERE LOWER(email) = $1`,
      [emailNormalizado]
    );

    if (existente.rows.length > 0) {
      return res.status(409).json({
        erro: "Este e-mail já está cadastrado.",
      });
    }

    const senhaHash = await bcrypt.hash(senhaTexto, 10);

    const resultado = await pool.query(
      `INSERT INTO usuarios (nome, email, senha)
       VALUES ($1, $2, $3)
       RETURNING id, nome, email`,
      [nomeNormalizado, emailNormalizado, senhaHash]
    );

    return res.status(201).json({
      mensagem: "Usuário cadastrado com sucesso.",
      usuario: resultado.rows[0],
    });
  } catch (erro) {
    registrarErro("Cadastro", erro);

    if (erro?.code === "23505") {
      return res.status(409).json({
        erro: "Este e-mail já está cadastrado.",
      });
    }

    return res.status(500).json({
      erro: "Não foi possível cadastrar o usuário.",
    });
  }
});

// ==========================================
// LOGIN
// ==========================================

app.post("/login", async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res.status(400).json({
        erro: "E-mail e senha são obrigatórios.",
      });
    }

    const emailNormalizado = String(email).trim().toLowerCase();

    const resultado = await pool.query(
      `SELECT id, nome, email, senha
       FROM usuarios
       WHERE LOWER(email) = $1`,
      [emailNormalizado]
    );

    if (resultado.rows.length === 0) {
      return res.status(401).json({
        erro: "E-mail ou senha incorretos.",
      });
    }

    const usuario = resultado.rows[0];

    const senhaCorreta = await bcrypt.compare(
      String(senha),
      usuario.senha
    );

    if (!senhaCorreta) {
      return res.status(401).json({
        erro: "E-mail ou senha incorretos.",
      });
    }

    if (!CHAVE_TOKEN) {
      return res.status(500).json({
        erro: "Autenticação não configurada no servidor.",
      });
    }

    const token = jwt.sign(
      { id: usuario.id, email: usuario.email },
      CHAVE_TOKEN,
      { expiresIn: "2h" }
    );

    return res.status(200).json({
      mensagem: "Login realizado com sucesso.",
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
      },
    });
  } catch (erro) {
    registrarErro("Login", erro);

    return res.status(500).json({
      erro: "Não foi possível realizar o login.",
    });
  }
});

// ==========================================
// CONSULTAR USUÁRIO
// ==========================================

app.get("/usuarios/:id", checar_token, async (req, res) => {
  try {
    const { id } = req.params;

    if (!verificarAcesso(req, id)) {
      return res.status(403).json({
        erro: "Você não tem permissão para acessar este usuário.",
      });
    }

    const resultado = await pool.query(
      `SELECT id, nome, email
       FROM usuarios
       WHERE id = $1`,
      [id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Usuário não encontrado.",
      });
    }

    return res.status(200).json(resultado.rows[0]);
  } catch (erro) {
    registrarErro("Consultar usuário", erro);

    return res.status(500).json({
      erro: "Não foi possível consultar o usuário.",
    });
  }
});

// ==========================================
// ATUALIZAR USUÁRIO
// ==========================================

app.put("/usuarios/:id", checar_token, async (req, res) => {
  try {
    const { id } = req.params;
    const { nome, email } = req.body;

    if (!verificarAcesso(req, id)) {
      return res.status(403).json({
        erro: "Você não tem permissão para alterar este usuário.",
      });
    }

    if (!nome || !email) {
      return res.status(400).json({
        erro: "Nome e e-mail são obrigatórios.",
      });
    }

    const nomeNormalizado = String(nome).trim();
    const emailNormalizado = String(email).trim().toLowerCase();

    if (!nomeNormalizado || !emailNormalizado.includes("@")) {
      return res.status(400).json({
        erro: "Informe um nome e um e-mail válidos.",
      });
    }

    const resultado = await pool.query(
      `UPDATE usuarios
       SET nome = $1, email = $2
       WHERE id = $3
       RETURNING id, nome, email`,
      [nomeNormalizado, emailNormalizado, id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Usuário não encontrado.",
      });
    }

    return res.status(200).json({
      mensagem: "Usuário atualizado com sucesso.",
      usuario: resultado.rows[0],
    });
  } catch (erro) {
    registrarErro("Atualizar usuário", erro);

    if (erro?.code === "23505") {
      return res.status(409).json({
        erro: "Este e-mail já está em uso.",
      });
    }

    return res.status(500).json({
      erro: "Não foi possível atualizar o usuário.",
    });
  }
});

// ==========================================
// EXCLUIR USUÁRIO
// ==========================================

app.delete("/usuarios/:id", checar_token, async (req, res) => {
  try {
    const { id } = req.params;

    if (!verificarAcesso(req, id)) {
      return res.status(403).json({
        erro: "Você não tem permissão para excluir este usuário.",
      });
    }

    const resultado = await pool.query(
      `DELETE FROM usuarios
       WHERE id = $1
       RETURNING id`,
      [id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Usuário não encontrado.",
      });
    }

    return res.status(200).json({
      mensagem: "Usuário excluído com sucesso.",
    });
  } catch (erro) {
    registrarErro("Excluir usuário", erro);

    if (erro?.code === "23503") {
      return res.status(409).json({
        erro: "Este usuário possui registros associados e não pode ser excluído.",
      });
    }

    return res.status(500).json({
      erro: "Não foi possível excluir o usuário.",
    });
  }
});

// ==========================================
// ADMINISTRADOR
// ==========================================

// Cadastro público de administradores desativado.
app.post("/admin/login", (req, res) => {
  return res.status(403).json({
    erro: "Cadastro público de administrador desativado.",
  });
});

// ==========================================
// LISTAR LIVROS
// ==========================================

app.get("/livros", async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT * FROM livros ORDER BY id ASC`
    );

    return res.status(200).json(resultado.rows);
  } catch (erro) {
    registrarErro("Listar livros", erro);

    return res.status(500).json({
      erro: "Não foi possível listar os livros.",
    });
  }
});

// ==========================================
// CONSULTAR LIVRO
// ==========================================

app.get("/livros/:id", async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT * FROM livros WHERE id = $1`,
      [req.params.id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Livro não encontrado.",
      });
    }

    return res.status(200).json(resultado.rows[0]);
  } catch (erro) {
    registrarErro("Consultar livro", erro);

    return res.status(500).json({
      erro: "Não foi possível consultar o livro.",
    });
  }
});

// ==========================================
// CADASTRAR LIVRO
// ==========================================

app.post("/livros", async (req, res) => {
  try {
    const { nome, genero } = req.body;

    if (!nome || !genero) {
      return res.status(400).json({
        erro: "Nome e gênero são obrigatórios.",
      });
    }

    const resultado = await pool.query(
      `INSERT INTO livros (nome, genero)
       VALUES ($1, $2)
       RETURNING *`,
      [String(nome).trim(), String(genero).trim()]
    );

    return res.status(201).json({
      mensagem: "Livro cadastrado com sucesso.",
      livro: resultado.rows[0],
    });
  } catch (erro) {
    registrarErro("Cadastrar livro", erro);

    return res.status(500).json({
      erro: "Não foi possível cadastrar o livro.",
    });
  }
});

// ==========================================
// ATUALIZAR LIVRO
// ==========================================

app.put("/livros/:id", async (req, res) => {
  try {
    const { nome, genero } = req.body;

    if (!nome || !genero) {
      return res.status(400).json({
        erro: "Nome e gênero são obrigatórios.",
      });
    }

    const resultado = await pool.query(
      `UPDATE livros
       SET nome = $1, genero = $2
       WHERE id = $3
       RETURNING *`,
      [String(nome).trim(), String(genero).trim(), req.params.id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Livro não encontrado.",
      });
    }

    return res.status(200).json({
      mensagem: "Livro atualizado com sucesso.",
      livro: resultado.rows[0],
    });
  } catch (erro) {
    registrarErro("Atualizar livro", erro);

    return res.status(500).json({
      erro: "Não foi possível atualizar o livro.",
    });
  }
});

// ==========================================
// EXCLUIR LIVRO
// ==========================================

app.delete("/livros/:id", async (req, res) => {
  try {
    const resultado = await pool.query(
      `DELETE FROM livros WHERE id = $1 RETURNING id`,
      [req.params.id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Livro não encontrado.",
      });
    }

    return res.status(200).json({
      mensagem: "Livro excluído com sucesso.",
    });
  } catch (erro) {
    registrarErro("Excluir livro", erro);

    if (erro?.code === "23503") {
      return res.status(409).json({
        erro: "Este livro possui registros associados e não pode ser excluído.",
      });
    }

    return res.status(500).json({
      erro: "Não foi possível excluir o livro.",
    });
  }
});

// ==========================================
// LISTAR ALUGUÉIS DO USUÁRIO
// ==========================================

app.get("/alugueis", checar_token, async (req, res) => {
  try {
    const usuarioId = req.usuario.id;

    console.log("📚 Consultando aluguéis do usuário:", usuarioId);

    const resultado = await pool.query(
      `SELECT *
       FROM alugueis
       WHERE usuario_id = $1
       ORDER BY id DESC`,
      [usuarioId]
    );

    console.log(
      `✅ Aluguéis encontrados: ${resultado.rows.length}`
    );

    return res.status(200).json(resultado.rows);
  } catch (erro) {
    registrarErro("Listar aluguéis", erro);

    // Código PostgreSQL 42P01: tabela inexistente.
    if (erro?.code === "42P01") {
      return res.status(500).json({
        erro: "A tabela alugueis não existe no banco de dados.",
        codigo: erro.code,
      });
    }

    // Código PostgreSQL 42703: coluna inexistente.
    if (erro?.code === "42703") {
      return res.status(500).json({
        erro: "Uma coluna utilizada na consulta não existe na tabela alugueis.",
        codigo: erro.code,
        coluna: erro.column,
      });
    }

    return res.status(500).json({
      erro: "Não foi possível buscar os aluguéis.",
      codigo: erro?.code || "ERRO_INTERNO",
    });
  }
});

// ==========================================
// CRIAR ALUGUEL
// ==========================================

app.post("/alugueis", checar_token, async (req, res) => {
  try {
    const usuarioId = req.usuario.id;
    const { livro_id, meses } = req.body;

    const livroId = Number(livro_id);
    const quantidadeMeses = Number(meses);

    if (
      !Number.isInteger(livroId) ||
      livroId <= 0 ||
      !Number.isInteger(quantidadeMeses) ||
      quantidadeMeses <= 0
    ) {
      return res.status(400).json({
        erro: "Informe um livro e uma quantidade de meses válidos.",
      });
    }

    const livro = await pool.query(
      `SELECT id FROM livros WHERE id = $1`,
      [livroId]
    );

    if (livro.rows.length === 0) {
      return res.status(404).json({
        erro: "Livro não encontrado.",
      });
    }

    const resultado = await pool.query(
      `INSERT INTO alugueis
         (usuario_id, livro_id, meses, data_inicio)
       VALUES ($1, $2, $3, CURRENT_DATE)
       RETURNING *`,
      [usuarioId, livroId, quantidadeMeses]
    );

    return res.status(201).json({
      mensagem: "Aluguel criado com sucesso.",
      aluguel: resultado.rows[0],
    });
  } catch (erro) {
    registrarErro("Criar aluguel", erro);

    if (erro?.code === "42P01" || erro?.code === "42703") {
      return res.status(500).json({
        erro: "A estrutura da tabela alugueis não corresponde à consulta da API.",
        codigo: erro.code,
        coluna: erro.column,
      });
    }

    if (erro?.code === "23503") {
      return res.status(400).json({
        erro: "O usuário ou o livro informado não existe no banco de dados.",
      });
    }

    return res.status(500).json({
      erro: "Não foi possível criar o aluguel.",
      codigo: erro?.code || "ERRO_INTERNO",
    });
  }
});

// ==========================================
// ROTAS INEXISTENTES
// ==========================================

app.use((req, res) => {
  return res.status(404).json({
    erro: "Rota não encontrada.",
    rota: req.originalUrl,
  });
});

// ==========================================
// ERROS GLOBAIS
// ==========================================

app.use((erro, req, res, next) => {
  registrarErro("Erro global", erro);

  if (res.headersSent) {
    return next(erro);
  }

  return res.status(500).json({
    erro: "Ocorreu um erro interno no servidor.",
  });
});

// ==========================================
// INICIAR SERVIDOR
// ==========================================

app.listen(porta, () => {
  console.log(`🚀 PaginariumAPI executando na porta ${porta}`);
});
