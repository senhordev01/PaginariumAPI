
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pool from "./db.js";

dotenv.config();

const app = express();
const porta = process.env.PORT || 8080;

app.use(express.json());

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

const CHAVE_TOKEN = process.env.CHAVE_TOKEN;

if (!CHAVE_TOKEN) {
  console.error("ERRO: CHAVE_TOKEN não foi definida no ambiente.");
}

// ==========================================
// MIDDLEWARE DE AUTENTICAÇÃO
// ==========================================

function checar_token(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      erro: "Token de autenticação não informado.",
    });
  }

  const token = authorization.split(" ")[1];

  if (!token || !CHAVE_TOKEN) {
    return res.status(401).json({
      erro: "Token inválido ou autenticação indisponível.",
    });
  }

  try {
    const decoded = jwt.verify(token, CHAVE_TOKEN);

    req.usuario = decoded;

    next();
  } catch (erro) {
    return res.status(401).json({
      erro: "Token inválido ou expirado.",
    });
  }
}

// ==========================================
// VERIFICAÇÃO DE ACESSO
// ==========================================

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
// CADASTRO DE USUÁRIO
// ==========================================

app.post("/cadastro", async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
      return res.status(400).json({
        erro: "Nome, e-mail e senha são obrigatórios.",
      });
    }

    const emailNormalizado = String(email).trim().toLowerCase();

    if (String(senha).length < 6) {
      return res.status(400).json({
        erro: "A senha deve ter pelo menos 6 caracteres.",
      });
    }

    const existente = await pool.query(
      "SELECT id FROM usuarios WHERE LOWER(email) = $1",
      [emailNormalizado]
    );

    if (existente.rows.length > 0) {
      return res.status(409).json({
        erro: "Este e-mail já está cadastrado.",
      });
    }

    const senhaHash = await bcrypt.hash(String(senha), 10);

    const resultado = await pool.query(
      `INSERT INTO usuarios (nome, email, senha)
       VALUES ($1, $2, $3)
       RETURNING id, nome, email`,
      [String(nome).trim(), emailNormalizado, senhaHash]
    );

    return res.status(201).json({
      mensagem: "Usuário cadastrado com sucesso.",
      usuario: resultado.rows[0],
    });
  } catch (erro) {
    console.error("Erro no cadastro:", erro);

    if (erro.code === "23505") {
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

    const resultado = await pool.query(
      `SELECT id, nome, email, senha
       FROM usuarios
       WHERE LOWER(email) = $1`,
      [String(email).trim().toLowerCase()]
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
      {
        id: usuario.id,
        email: usuario.email,
      },
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
    console.error("Erro no login:", erro);

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

    // Mantém apenas colunas confirmadas pelo código original.
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
    console.error("Erro ao consultar usuário:", erro);

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

    const emailNormalizado = String(email).trim().toLowerCase();

    const resultado = await pool.query(
      `UPDATE usuarios
       SET nome = $1, email = $2
       WHERE id = $3
       RETURNING id, nome, email`,
      [String(nome).trim(), emailNormalizado, id]
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
    console.error("Erro ao atualizar usuário:", erro);

    if (erro.code === "23505") {
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
    console.error("Erro ao excluir usuário:", erro);

    return res.status(500).json({
      erro: "Não foi possível excluir o usuário.",
    });
  }
});

// ==========================================
// CADASTRO DE ADMINISTRADOR
// ==========================================

// ATENÇÃO: esta rota é pública no código original.
// Não a mantenha pública em produção.
// O cadastro administrativo deve ser restrito a um
// processo autorizado e protegido.

app.post("/admin/login", async (req, res) => {
  return res.status(403).json({
    erro:
      "Cadastro público de administrador desativado. " +
      "Configure um processo administrativo seguro.",
  });
});

// ==========================================
// LISTAR LIVROS
// ==========================================

app.get("/livros", async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT *
       FROM livros
       ORDER BY id ASC`
    );

    return res.status(200).json(resultado.rows);
  } catch (erro) {
    console.error("Erro ao listar livros:", erro);

    return res.status(500).json({
      erro: "Não foi possível listar os livros.",
    });
  }
});

// ==========================================
// CONSULTAR LIVRO POR ID
// ==========================================

app.get("/livros/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const resultado = await pool.query(
      "SELECT * FROM livros WHERE id = $1",
      [id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Livro não encontrado.",
      });
    }

    return res.status(200).json(resultado.rows[0]);
  } catch (erro) {
    console.error("Erro ao consultar livro:", erro);

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
    console.error("Erro ao cadastrar livro:", erro);

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
    const { id } = req.params;
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
      [String(nome).trim(), String(genero).trim(), id]
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
    console.error("Erro ao atualizar livro:", erro);

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
    const { id } = req.params;

    const resultado = await pool.query(
      `DELETE FROM livros
       WHERE id = $1
       RETURNING id`,
      [id]
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
    console.error("Erro ao excluir livro:", erro);

    return res.status(500).json({
      erro:
        erro.code === "23503"
          ? "Este livro possui registros associados e não pode ser excluído."
          : "Não foi possível excluir o livro.",
    });
  }
});

// ==========================================
// LISTAR ALUGUÉIS DO USUÁRIO AUTENTICADO
// ==========================================

app.get("/alugueis", checar_token, async (req, res) => {
  try {
    const usuarioId = req.usuario.id;

    const resultado = await pool.query(
      `SELECT *
       FROM alugueis
       WHERE usuario_id = $1
       ORDER BY id DESC`,
      [usuarioId]
    );

    return res.status(200).json(resultado.rows);
  } catch (erro) {
    console.error("Erro ao listar aluguéis:", erro);

    if (erro.code === "42P01") {
      return res.status(500).json({
        erro:
          "A tabela alugueis não existe no banco de dados.",
      });
    }

    if (erro.code === "42703") {
      return res.status(500).json({
        erro:
          "Uma das colunas utilizadas na consulta não existe. " +
          "Confira a estrutura da tabela alugueis.",
      });
    }

    return res.status(500).json({
      erro: "Não foi possível buscar os aluguéis.",
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
      "SELECT id FROM livros WHERE id = $1",
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
    console.error("Erro ao criar aluguel:", erro);

    if (erro.code === "42P01" || erro.code === "42703") {
      return res.status(500).json({
        erro:
          "A estrutura da tabela alugueis não corresponde " +
          "à consulta da API.",
      });
    }

    return res.status(500).json({
      erro: "Não foi possível criar o aluguel.",
    });
  }
});

// ==========================================
// TRATAMENTO DE ROTAS INEXISTENTES
// ==========================================

app.use((req, res) => {
  return res.status(404).json({
    erro: "Rota não encontrada.",
    rota: req.originalUrl,
  });
});

// ==========================================
// TRATAMENTO GLOBAL DE ERROS
// ==========================================

app.use((erro, req, res, next) => {
  console.error("Erro inesperado:", erro);

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
  console.log(`PaginariumAPI executando na porta ${porta}`);
});
