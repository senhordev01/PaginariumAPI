
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const CHAVE_TOKEN = process.env.CHAVE_TOKEN;

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "Cache-Control",
    "Pragma"
  ]
}));

app.use(express.json());

function registrarErro(contexto, erro) {
  console.error(`[${contexto}]`, {
    mensagem: erro.message,
    codigo: erro.code,
    detalhe: erro.detail,
    tabela: erro.table,
    coluna: erro.column,
    restricao: erro.constraint,
    stack: erro.stack
  });
}

function gerarToken(usuario) {
  if (!CHAVE_TOKEN) {
    throw new Error("A variável CHAVE_TOKEN não está configurada.");
  }

  return jwt.sign(
    {
      id: usuario.id,
      email: usuario.email
    },
    CHAVE_TOKEN,
    { expiresIn: "2h" }
  );
}

function checar_token(req, res, next) {
  const autorizacao = req.headers.authorization;

  if (!autorizacao || !autorizacao.startsWith("Bearer ")) {
    return res.status(401).json({
      erro: "Token de autenticação não informado."
    });
  }

  const token = autorizacao.split(" ")[1];

  try {
    req.usuario = jwt.verify(token, CHAVE_TOKEN);
    next();
  } catch (erro) {
    return res.status(401).json({
      erro: "Token inválido ou expirado."
    });
  }
}

// ==========================================
// STATUS DA API
// ==========================================
app.get("/", (req, res) => {
  res.json({
    mensagem: "API do Paginarium funcionando."
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.status(200).json({
      status: "ok",
      banco: "conectado"
    });
  } catch (erro) {
    registrarErro("Health check", erro);

    res.status(500).json({
      status: "erro",
      banco: "indisponível"
    });
  }
});

// ==========================================
// CADASTRO DE USUÁRIO
// ==========================================
app.post("/cadastro", async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
      return res.status(400).json({
        erro: "Informe nome, e-mail e senha."
      });
    }

    const emailNormalizado = String(email).trim().toLowerCase();

    const existente = await pool.query(
      "SELECT id FROM usuarios WHERE LOWER(email) = $1",
      [emailNormalizado]
    );

    if (existente.rows.length > 0) {
      return res.status(409).json({
        erro: "Este e-mail já está cadastrado."
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
      usuario: resultado.rows[0]
    });
  } catch (erro) {
    registrarErro("Cadastro", erro);

    if (erro.code === "23505") {
      return res.status(409).json({
        erro: "Este usuário já está cadastrado."
      });
    }

    return res.status(500).json({
      erro: "Não foi possível cadastrar o usuário."
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
        erro: "Informe e-mail e senha."
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
        erro: "E-mail ou senha inválidos."
      });
    }

    const usuario = resultado.rows[0];
    const senhaValida = await bcrypt.compare(
      String(senha),
      usuario.senha
    );

    if (!senhaValida) {
      return res.status(401).json({
        erro: "E-mail ou senha inválidos."
      });
    }

    const token = gerarToken(usuario);

    return res.status(200).json({
      mensagem: "Login realizado com sucesso.",
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email
      }
    });
  } catch (erro) {
    registrarErro("Login", erro);

    return res.status(500).json({
      erro: "Não foi possível realizar o login."
    });
  }
});

// ==========================================
// LISTAR USUÁRIOS
// ==========================================
app.get("/usuarios", checar_token, async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT id, nome, email
       FROM usuarios
       ORDER BY id DESC`
    );

    return res.status(200).json(resultado.rows);
  } catch (erro) {
    registrarErro("Listar usuários", erro);

    return res.status(500).json({
      erro: "Não foi possível listar os usuários."
    });
  }
});

// ==========================================
// BUSCAR USUÁRIO POR ID
// ==========================================
app.get("/usuarios/:id", checar_token, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        erro: "ID inválido."
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
        erro: "Usuário não encontrado."
      });
    }

    return res.status(200).json(resultado.rows[0]);
  } catch (erro) {
    registrarErro("Buscar usuário", erro);

    return res.status(500).json({
      erro: "Não foi possível buscar o usuário."
    });
  }
});

// ==========================================
// ATUALIZAR USUÁRIO
// ==========================================
app.put("/usuarios/:id", checar_token, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { nome, email } = req.body;

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        erro: "ID inválido."
      });
    }

    if (id !== Number(req.usuario.id)) {
      return res.status(403).json({
        erro: "Você só pode atualizar sua própria conta."
      });
    }

    if (!nome || !email) {
      return res.status(400).json({
        erro: "Informe nome e e-mail."
      });
    }

    const resultado = await pool.query(
      `UPDATE usuarios
       SET nome = $1, email = $2
       WHERE id = $3
       RETURNING id, nome, email`,
      [String(nome).trim(), String(email).trim().toLowerCase(), id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Usuário não encontrado."
      });
    }

    return res.status(200).json({
      mensagem: "Usuário atualizado com sucesso.",
      usuario: resultado.rows[0]
    });
  } catch (erro) {
    registrarErro("Atualizar usuário", erro);

    if (erro.code === "23505") {
      return res.status(409).json({
        erro: "Este e-mail já está em uso."
      });
    }

    return res.status(500).json({
      erro: "Não foi possível atualizar o usuário."
    });
  }
});

// ==========================================
// EXCLUIR USUÁRIO
// ==========================================
app.delete("/usuarios/:id", checar_token, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        erro: "ID inválido."
      });
    }

    if (id !== Number(req.usuario.id)) {
      return res.status(403).json({
        erro: "Você só pode excluir sua própria conta."
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
        erro: "Usuário não encontrado."
      });
    }

    return res.status(200).json({
      mensagem: "Usuário excluído com sucesso."
    });
  } catch (erro) {
    registrarErro("Excluir usuário", erro);

    if (erro.code === "23503") {
      return res.status(409).json({
        erro: "Não é possível excluir este usuário porque existem registros vinculados a ele."
      });
    }

    return res.status(500).json({
      erro: "Não foi possível excluir o usuário."
    });
  }
});

// ==========================================
// LISTAR LIVROS
// ==========================================
app.get("/livros", async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT id, nome, genero, valor, capa_url, pdf_url
       FROM livros
       ORDER BY id DESC`
    );

    return res.status(200).json(resultado.rows);
  } catch (erro) {
    registrarErro("Listar livros", erro);

    return res.status(500).json({
      erro: "Não foi possível listar os livros."
    });
  }
});

// ==========================================
// BUSCAR LIVRO POR ID
// ==========================================
app.get("/livros/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        erro: "ID inválido."
      });
    }

    const resultado = await pool.query(
      `SELECT id, nome, genero, valor, capa_url, pdf_url
       FROM livros
       WHERE id = $1`,
      [id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Livro não encontrado."
      });
    }

    return res.status(200).json(resultado.rows[0]);
  } catch (erro) {
    registrarErro("Buscar livro", erro);

    return res.status(500).json({
      erro: "Não foi possível buscar o livro."
    });
  }
});

// ==========================================
// CADASTRAR LIVRO
// ==========================================
app.post("/livros", checar_token, async (req, res) => {
  try {
    const { nome, genero, valor, capa_url, pdf_url } = req.body;

    if (!nome || !genero || valor === undefined) {
      return res.status(400).json({
        erro: "Informe nome, gênero e valor do livro."
      });
    }

    const valorNumerico = Number(valor);

    if (!Number.isFinite(valorNumerico) || valorNumerico < 0) {
      return res.status(400).json({
        erro: "Informe um valor válido para o livro."
      });
    }

    const resultado = await pool.query(
      `INSERT INTO livros (nome, genero, valor, capa_url, pdf_url)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [
        String(nome).trim(),
        String(genero).trim(),
        valorNumerico,
        capa_url || null,
        pdf_url || null
      ]
    );

    return res.status(201).json({
      mensagem: "Livro cadastrado com sucesso.",
      livro: resultado.rows[0]
    });
  } catch (erro) {
    registrarErro("Cadastrar livro", erro);

    return res.status(500).json({
      erro: "Não foi possível cadastrar o livro."
    });
  }
});

// ==========================================
// ATUALIZAR LIVRO
// ==========================================
app.put("/livros/:id", checar_token, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { nome, genero, valor, capa_url, pdf_url } = req.body;

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        erro: "ID inválido."
      });
    }

    if (!nome || !genero || valor === undefined) {
      return res.status(400).json({
        erro: "Informe nome, gênero e valor do livro."
      });
    }

    const valorNumerico = Number(valor);

    if (!Number.isFinite(valorNumerico) || valorNumerico < 0) {
      return res.status(400).json({
        erro: "Informe um valor válido para o livro."
      });
    }

    const resultado = await pool.query(
      `UPDATE livros
       SET nome = $1,
           genero = $2,
           valor = $3,
           capa_url = $4,
           pdf_url = $5
       WHERE id = $6
       RETURNING *`,
      [
        String(nome).trim(),
        String(genero).trim(),
        valorNumerico,
        capa_url || null,
        pdf_url || null,
        id
      ]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Livro não encontrado."
      });
    }

    return res.status(200).json({
      mensagem: "Livro atualizado com sucesso.",
      livro: resultado.rows[0]
    });
  } catch (erro) {
    registrarErro("Atualizar livro", erro);

    return res.status(500).json({
      erro: "Não foi possível atualizar o livro."
    });
  }
});

// ==========================================
// EXCLUIR LIVRO
// ==========================================
app.delete("/livros/:id", checar_token, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        erro: "ID inválido."
      });
    }

    const resultado = await pool.query(
      `DELETE FROM livros
       WHERE id = $1
       RETURNING id`,
      [id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Livro não encontrado."
      });
    }

    return res.status(200).json({
      mensagem: "Livro excluído com sucesso."
    });
  } catch (erro) {
    registrarErro("Excluir livro", erro);

    if (erro.code === "23503") {
      return res.status(409).json({
        erro: "Não é possível excluir este livro porque ele possui aluguéis registrados."
      });
    }

    return res.status(500).json({
      erro: "Não foi possível excluir o livro."
    });
  }
});

// ==========================================
// LISTAR ALUGUÉIS DO USUÁRIO AUTENTICADO
// ==========================================
app.get("/alugueis", checar_token, async (req, res) => {
  try {
    const usuarioId = Number(req.usuario.id);

    const resultado = await pool.query(
      `SELECT
         a.id,
         a.usuario_id,
         a.livro_id,
         a.data_inicio,
         a.data_fim,
         a.meses,
         a.valor_total,
         a.criado_em,
         l.nome AS livro_nome,
         l.genero,
         l.capa_url,
         l.pdf_url
       FROM alugar a
       INNER JOIN livros l ON l.id = a.livro_id
       WHERE a.usuario_id = $1
       ORDER BY a.id DESC`,
      [usuarioId]
    );

    return res.status(200).json(resultado.rows);
  } catch (erro) {
    registrarErro("Listar aluguéis", erro);

    return res.status(500).json({
      erro: "Não foi possível listar os aluguéis.",
      codigo: erro.code || "ERRO_INTERNO"
    });
  }
});

// ==========================================
// CRIAR ALUGUEL
// ==========================================
app.post("/alugueis", checar_token, async (req, res) => {
  try {
    const usuarioId = Number(req.usuario.id);
    const { livro_id, meses } = req.body;
    const livroId = Number(livro_id);
    const quantidadeMeses = Number(meses);

    if (
      !Number.isInteger(usuarioId) ||
      usuarioId <= 0 ||
      !Number.isInteger(livroId) ||
      livroId <= 0 ||
      !Number.isInteger(quantidadeMeses) ||
      quantidadeMeses <= 0
    ) {
      return res.status(400).json({
        erro: "Informe um livro e uma quantidade de meses válidos."
      });
    }

    const livro = await pool.query(
      `SELECT id, nome, valor
       FROM livros
       WHERE id = $1`,
      [livroId]
    );

    if (livro.rows.length === 0) {
      return res.status(404).json({
        erro: "Livro não encontrado."
      });
    }

    // Pressuposto: livros.valor representa o preço mensal do aluguel.
    const valorMensal = Number(livro.rows[0].valor);

    if (!Number.isFinite(valorMensal) || valorMensal < 0) {
      return res.status(400).json({
        erro: "O livro possui um valor inválido para aluguel."
      });
    }

    const valorTotal = (valorMensal * quantidadeMeses).toFixed(2);

    const resultado = await pool.query(
      `INSERT INTO alugar (
         usuario_id,
         livro_id,
         meses,
         valor_total,
         data_inicio,
         data_fim
       )
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

    return res.status(201).json({
      mensagem: "Aluguel criado com sucesso.",
      aluguel: resultado.rows[0],
      livro: livro.rows[0].nome
    });
  } catch (erro) {
    registrarErro("Criar aluguel", erro);

    if (erro.code === "23503") {
      return res.status(400).json({
        erro: "O usuário ou o livro informado não existe no banco de dados."
      });
    }

    return res.status(500).json({
      erro: "Não foi possível criar o aluguel.",
      codigo: erro.code || "ERRO_INTERNO"
    });
  }
});

// ==========================================
// TRATAMENTO DE ROTAS INEXISTENTES
// ==========================================
app.use((req, res) => {
  res.status(404).json({
    erro: "Rota não encontrada.",
    rota: req.originalUrl
  });
});

// ==========================================
// INICIAR SERVIDOR
// ==========================================
app.listen(PORT, () => {
  console.log(`API do Paginarium rodando na porta ${PORT}.`);
});
