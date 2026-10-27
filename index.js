
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const CHAVE_TOKEN = process.env.CHAVE_TOKEN;

app.use(cors());
app.use(express.json());

if (!CHAVE_TOKEN) {
  console.warn(
    "AVISO: configure a variável de ambiente CHAVE_TOKEN."
  );
}

// ======================================================
// AUTENTICAÇÃO
// ======================================================

function checar_token(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      erro: "Token não informado."
    });
  }

  const token = authorization.split(" ")[1];

  try {
    req.usuario = jwt.verify(token, CHAVE_TOKEN);
    next();
  } catch (erro) {
    return res.status(401).json({
      erro: "Token inválido ou expirado."
    });
  }
}

function mesmoUsuario(req, res, id) {
  if (Number(req.usuario.id) !== Number(id)) {
    res.status(403).json({
      erro: "Você não tem permissão para acessar este recurso."
    });
    return false;
  }

  return true;
}

// ======================================================
// CADASTRO
// ======================================================

app.post("/cadastro", async (req, res) => {
  const { nome, email, senha } = req.body;

  if (
    typeof nome !== "string" ||
    typeof email !== "string" ||
    typeof senha !== "string" ||
    !nome.trim() ||
    !email.trim() ||
    !senha
  ) {
    return res.status(400).json({
      erro: "Informe nome, e-mail e senha."
    });
  }

  try {
    const senhaHash = await bcrypt.hash(senha, 10);

    const resultado = await pool.query(
      `INSERT INTO usuarios (nome, email, senha)
       VALUES ($1, $2, $3)
       RETURNING id, nome, email, credito`,
      [nome.trim(), email.trim().toLowerCase(), senhaHash]
    );

    const usuario = resultado.rows[0];

    return res.status(201).json({
      mensagem: "Usuário cadastrado com sucesso.",
      usuario: {
        ...usuario,
        credito: Number(usuario.credito)
      }
    });
  } catch (erro) {
    if (erro.code === "23505") {
      return res.status(409).json({
        erro: "Este e-mail já está cadastrado."
      });
    }

    console.error("[Cadastro]", erro);

    return res.status(500).json({
      erro: "Não foi possível realizar o cadastro."
    });
  }
});

// ======================================================
// LOGIN
// ======================================================

app.post("/login", async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({
      erro: "Informe e-mail e senha."
    });
  }

  try {
    const resultado = await pool.query(
      `SELECT id, nome, email, senha, credito
       FROM usuarios
       WHERE email = $1`,
      [String(email).trim().toLowerCase()]
    );

    if (resultado.rows.length === 0) {
      return res.status(401).json({
        erro: "E-mail ou senha incorretos."
      });
    }

    const usuario = resultado.rows[0];
    const senhaValida = await bcrypt.compare(
      senha,
      usuario.senha
    );

    if (!senhaValida) {
      return res.status(401).json({
        erro: "E-mail ou senha incorretos."
      });
    }

    const token = jwt.sign(
      {
        id: usuario.id,
        email: usuario.email
      },
      CHAVE_TOKEN,
      { expiresIn: "7d" }
    );

    return res.json({
      mensagem: "Login realizado com sucesso.",
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
        credito: Number(usuario.credito)
      }
    });
  } catch (erro) {
    console.error("[Login]", erro);

    return res.status(500).json({
      erro: "Não foi possível realizar o login."
    });
  }
});

// ======================================================
// USUÁRIOS
// ======================================================

// Retorna os dados do usuário autenticado.
app.get("/usuarios", checar_token, async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT id, nome, email, credito
       FROM usuarios
       WHERE id = $1`,
      [req.usuario.id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Usuário não encontrado."
      });
    }

    const usuario = resultado.rows[0];

    return res.json({
      ...usuario,
      credito: Number(usuario.credito)
    });
  } catch (erro) {
    console.error("[Listar usuário]", erro);

    return res.status(500).json({
      erro: "Não foi possível consultar o usuário."
    });
  }
});

app.get("/usuarios/:id", checar_token, async (req, res) => {
  if (!mesmoUsuario(req, res, req.params.id)) return;

  try {
    const resultado = await pool.query(
      `SELECT id, nome, email, credito
       FROM usuarios
       WHERE id = $1`,
      [req.params.id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Usuário não encontrado."
      });
    }

    const usuario = resultado.rows[0];

    return res.json({
      ...usuario,
      credito: Number(usuario.credito)
    });
  } catch (erro) {
    console.error("[Consultar usuário]", erro);

    return res.status(500).json({
      erro: "Não foi possível consultar o usuário."
    });
  }
});

app.put("/usuarios/:id", checar_token, async (req, res) => {
  if (!mesmoUsuario(req, res, req.params.id)) return;

  const { nome, email, senha } = req.body;

  if (
    typeof nome !== "string" ||
    typeof email !== "string" ||
    !nome.trim() ||
    !email.trim()
  ) {
    return res.status(400).json({
      erro: "Informe um nome e um e-mail válidos."
    });
  }

  try {
    let resultado;

    if (senha) {
      const senhaHash = await bcrypt.hash(String(senha), 10);

      resultado = await pool.query(
        `UPDATE usuarios
         SET nome = $1, email = $2, senha = $3
         WHERE id = $4
         RETURNING id, nome, email, credito`,
        [
          nome.trim(),
          email.trim().toLowerCase(),
          senhaHash,
          req.params.id
        ]
      );
    } else {
      resultado = await pool.query(
        `UPDATE usuarios
         SET nome = $1, email = $2
         WHERE id = $3
         RETURNING id, nome, email, credito`,
        [
          nome.trim(),
          email.trim().toLowerCase(),
          req.params.id
        ]
      );
    }

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Usuário não encontrado."
      });
    }

    const usuario = resultado.rows[0];

    return res.json({
      mensagem: "Usuário atualizado com sucesso.",
      usuario: {
        ...usuario,
        credito: Number(usuario.credito)
      }
    });
  } catch (erro) {
    if (erro.code === "23505") {
      return res.status(409).json({
        erro: "Este e-mail já está cadastrado."
      });
    }

    console.error("[Atualizar usuário]", erro);

    return res.status(500).json({
      erro: "Não foi possível atualizar o usuário."
    });
  }
});

app.delete("/usuarios/:id", checar_token, async (req, res) => {
  if (!mesmoUsuario(req, res, req.params.id)) return;

  try {
    const resultado = await pool.query(
      `DELETE FROM usuarios
       WHERE id = $1
       RETURNING id`,
      [req.params.id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Usuário não encontrado."
      });
    }

    return res.json({
      mensagem: "Usuário excluído com sucesso."
    });
  } catch (erro) {
    console.error("[Excluir usuário]", erro);

    return res.status(500).json({
      erro: "Não foi possível excluir o usuário. Verifique se existem aluguéis vinculados."
    });
  }
});

// ======================================================
// LIVROS
// ======================================================

app.get("/livros", async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT id, nome, genero, valor, capa_url, pdf_url
       FROM livros
       ORDER BY id`
    );

    return res.json(
      resultado.rows.map((livro) => ({
        ...livro,
        valor: Number(livro.valor)
      }))
    );
  } catch (erro) {
    console.error("[Listar livros]", erro);

    return res.status(500).json({
      erro: "Não foi possível listar os livros."
    });
  }
});

app.get("/livros/:id", async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT id, nome, genero, valor, capa_url, pdf_url
       FROM livros
       WHERE id = $1`,
      [req.params.id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Livro não encontrado."
      });
    }

    const livro = resultado.rows[0];

    return res.json({
      ...livro,
      valor: Number(livro.valor)
    });
  } catch (erro) {
    console.error("[Consultar livro]", erro);

    return res.status(500).json({
      erro: "Não foi possível consultar o livro."
    });
  }
});

app.post("/livros", checar_token, async (req, res) => {
  const { nome, genero, valor, capa_url, pdf_url } = req.body;
  const valorNumerico = Number(valor);

  if (
    !nome ||
    !genero ||
    !Number.isFinite(valorNumerico) ||
    valorNumerico < 0 ||
    !capa_url ||
    !pdf_url
  ) {
    return res.status(400).json({
      erro: "Informe nome, gênero, valor, capa e PDF do livro."
    });
  }

  try {
    const resultado = await pool.query(
      `INSERT INTO livros (nome, genero, valor, capa_url, pdf_url)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, nome, genero, valor, capa_url, pdf_url`,
      [nome, genero, valorNumerico, capa_url, pdf_url]
    );

    const livro = resultado.rows[0];

    return res.status(201).json({
      mensagem: "Livro cadastrado com sucesso.",
      livro: {
        ...livro,
        valor: Number(livro.valor)
      }
    });
  } catch (erro) {
    console.error("[Cadastrar livro]", erro);

    return res.status(500).json({
      erro: "Não foi possível cadastrar o livro."
    });
  }
});

app.put("/livros/:id", checar_token, async (req, res) => {
  const { nome, genero, valor, capa_url, pdf_url } = req.body;
  const valorNumerico = Number(valor);

  if (
    !nome ||
    !genero ||
    !Number.isFinite(valorNumerico) ||
    valorNumerico < 0 ||
    !capa_url ||
    !pdf_url
  ) {
    return res.status(400).json({
      erro: "Informe todos os dados válidos do livro."
    });
  }

  try {
    const resultado = await pool.query(
      `UPDATE livros
       SET nome = $1,
           genero = $2,
           valor = $3,
           capa_url = $4,
           pdf_url = $5
       WHERE id = $6
       RETURNING id, nome, genero, valor, capa_url, pdf_url`,
      [
        nome,
        genero,
        valorNumerico,
        capa_url,
        pdf_url,
        req.params.id
      ]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Livro não encontrado."
      });
    }

    const livro = resultado.rows[0];

    return res.json({
      mensagem: "Livro atualizado com sucesso.",
      livro: {
        ...livro,
        valor: Number(livro.valor)
      }
    });
  } catch (erro) {
    console.error("[Atualizar livro]", erro);

    return res.status(500).json({
      erro: "Não foi possível atualizar o livro."
    });
  }
});

app.delete("/livros/:id", checar_token, async (req, res) => {
  try {
    const resultado = await pool.query(
      `DELETE FROM livros
       WHERE id = $1
       RETURNING id`,
      [req.params.id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Livro não encontrado."
      });
    }

    return res.json({
      mensagem: "Livro excluído com sucesso."
    });
  } catch (erro) {
    console.error("[Excluir livro]", erro);

    return res.status(500).json({
      erro: "Não foi possível excluir o livro. Verifique se existem aluguéis vinculados."
    });
  }
});

// ======================================================
// LISTAR ALUGUÉIS DO USUÁRIO AUTENTICADO
// ======================================================

app.get("/alugueis", checar_token, async (req, res) => {
  try {
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
         a.reembolsado,
         l.nome AS livro_nome,
         l.genero,
         l.capa_url,
         l.pdf_url
       FROM alugar a
       INNER JOIN livros l ON l.id = a.livro_id
       WHERE a.usuario_id = $1
       ORDER BY a.criado_em DESC`,
      [req.usuario.id]
    );

    return res.json(
      resultado.rows.map((aluguel) => ({
        ...aluguel,
        meses: Number(aluguel.meses),
        valor_total: Number(aluguel.valor_total),
        reembolsado: Boolean(aluguel.reembolsado)
      }))
    );
  } catch (erro) {
    console.error("[Listar aluguéis]", erro);

    return res.status(500).json({
      erro: "Não foi possível listar os aluguéis."
    });
  }
});

// ======================================================
// CRIAR ALUGUEL
// ======================================================

app.post("/alugueis", checar_token, async (req, res) => {
  const livroId = Number(req.body.livroId);
  const quantidadeMeses = Number(req.body.quantidadeMeses);
  const usuarioId = Number(req.usuario.id);

  if (
    !Number.isInteger(livroId) ||
    livroId <= 0 ||
    !Number.isInteger(quantidadeMeses) ||
    quantidadeMeses < 1 ||
    quantidadeMeses > 12
  ) {
    return res.status(400).json({
      erro: "Informe um livro válido e um período de 1 a 12 meses."
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const usuarioResultado = await client.query(
      `SELECT id, credito
       FROM usuarios
       WHERE id = $1
       FOR UPDATE`,
      [usuarioId]
    );

    if (usuarioResultado.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        erro: "Usuário não encontrado."
      });
    }

    const livroResultado = await client.query(
      `SELECT id, nome, valor
       FROM livros
       WHERE id = $1`,
      [livroId]
    );

    if (livroResultado.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        erro: "Livro não encontrado."
      });
    }

    const creditoAtual = Number(
      usuarioResultado.rows[0].credito
    );

    const valorMensal = Number(
      livroResultado.rows[0].valor
    );

    if (
      !Number.isFinite(creditoAtual) ||
      !Number.isFinite(valorMensal) ||
      creditoAtual < 0 ||
      valorMensal < 0
    ) {
      await client.query("ROLLBACK");

      return res.status(500).json({
        erro: "Os valores de créditos ou do livro são inválidos."
      });
    }

    const valorTotal = Number(
      (valorMensal * quantidadeMeses).toFixed(2)
    );

    // Regra atual: 1 crédito equivale a 1 unidade monetária.
    // Como credito é INTEGER, valores fracionários são arredondados
    // para cima para o débito não ficar abaixo do valor da locação.
    const creditosNecessarios = Math.ceil(valorTotal);

    if (creditoAtual < creditosNecessarios) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        erro: "Créditos insuficientes para alugar este livro.",
        credito: creditoAtual,
        creditosNecessarios
      });
    }

    const aluguelResultado = await client.query(
      `INSERT INTO alugar
         (usuario_id, livro_id, meses, valor_total,
          data_inicio, data_fim)
       VALUES
         ($1, $2, $3::integer, $4, CURRENT_DATE,
          (CURRENT_DATE + ($3::integer * INTERVAL '1 month'))::date)
       RETURNING
         id, usuario_id, livro_id, meses, valor_total,
         data_inicio, data_fim, criado_em`,
      [
        usuarioId,
        livroId,
        quantidadeMeses,
        valorTotal
      ]
    );

    const creditoResultado = await client.query(
      `UPDATE usuarios
       SET credito = credito - $1::integer
       WHERE id = $2
       RETURNING credito`,
      [creditosNecessarios, usuarioId]
    );

    await client.query("COMMIT");

    const aluguel = aluguelResultado.rows[0];

    return res.status(201).json({
      mensagem: "Livro alugado com sucesso.",
      aluguel: {
        ...aluguel,
        meses: Number(aluguel.meses),
        valor_total: Number(aluguel.valor_total),
        reembolsado: false
      },
      credito: Number(creditoResultado.rows[0].credito),
      creditosUtilizados: creditosNecessarios
    });
  } catch (erro) {
    await client.query("ROLLBACK");

    console.error("[Criar aluguel]", {
      mensagem: erro.message,
      codigo: erro.code,
      detalhe: erro.detail
    });

    return res.status(500).json({
      erro: "Não foi possível realizar o aluguel."
    });
  } finally {
    client.release();
  }
});

// ======================================================
// REEMBOLSO DE ALUGUEL — LIMITE DE 5 MINUTOS
// ======================================================

app.post(
  "/alugueis/:id/reembolso",
  checar_token,
  async (req, res) => {
    const aluguelId = Number(req.params.id);
    const usuarioId = Number(req.usuario.id);

    if (!Number.isInteger(aluguelId) || aluguelId <= 0) {
      return res.status(400).json({
        erro: "Identificador de aluguel inválido."
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // Bloqueia o aluguel para impedir reembolsos duplicados.
      const aluguelResultado = await client.query(
        `SELECT
           id,
           usuario_id,
           livro_id,
           valor_total,
           criado_em,
           reembolsado
         FROM alugar
         WHERE id = $1
         FOR UPDATE`,
        [aluguelId]
      );

      if (aluguelResultado.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          erro: "Aluguel não encontrado."
        });
      }

      const aluguel = aluguelResultado.rows[0];

      if (Number(aluguel.usuario_id) !== usuarioId) {
        await client.query("ROLLBACK");

        return res.status(403).json({
          erro: "Você não pode solicitar reembolso deste aluguel."
        });
      }

      if (aluguel.reembolsado) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          erro: "Este aluguel já foi reembolsado."
        });
      }

      // O prazo é calculado pelo relógio do banco de dados.
      const prazoResultado = await client.query(
        `SELECT
           (NOW() <= $1::timestamp + INTERVAL '5 minutes')
             AS dentro_do_prazo,
           (NOW() - $1::timestamp)
             AS tempo_decorrido`,
        [aluguel.criado_em]
      );

      if (!prazoResultado.rows[0].dentro_do_prazo) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          erro: "O prazo de 5 minutos para solicitar o reembolso expirou."
        });
      }

      const valorTotal = Number(aluguel.valor_total);

      if (!Number.isFinite(valorTotal) || valorTotal < 0) {
        await client.query("ROLLBACK");

        return res.status(500).json({
          erro: "O valor do aluguel é inválido."
        });
      }

      // Deve usar a mesma regra de conversão do débito no aluguel.
      const creditosDevolvidos = Math.ceil(valorTotal);

      // Bloqueia o usuário durante a atualização dos créditos.
      const usuarioResultado = await client.query(
        `SELECT id
         FROM usuarios
         WHERE id = $1
         FOR UPDATE`,
        [usuarioId]
      );

      if (usuarioResultado.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          erro: "Usuário não encontrado."
        });
      }

      const creditoResultado = await client.query(
        `UPDATE usuarios
         SET credito = credito + $1::integer
         WHERE id = $2
         RETURNING credito`,
        [creditosDevolvidos, usuarioId]
      );

      await client.query(
        `UPDATE alugar
         SET reembolsado = TRUE
         WHERE id = $1`,
        [aluguelId]
      );

      await client.query("COMMIT");

      return res.json({
        mensagem: "Reembolso realizado com sucesso.",
        aluguelId,
        reembolsado: true,
        creditosDevolvidos,
        credito: Number(creditoResultado.rows[0].credito)
      });
    } catch (erro) {
      await client.query("ROLLBACK");

      console.error("[Reembolso]", {
        mensagem: erro.message,
        codigo: erro.code,
        detalhe: erro.detail
      });

      return res.status(500).json({
        erro: "Não foi possível processar o reembolso."
      });
    } finally {
      client.release();
    }
  }
);

// ======================================================
// ROTA INEXISTENTE
// ======================================================

app.use((req, res) => {
  return res.status(404).json({
    erro: "Rota não encontrada."
  });
});

// ======================================================
// TRATAMENTO DE ERROS
// ======================================================

app.use((erro, req, res, next) => {
  console.error("[Erro inesperado]", erro);

  if (res.headersSent) {
    return next(erro);
  }

  return res.status(500).json({
    erro: "Ocorreu um erro interno no servidor."
  });
});

// ======================================================
// INICIAR SERVIDOR
// ======================================================

app.listen(PORT, () => {
  console.log(`Servidor iniciado na porta ${PORT}.`);
});
