import express from "express";
import "dotenv/config";
import cors from "cors";
import pool from "./db.js";
import bcrypt, {genSalt} from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

const app = express();
const porta = 8080;
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

app.use(express.json());
const upload = multer({ storage: multer.memoryStorage() });
app.use(cors());

//node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

//API do Paginarium

const chave = Buffer.from(process.env.CHAVE_CRYPTO, 'hex');
function checar_token(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        console.log("AUTH HEADER:", authHeader);

        if (!authHeader) {
            return res.status(401).json("Token não enviado");
        }

        const token = authHeader.split(" ")[1];

        console.log("TOKEN:", token);

        const decoded = jwt.verify(token, process.env.CHAVE_TOKEN);

        req.usuario = decoded;

        next();

    } catch (erro) {
        console.log("JWT ERROR:", erro.message);
        return res.status(403).json("Token inválido");
    }
}

app.post("/cadastro", async (req, res) => {
  try {
    console.log("BODY:", req.body);
    const { nome, email, senha } = req.body || {};

    if (!nome || !email || !senha) {
      return res.status(422).json("Campos obrigatórios faltando");
    }
    
    const usuarioExiste = await pool.query(
      `
      SELECT 1
      FROM Usuarios
      WHERE email = $1
      `,
      [email]
    );

    if (usuarioExiste.rows.length > 0) {
      return res.status(409).json("Esse usuário já foi cadastrado");
    }

    const salt = await genSalt(12);
    const senhaHash = await bcrypt.hash(senha, salt);

    const resultado = await pool.query(
      `
      INSERT INTO Usuarios (nome, email, senha)
      VALUES ($1, $2, $3)
      RETURNING id, nome, email
      `,
      [nome, email, senhaHash]
    );

    res.status(201).json({
      banco: resultado.rows[0],
      msg: "Usuário cadastrado com sucesso"
    });

  } catch (erro) {
    console.log(erro.message);
    res.status(500).json("Erro no servidor");
  }
});

/*Area de Login no Sistema*/

app.post("/login", async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res.status(422).json("Email e senha obrigatórios");
    }

    // Primeiro procura usuário normal
    let resultado = await pool.query(
      "SELECT * FROM Usuarios WHERE email=$1",
      [email]
    );

    if (resultado.rows.length > 0) {
      const usuario = resultado.rows[0];

      const senhaValida = await bcrypt.compare(senha, usuario.senha);

      if (!senhaValida) {
        return res.status(401).json("Senha inválida");
      }

      const token = jwt.sign(
        {
          id: usuario.id,
          email: usuario.email,
          tipo: "normal"
        },
        process.env.CHAVE_TOKEN,
        { expiresIn: "2h" }
      );

      return res.json({
        mensagem: "Login realizado",
        token,
        usuario: {
          id: usuario.id,
          nome: usuario.nome,
          email: usuario.email,
          credito: usuario.credito,
          tipo: "normal"
        }
      });
    }

    // Se não encontrou usuário, procura administrador
    resultado = await pool.query(
      "SELECT * FROM Administradores WHERE email=$1",
      [email]
    );

    if (resultado.rows.length > 0) {
      const administrador = resultado.rows[0];

      const senhaValida = await bcrypt.compare(
        senha,
        administrador.senha
      );

      if (!senhaValida) {
        return res.status(401).json("Senha inválida");
      }

      const token = jwt.sign(
        {
          id: administrador.id,
          email: administrador.email,
          tipo: "admin"
        },
        process.env.CHAVE_TOKEN,
        { expiresIn: "2h" }
      );

      return res.json({
        mensagem: "Login de administrador realizado",
        token,
        usuario: {
          id: administrador.id,
          nome: administrador.nome,
          email: administrador.email,
          tipo: "admin"
        }
      });
    }

    return res.status(404).json("Usuário não encontrado");

  } catch (erro) {
    console.log("ERRO LOGIN:", erro.message);
    res.status(500).json("Erro no servidor");
  }
});

function verificarAcesso(req, id) {
    return Number(req.usuario.id) === Number(id);
}

app.get("/usuarios/:id", checar_token, async (req, res) => {
    try {

        console.log("REQ.USUARIO:", req.usuario);
        console.log("PARAM ID:", req.params.id);

        const { id } = req.params;

        if (!verificarAcesso(req, id)) {
            return res.status(403).json("Acesso negado");
        }

        const resultado = await pool.query(
            "SELECT * FROM Usuarios WHERE id=$1",
            [id]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json("Usuário não encontrado");
        }

        const usuario = resultado.rows[0];

        res.json(usuario);

    } catch (erro) {
        console.log(erro.message);
        res.status(500).json("Erro no servidor");
    }
});

app.put("/usuarios/:id", checar_token, async (req, res) => {
    try {
        const paramID = Number(req.params.id);
        const id = Number(req.usuario.id);

        if (id !== paramID) {
            return res.status(403).json("Acesso negado");
        }

        const {nome, email} = req.body;

        const resultado = await pool.query(
            `UPDATE Usuarios SET nome=$1, email=$2 WHERE id=$3 RETURNING id`,
            [nome, email, paramID]

        );

        if (resultado.rowCount === 0) {
            return res.status(404).json("Usuário não encontrado");
        }

        res.status(200).json("Usuário Atualizado!");

    } catch (erro) {
        console.log(erro.message);
        res.status(500).json("Erro no servidor");
    }
});

app.delete("/usuarios/:id", checar_token, async (req, res) => {
    try {
        const paramID = Number(req.params.id);
        const id = Number(req.usuario.id);

        console.log("ID TOKEN:", id);
        console.log("ID URL:", paramID);
        
        if (id !== paramID) {
            return res.status(403).json("Acesso negado");
        }

        const resultado = await pool.query(
            "DELETE FROM Usuarios WHERE id=$1 RETURNING id",
            [paramID]
        );

        if (resultado.rowCount === 0) {
            return res.status(404).json("Usuário não encontrado");
        }

        res.status(200).json("Usuário deletado");

    } catch (erro) {
        console.log("DELETE ERROR:", erro.message);
        res.status(500).json("Erro no servidor");
    }
});

/* Area de Criar Contas Adm*/
app.post("/admin/cadastro", async (req, res) => {
  try {
    const { nome, email, senha } = req.body;
    const admExiste = await pool.query(`SELECT * FROM Administradores WHERE email=$1`, [email]);
    if (admExiste.rows.length > 0) return res.status(409).json("Esse administrador já foi cadastrado");

    const salt = await genSalt(12);
    const senhaHash = await bcrypt.hash(senha, salt);
    const resultado = await pool.query(
      `INSERT INTO Administradores (nome, email, senha) VALUES ($1, $2, $3) RETURNING id, nome, email`,
      [nome, email, senhaHash]
    );
    res.status(201).json({ banco: resultado.rows[0], msg: "Administrador cadastrado com sucesso" });
  } catch (erro) {
    console.log("ERRO ADMIN:", erro.message);
    res.status(500).json("erro no servidor");
  }
});
app.post("/alugueis", checar_token, async (req, res) => {
  try {
    const usuario_id = Number(req.usuario.id);
    const { livro_id, meses } = req.body;

    if (!livro_id || !meses || meses <= 0) {
      return res.status(422).json("Dados inválidos");
    }

    const aluguelAtivo = await pool.query(
      `SELECT 1 FROM Alugar
       WHERE usuario_id = $1
         AND livro_id = $2
         AND data_fim >= CURRENT_DATE`,
      [usuario_id, livro_id]
    );

    if (aluguelAtivo.rows.length > 0) {
      return res.status(409).json("Você já possui este livro alugado e ainda no prazo.");
    }

    const livroRes = await pool.query("SELECT * FROM Livros WHERE id=$1", [livro_id]);
    if (livroRes.rows.length === 0) return res.status(404).json("Livro não encontrado");
    const livro = livroRes.rows[0];
    const valor_total = Number(livro.valor) * Number(meses);

    const usuarioRes = await pool.query("SELECT * FROM Usuarios WHERE id=$1", [usuario_id]);
    if (usuarioRes.rows.length === 0) return res.status(404).json("Usuário não encontrado");
    const credito_atual = Number(usuarioRes.rows[0].credito);

    if (credito_atual < valor_total) {
      return res.status(400).json("Saldo insuficiente");
    }

    await pool.query(
      "UPDATE Usuarios SET credito = credito - $1 WHERE id = $2",
      [valor_total, usuario_id]
    );

    // ✅ Calcula data_fim corretamente em formato YYYY-MM-DD
    const dataFim = new Date();
    dataFim.setMonth(dataFim.getMonth() + Number(meses));
    const dataFimISO = dataFim.toISOString().split("T")[0];

    const resultado = await pool.query(
      `INSERT INTO Alugar (usuario_id, livro_id, meses, valor_total, data_inicio, data_fim)
       VALUES ($1, $2, $3, $4, CURRENT_DATE, $5)
       RETURNING *`,
      [usuario_id, livro_id, meses, valor_total, dataFimISO]
    );

    const usuarioAtualizado = await pool.query(
      "SELECT credito FROM Usuarios WHERE id=$1",
      [usuario_id]
    );

    res.status(201).json({
      aluguel: resultado.rows[0],
      novo_credito: Number(usuarioAtualizado.rows[0].credito),
    });
  } catch (erro) {
    console.log(erro.message);
    res.status(500).json("Erro no servidor");
  }
});

app.get("/alugueis", checar_token, async (req, res) => {
  try {
    const usuario_id = Number(req.usuario.id);

    const resultado = await pool.query(
      `SELECT
          a.id,
          a.livro_id,
          a.meses,
          a.valor_total,
          a.data_inicio,
          a.data_fim,
          a.criado_em,
          l.nome,
          l.capa_url,
          l.pdf_url,
          GREATEST(0, 300 - EXTRACT(EPOCH FROM (NOW() - a.criado_em)))::int AS segundos_restantes
       FROM Alugar a
       JOIN livros l ON l.id = a.livro_id
       WHERE a.usuario_id = $1
       ORDER BY a.data_fim DESC`,
      [usuario_id]
    );

    res.json(resultado.rows);
  } catch (erro) {
    console.log("ERRO GET /alugueis:", erro);
    res.status(500).json({ erro: erro.message});
  }
});

// POST
app.post("/livros", upload.any(), async (req, res) => {
  try {
    const { nome, genero, valor } = req.body;
    const capa = req.files?.find(f => f.fieldname === "capa");
    const pdf = req.files?.find(f => f.fieldname === "pdf");
    const valorNumber = Number(valor);

    if (!Number.isFinite(valorNumber)) return res.status(422).json("Valor inválido");
    if (!nome || !genero) return res.status(422).json("Nome e gênero são obrigatórios");
    if (!capa || !pdf || !capa.buffer || !pdf.buffer) return res.status(422).json("Capa e PDF são obrigatórios");

    const livroExiste = await pool.query(`SELECT 1 FROM livros WHERE nome=$1`, [nome]);
    if (livroExiste.rows.length > 0) return res.status(409).json("Esse livro já foi cadastrado!");

    const sanitize = (name) =>
      name.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.-]/g, "-");

    const nomeCapa = `${Date.now()}-${sanitize(capa.originalname)}`;
    const nomePdf = `${Date.now()}-${sanitize(pdf.originalname)}`;

    const { error: erroCapa } = await supabase.storage.from("capas").upload(nomeCapa, capa.buffer, { contentType: capa.mimetype });
    if (erroCapa) { console.log("ERRO CAPA:", erroCapa); return res.status(500).json(erroCapa.message); }

    const { error: erroPdf } = await supabase.storage.from("Livros").upload(nomePdf, pdf.buffer, { contentType: pdf.mimetype });
    if (erroPdf) { console.log("ERRO PDF:", erroPdf); return res.status(500).json(erroPdf.message); }

    const capaUrl = supabase.storage.from("capas").getPublicUrl(nomeCapa).data.publicUrl;
    const pdfUrl = supabase.storage.from("Livros").getPublicUrl(nomePdf).data.publicUrl;

    const resultado = await pool.query(
      `INSERT INTO livros (nome, genero, capa_url, pdf_url, valor) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [nome, genero, capaUrl, pdfUrl, valorNumber]
    );

    return res.status(201).json({ livro: resultado.rows[0], msg: "Livro inserido com sucesso" });
  } catch (erro) {
    console.log("ERRO /livros:", erro);
    return res.status(500).json({ erro: erro.message });
  }
});

app.get("/livros", async (req, res) => {
  try {
    const resultado = await pool.query(`SELECT * FROM livros ORDER BY id`);
    res.status(200).json(resultado.rows);
  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});

app.put("/livros/:id", upload.any(), async (req, res) => {
  try {
    const { id } = req.params;
    const { nome, genero, valor } = req.body;
    const capa = req.files?.find(f => f.fieldname === "capa");
    const pdf = req.files?.find(f => f.fieldname === "pdf");
    const valorNumber = Number(valor);

    if (!Number.isFinite(valorNumber)) return res.status(422).json("Valor inválido");

    const livroAtual = await pool.query("SELECT * FROM livros WHERE id=$1", [id]);
    if (livroAtual.rows.length === 0) return res.status(404).json("Livro não encontrado");

    let capaUrl = livroAtual.rows[0].capa_url;
    let pdfUrl = livroAtual.rows[0].pdf_url;

    const sanitize = (name) =>
      name.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.-]/g, "-");

    if (capa) {
      const nomeCapa = `${Date.now()}-${sanitize(capa.originalname)}`;
      const { error } = await supabase.storage.from("capas").upload(nomeCapa, capa.buffer, { contentType: capa.mimetype });
      if (error) return res.status(500).json(error.message);
      capaUrl = supabase.storage.from("capas").getPublicUrl(nomeCapa).data.publicUrl;
    }

    if (pdf) {
      const nomePdf = `${Date.now()}-${sanitize(pdf.originalname)}`;
      const { error } = await supabase.storage.from("Livros").upload(nomePdf, pdf.buffer, { contentType: pdf.mimetype });
      if (error) return res.status(500).json(error.message);
      pdfUrl = supabase.storage.from("Livros").getPublicUrl(nomePdf).data.publicUrl;
    }

    const resultado = await pool.query(
      `UPDATE livros SET nome=$1, genero=$2, capa_url=$3, pdf_url=$4, valor=$5 WHERE id=$6 RETURNING *`,
      [nome, genero, capaUrl, pdfUrl, valorNumber, id]
    );

    return res.json(resultado.rows[0]);
  } catch (erro) {
    console.log(erro);
    return res.status(500).json({ erro: erro.message });
  }
});

app.delete("/livros/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const resultado = await pool.query(`DELETE FROM livros WHERE id=$1 RETURNING *`, [id]);
    if (resultado.rows.length === 0) return res.status(404).json("Livro não encontrado");
    res.json(resultado.rows[0]);
  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});

app.delete("/alugueis/:id", checar_token, async (req, res) => {
  try {
    const usuario_id = Number(req.usuario.id);
    const aluguel_id = Number(req.params.id);

    const aluguelRes = await pool.query(
      `SELECT *,
              EXTRACT(EPOCH FROM (NOW() - criado_em)) / 60 AS minutos_decorridos
       FROM Alugar
       WHERE id = $1 AND usuario_id = $2`,
      [aluguel_id, usuario_id]
    );

    if (aluguelRes.rows.length === 0) {
      return res.status(404).json("Aluguel não encontrado");
    }

    const aluguel = aluguelRes.rows[0];
    const diferencaMinutos = Number(aluguel.minutos_decorridos);

    console.log("MINUTOS DECORRIDOS (pg):", diferencaMinutos);

    if (diferencaMinutos > 5) {
      return res.status(403).json(
        `Prazo encerrado. Já passaram ${diferencaMinutos.toFixed(2)} minutos.`
      );
    }

    await pool.query(`DELETE FROM Alugar WHERE id = $1`, [aluguel_id]);

    await pool.query(
      `UPDATE Usuarios SET credito = credito + $1 WHERE id = $2`,
      [Number(aluguel.valor_total), usuario_id]
    );

    const usuarioRes = await pool.query(
      `SELECT credito FROM Usuarios WHERE id = $1`,
      [usuario_id]
    );

    res.json({
      msg: "Reembolso realizado com sucesso",
      novo_credito: Number(usuarioRes.rows[0].credito),
    });

  } catch (erro) {
    console.log(erro.message);
    res.status(500).json("Erro no servidor");
  }
});



app.listen(porta, () => {
  console.log(`rodando na porta ${porta}`);
});