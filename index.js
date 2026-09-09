import express from "express";
import "dotenv/config";
import cors from "cors";
import pool from "./db.js";
import bcrypt, {genSalt} from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
const app = express();
const porta = 8080;


app.use(express.json());
app.use(cors());


//node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

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

        const resultado = await pool.query(
            "SELECT * FROM Usuarios WHERE email=$1",
            [email]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json("Usuário não encontrado");
        }

        const usuario = resultado.rows[0];
        const senhaValida = await bcrypt.compare(senha, usuario.senha);

        if (!senhaValida) {
            return res.status(401).json("Senha inválida");
        }

        const token = jwt.sign(
            { id: usuario.id, email: usuario.email },
            process.env.CHAVE_TOKEN,
            { expiresIn: "2h" }
        );

        res.json({
            mensagem: "Login realizado",
            token
        });

    } catch (erro) {
        console.log(erro.message);
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
app.post("/admin/login", async (req, res) => {
  try{
    const { nome, email, senha } = req.body;

    const admExiste = await pool.query(
        `
        SELECT * FROM Administradores
        WHERE email = $1
        `,
        [email]
    );

    if(admExiste.rows.length > 0){
      return res.status(409).json("Esse administrador já foi cadastrado")
    }

    const salt = await genSalt(12);
    const senhaHash = await bcrypt.hash(senha, salt);

    const resultado = await pool.query(
      `
      INSERT INTO Administradores (nome, email, senha)
      VALUES ($1, $2, $3)
      RETURNING id, nome, email
      `,
      [nome, email, senhaHash]
    );
    res.status(201).json({
      banco: resultado.rows[0],
      msg: "Administrador cadastrado com sucesso"
    });
  }catch(erro){
    console.log(erro.message);
    res.status(500).json("erro no servidor");
  }
});

/*Area do Crud dos Livros*/

// POST
app.post("/livros", async (req, res) => {
  try {
    const { nome, genero } = req.body;

    if (!nome || !genero) {
      return res.status(422).json("Campos obrigatórios faltando");
    }
    const livroExiste = await pool.query(
      `
      SELECT * FROM livros
      WHERE nome = $1
      `,
      [nome]
    );

    if(livroExiste.rows.length > 0){
        return res.status(409).json("Esse livro ja foi cadastrado!");
    }
    const resultado = await pool.query(
      `
      INSERT INTO livros (nome, genero)
      VALUES ($1, $2)
      RETURNING *
      `,
      [nome, genero]
    );


    res.status(201).json({banco: resultado.rows[0], msg:"livro inserido com sucesso"});
  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});


// GET
app.get("/livros", async (req, res) => {
  try {
    const resultado = await pool.query(
      `
      SELECT * FROM livros
      ORDER BY id
      `
    );

    res.status(200).json(resultado.rows);

  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});


// PUT
app.put("/livros/:id", async (req, res) => {
  try {
    const { nome, genero } = req.body;
    const { id } = req.params;

    const resultado = await pool.query(
      `
      UPDATE livros
      SET nome = $1, genero = $2
      WHERE id = $3
      RETURNING *
      `,
      [nome, genero, id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json("Livro não encontrado");
    }

    res.json(resultado.rows[0]);

  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});


// DELETE
app.delete("/livros/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const resultado = await pool.query(
      `
      DELETE FROM livros
      WHERE id = $1
      RETURNING *
      `,
      [id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json("Livro não encontrado");
    }

    res.json(resultado.rows[0]);

  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});

app.listen(porta, () => {
  console.log(`rodando na porta ${porta}`);
});