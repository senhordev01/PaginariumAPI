
import express from "express";
import "dotenv/config";
import cors from "cors";
import pool from "./db.js";
import bcrypt, { genSalt } from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const porta = process.env.PORT || 8080;

app.use(express.json());

app.use(cors());

/* =========================
   CONFIGURAÇÕES E AUTENTICAÇÃO
========================= */

function checar_token(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({
                erro: "Token não enviado"
            });
        }

        const partes = authHeader.split(" ");

        if (partes.length !== 2 || partes[0] !== "Bearer") {
            return res.status(401).json({
                erro: "Formato do token inválido. Use Bearer <token>."
            });
        }

        const token = partes[1];

        if (!process.env.CHAVE_TOKEN) {
            console.error("CHAVE_TOKEN não configurada.");
            return res.status(500).json({
                erro: "Configuração de autenticação ausente"
            });
        }

        const decoded = jwt.verify(token, process.env.CHAVE_TOKEN);

        req.usuario = decoded;

        next();
    } catch (erro) {
        console.error("Erro de autenticação:", erro.message);

        if (erro.name === "TokenExpiredError") {
            return res.status(401).json({
                erro: "Token expirado. Faça login novamente."
            });
        }

        return res.status(403).json({
            erro: "Token inválido"
        });
    }
}

function verificarAcesso(req, id) {
    return Number(req.usuario.id) === Number(id);
}

/* =========================
   ROTA INICIAL E TESTE
========================= */

app.get("/", (req, res) => {
    res.status(200).json({
        mensagem: "PaginariumAPI está funcionando!",
        status: "online"
    });
});

app.get("/health", async (req, res) => {
    try {
        await pool.query("SELECT 1");

        res.status(200).json({
            status: "online",
            banco: "conectado"
        });
    } catch (erro) {
        console.error("Erro ao verificar banco:", erro.message);

        res.status(503).json({
            status: "indisponível",
            banco: "erro de conexão"
        });
    }
});

/* =========================
   CADASTRO DE USUÁRIOS
========================= */

app.post("/cadastro", async (req, res) => {
    try {
        const { nome, email, senha } = req.body || {};

        if (!nome || !email || !senha) {
            return res.status(422).json({
                erro: "Nome, email e senha são obrigatórios"
            });
        }

        const usuarioExiste = await pool.query(
            `SELECT 1 FROM Usuarios WHERE email = $1`,
            [email]
        );

        if (usuarioExiste.rows.length > 0) {
            return res.status(409).json({
                erro: "Esse usuário já foi cadastrado"
            });
        }

        const salt = await genSalt(12);
        const senhaHash = await bcrypt.hash(senha, salt);

        const resultado = await pool.query(
            `INSERT INTO Usuarios (nome, email, senha)
             VALUES ($1, $2, $3)
             RETURNING id, nome, email`,
            [nome, email, senhaHash]
        );

        return res.status(201).json({
            banco: resultado.rows[0],
            msg: "Usuário cadastrado com sucesso"
        });
    } catch (erro) {
        console.error("Erro no cadastro:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor ao cadastrar usuário"
        });
    }
});

/* =========================
   LOGIN DE USUÁRIOS
========================= */

app.post("/login", async (req, res) => {
    try {
        const { email, senha } = req.body || {};

        if (!email || !senha) {
            return res.status(422).json({
                erro: "Email e senha são obrigatórios"
            });
        }

        const resultado = await pool.query(
            `SELECT id, nome, email, senha
             FROM Usuarios
             WHERE email = $1`,
            [email]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json({
                erro: "Usuário não encontrado"
            });
        }

        const usuario = resultado.rows[0];

        const senhaValida = await bcrypt.compare(
            senha,
            usuario.senha
        );

        if (!senhaValida) {
            return res.status(401).json({
                erro: "Senha inválida"
            });
        }

        if (!process.env.CHAVE_TOKEN) {
            console.error("CHAVE_TOKEN não configurada.");

            return res.status(500).json({
                erro: "Configuração de autenticação ausente"
            });
        }

        const token = jwt.sign(
            {
                id: usuario.id,
                email: usuario.email
            },
            process.env.CHAVE_TOKEN,
            {
                expiresIn: "2h"
            }
        );

        return res.status(200).json({
            mensagem: "Login realizado",
            token,
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email
            }
        });
    } catch (erro) {
        console.error("Erro no login:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor durante o login"
        });
    }
});

/* =========================
   CONSULTAR USUÁRIO
========================= */

app.get("/usuarios/:id", checar_token, async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id <= 0) {
            return res.status(400).json({
                erro: "ID de usuário inválido"
            });
        }

        if (!verificarAcesso(req, id)) {
            return res.status(403).json({
                erro: "Acesso negado: você só pode consultar sua própria conta"
            });
        }

        const resultado = await pool.query(
            `SELECT id, nome, email
             FROM Usuarios
             WHERE id = $1`,
            [id]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json({
                erro: "Usuário não encontrado"
            });
        }

        return res.status(200).json(resultado.rows[0]);
    } catch (erro) {
        console.error("Erro ao consultar usuário:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor ao consultar usuário"
        });
    }
});

/* =========================
   ATUALIZAR USUÁRIO
========================= */

app.put("/usuarios/:id", checar_token, async (req, res) => {
    try {
        const paramID = Number(req.params.id);
        const id = Number(req.usuario.id);

        if (!Number.isInteger(paramID) || paramID <= 0) {
            return res.status(400).json({
                erro: "ID de usuário inválido"
            });
        }

        if (id !== paramID) {
            return res.status(403).json({
                erro: "Acesso negado"
            });
        }

        const { nome, email } = req.body || {};

        if (!nome || !email) {
            return res.status(422).json({
                erro: "Nome e email são obrigatórios"
            });
        }

        const resultado = await pool.query(
            `UPDATE Usuarios
             SET nome = $1, email = $2
             WHERE id = $3
             RETURNING id, nome, email`,
            [nome, email, paramID]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json({
                erro: "Usuário não encontrado"
            });
        }

        return res.status(200).json({
            mensagem: "Usuário atualizado com sucesso",
            usuario: resultado.rows[0]
        });
    } catch (erro) {
        console.error("Erro ao atualizar usuário:", erro.message);

        if (erro.code === "23505") {
            return res.status(409).json({
                erro: "Esse email já está sendo utilizado"
            });
        }

        return res.status(500).json({
            erro: "Erro no servidor ao atualizar usuário"
        });
    }
});

/* =========================
   EXCLUIR USUÁRIO
========================= */

app.delete("/usuarios/:id", checar_token, async (req, res) => {
    try {
        const paramID = Number(req.params.id);
        const id = Number(req.usuario.id);

        if (!Number.isInteger(paramID) || paramID <= 0) {
            return res.status(400).json({
                erro: "ID de usuário inválido"
            });
        }

        if (id !== paramID) {
            return res.status(403).json({
                erro: "Acesso negado"
            });
        }

        const resultado = await pool.query(
            `DELETE FROM Usuarios
             WHERE id = $1
             RETURNING id`,
            [paramID]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json({
                erro: "Usuário não encontrado"
            });
        }

        return res.status(200).json({
            mensagem: "Usuário deletado com sucesso"
        });
    } catch (erro) {
        console.error("Erro ao excluir usuário:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor ao excluir usuário"
        });
    }
});

/* =========================
   CADASTRO DE ADMINISTRADOR
   Mantida a rota original.
========================= */

app.post("/admin/login", async (req, res) => {
    try {
        const { nome, email, senha } = req.body || {};

        if (!nome || !email || !senha) {
            return res.status(422).json({
                erro: "Nome, email e senha são obrigatórios"
            });
        }

        const admExiste = await pool.query(
            `SELECT 1 FROM Administradores WHERE email = $1`,
            [email]
        );

        if (admExiste.rows.length > 0) {
            return res.status(409).json({
                erro: "Esse administrador já foi cadastrado"
            });
        }

        const salt = await genSalt(12);
        const senhaHash = await bcrypt.hash(senha, salt);

        const resultado = await pool.query(
            `INSERT INTO Administradores (nome, email, senha)
             VALUES ($1, $2, $3)
             RETURNING id, nome, email`,
            [nome, email, senhaHash]
        );

        return res.status(201).json({
            banco: resultado.rows[0],
            msg: "Administrador cadastrado com sucesso"
        });
    } catch (erro) {
        console.error("Erro no cadastro de administrador:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor"
        });
    }
});

/* =========================
   LIVROS - CADASTRAR
========================= */

app.post("/livros", async (req, res) => {
    try {
        const { nome, genero } = req.body || {};

        if (!nome || !genero) {
            return res.status(422).json({
                erro: "Nome e gênero são obrigatórios"
            });
        }

        const livroExiste = await pool.query(
            `SELECT 1 FROM livros WHERE nome = $1`,
            [nome]
        );

        if (livroExiste.rows.length > 0) {
            return res.status(409).json({
                erro: "Esse livro já foi cadastrado"
            });
        }

        const resultado = await pool.query(
            `INSERT INTO livros (nome, genero)
             VALUES ($1, $2)
             RETURNING *`,
            [nome, genero]
        );

        return res.status(201).json({
            banco: resultado.rows[0],
            msg: "Livro inserido com sucesso"
        });
    } catch (erro) {
        console.error("Erro ao cadastrar livro:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor ao cadastrar livro"
        });
    }
});

/* =========================
   LIVROS - LISTAR
========================= */

app.get("/livros", async (req, res) => {
    try {
        const resultado = await pool.query(
            `SELECT * FROM livros ORDER BY id`
        );

        return res.status(200).json(resultado.rows);
    } catch (erro) {
        console.error("Erro ao listar livros:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor ao listar livros"
        });
    }
});

/* =========================
   LIVROS - ATUALIZAR
========================= */

app.put("/livros/:id", async (req, res) => {
    try {
        const { nome, genero } = req.body || {};
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id <= 0) {
            return res.status(400).json({
                erro: "ID de livro inválido"
            });
        }

        if (!nome || !genero) {
            return res.status(422).json({
                erro: "Nome e gênero são obrigatórios"
            });
        }

        const resultado = await pool.query(
            `UPDATE livros
             SET nome = $1, genero = $2
             WHERE id = $3
             RETURNING *`,
            [nome, genero, id]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json({
                erro: "Livro não encontrado"
            });
        }

        return res.status(200).json(resultado.rows[0]);
    } catch (erro) {
        console.error("Erro ao atualizar livro:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor ao atualizar livro"
        });
    }
});

/* =========================
   LIVROS - EXCLUIR
========================= */

app.delete("/livros/:id", async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id <= 0) {
            return res.status(400).json({
                erro: "ID de livro inválido"
            });
        }

        const resultado = await pool.query(
            `DELETE FROM livros
             WHERE id = $1
             RETURNING *`,
            [id]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json({
                erro: "Livro não encontrado"
            });
        }

        return res.status(200).json(resultado.rows[0]);
    } catch (erro) {
        console.error("Erro ao excluir livro:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor ao excluir livro"
        });
    }
});

/* =========================
   ALUGUÉIS
========================= */

// A rota existe para que o caminho não fique sem tratamento.
// A consulta real depende da estrutura das tabelas do PostgreSQL.

app.get("/alugueis", (req, res) => {
    return res.status(501).json({
        erro: "A rota de aluguéis ainda precisa ser implementada",
        mensagem: "Configure a consulta conforme as tabelas e relacionamentos do banco de dados."
    });
});

/* =========================
   ROTA NÃO ENCONTRADA
========================= */

app.use((req, res) => {
    return res.status(404).json({
        erro: "Rota não encontrada",
        metodo: req.method,
        caminho: req.originalUrl
    });
});

/* =========================
   INICIALIZAÇÃO
========================= */

app.listen(porta, "0.0.0.0", () => {
    console.log(`PaginariumAPI rodando na porta ${porta}`);
});
