
import express from "express";
import "dotenv/config";
import cors from "cors";
import pool from "./db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const porta = process.env.PORT || 8080;

app.use(express.json());
app.use(cors());

// =====================================================
// AUTENTICAÇÃO JWT
// =====================================================

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
                erro: "Formato do token inválido"
            });
        }

        const token = partes[1];

        const decoded = jwt.verify(
            token,
            process.env.CHAVE_TOKEN
        );

        req.usuario = decoded;

        next();
    } catch (erro) {
        console.log("JWT ERROR:", erro.message);

        return res.status(401).json({
            erro: "Token inválido ou expirado"
        });
    }
}

function verificarAcesso(req, id) {
    return Number(req.usuario.id) === Number(id);
}

// =====================================================
// CADASTRO DE USUÁRIOS
// =====================================================

app.post("/cadastro", async (req, res) => {
    try {
        const { nome, email, senha } = req.body || {};

        if (!nome || !email || !senha) {
            return res.status(422).json({
                erro: "Nome, email e senha são obrigatórios"
            });
        }

        const usuarioExiste = await pool.query(
            `SELECT id FROM usuarios WHERE email = $1`,
            [email]
        );

        if (usuarioExiste.rows.length > 0) {
            return res.status(409).json({
                erro: "Esse usuário já foi cadastrado"
            });
        }

        const senhaHash = await bcrypt.hash(senha, 12);

        const resultado = await pool.query(
            `INSERT INTO usuarios (nome, email, senha)
             VALUES ($1, $2, $3)
             RETURNING id, nome, email`,
            [nome, email, senhaHash]
        );

        return res.status(201).json({
            usuario: resultado.rows[0],
            msg: "Usuário cadastrado com sucesso"
        });
    } catch (erro) {
        console.error("ERRO NO CADASTRO:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor"
        });
    }
});

// =====================================================
// LOGIN DE USUÁRIOS
// =====================================================

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
             FROM usuarios
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
            throw new Error("CHAVE_TOKEN não configurada");
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
        console.error("ERRO NO LOGIN:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor"
        });
    }
});

// =====================================================
// CONSULTAR USUÁRIO
// =====================================================

app.get("/usuarios/:id", checar_token, async (req, res) => {
    try {
        const { id } = req.params;

        if (!verificarAcesso(req, id)) {
            return res.status(403).json({
                erro: "Acesso negado"
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
                erro: "Usuário não encontrado"
            });
        }

        return res.status(200).json(resultado.rows[0]);
    } catch (erro) {
        console.error("ERRO AO CONSULTAR USUÁRIO:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor"
        });
    }
});

// =====================================================
// ATUALIZAR USUÁRIO
// =====================================================

app.put("/usuarios/:id", checar_token, async (req, res) => {
    try {
        const paramID = Number(req.params.id);

        if (!Number.isInteger(paramID) || paramID <= 0) {
            return res.status(400).json({
                erro: "ID inválido"
            });
        }

        if (!verificarAcesso(req, paramID)) {
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
            `UPDATE usuarios
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
        console.error("ERRO AO ATUALIZAR USUÁRIO:", erro.message);

        if (erro.code === "23505") {
            return res.status(409).json({
                erro: "Esse email já está cadastrado"
            });
        }

        return res.status(500).json({
            erro: "Erro no servidor"
        });
    }
});

// =====================================================
// EXCLUIR USUÁRIO
// =====================================================

app.delete("/usuarios/:id", checar_token, async (req, res) => {
    try {
        const paramID = Number(req.params.id);

        if (!Number.isInteger(paramID) || paramID <= 0) {
            return res.status(400).json({
                erro: "ID inválido"
            });
        }

        if (!verificarAcesso(req, paramID)) {
            return res.status(403).json({
                erro: "Acesso negado"
            });
        }

        const resultado = await pool.query(
            `DELETE FROM usuarios
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
            mensagem: "Usuário excluído com sucesso"
        });
    } catch (erro) {
        console.error("ERRO AO EXCLUIR USUÁRIO:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor"
        });
    }
});

// =====================================================
// CADASTRO DE ADMINISTRADOR
// =====================================================

// ATENÇÃO: esta rota permite criar administradores publicamente.
// Em produção, restrinja o cadastro a administradores autorizados.

app.post("/admin/login", async (req, res) => {
    try {
        const { nome, email, senha } = req.body || {};

        if (!nome || !email || !senha) {
            return res.status(422).json({
                erro: "Nome, email e senha são obrigatórios"
            });
        }

        const admExiste = await pool.query(
            `SELECT id FROM administradores WHERE email = $1`,
            [email]
        );

        if (admExiste.rows.length > 0) {
            return res.status(409).json({
                erro: "Esse administrador já foi cadastrado"
            });
        }

        const senhaHash = await bcrypt.hash(senha, 12);

        const resultado = await pool.query(
            `INSERT INTO administradores (nome, email, senha)
             VALUES ($1, $2, $3)
             RETURNING id, nome, email`,
            [nome, email, senhaHash]
        );

        return res.status(201).json({
            administrador: resultado.rows[0],
            msg: "Administrador cadastrado com sucesso"
        });
    } catch (erro) {
        console.error("ERRO NO CADASTRO DE ADMIN:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor"
        });
    }
});

// =====================================================
// CRUD DE LIVROS
// =====================================================

// CADASTRAR LIVRO

app.post("/livros", async (req, res) => {
    try {
        const { nome, genero } = req.body || {};

        if (!nome || !genero) {
            return res.status(422).json({
                erro: "Nome e gênero são obrigatórios"
            });
        }

        const livroExiste = await pool.query(
            `SELECT id FROM livros WHERE nome = $1`,
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
            livro: resultado.rows[0],
            msg: "Livro inserido com sucesso"
        });
    } catch (erro) {
        console.error("ERRO AO CADASTRAR LIVRO:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor"
        });
    }
});

// LISTAR LIVROS

app.get("/livros", async (req, res) => {
    try {
        const resultado = await pool.query(
            `SELECT * FROM livros ORDER BY id`
        );

        return res.status(200).json(resultado.rows);
    } catch (erro) {
        console.error("ERRO AO LISTAR LIVROS:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor"
        });
    }
});

// ATUALIZAR LIVRO

app.put("/livros/:id", async (req, res) => {
    try {
        const { nome, genero } = req.body || {};
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id <= 0) {
            return res.status(400).json({
                erro: "ID inválido"
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
        console.error("ERRO AO ATUALIZAR LIVRO:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor"
        });
    }
});

// EXCLUIR LIVRO

app.delete("/livros/:id", async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id <= 0) {
            return res.status(400).json({
                erro: "ID inválido"
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

        return res.status(200).json({
            mensagem: "Livro excluído com sucesso",
            livro: resultado.rows[0]
        });
    } catch (erro) {
        console.error("ERRO AO EXCLUIR LIVRO:", erro.message);

        return res.status(500).json({
            erro: "Erro no servidor"
        });
    }
});

// =====================================================
// ALUGUÉIS
// =====================================================

// ATENÇÃO:
// Estas rotas pressupõem uma tabela "alugueis" com as colunas:
// id, usuario_id, livro_id, meses e data_inicio.
// Ajuste os nomes caso seu banco utilize outra estrutura.

// LISTAR ALUGUÉIS DO USUÁRIO AUTENTICADO

app.get("/alugueis", checar_token, async (req, res) => {
    try {
        const usuarioID = Number(req.usuario.id);

        const resultado = await pool.query(
            `SELECT *
             FROM alugueis
             WHERE usuario_id = $1
             ORDER BY id DESC`,
            [usuarioID]
        );

        return res.status(200).json(resultado.rows);
    } catch (erro) {
        console.error("ERRO AO LISTAR ALUGUÉIS:", erro.message);

        if (erro.code === "42P01") {
            return res.status(500).json({
                erro: "A tabela alugueis não existe no banco de dados"
            });
        }

        return res.status(500).json({
            erro: "Erro ao consultar aluguéis"
        });
    }
});

// CADASTRAR ALUGUEL

app.post("/alugueis", checar_token, async (req, res) => {
    try {
        const usuarioID = Number(req.usuario.id);
        const { livro_id, meses } = req.body || {};

        const livroID = Number(livro_id);
        const quantidadeMeses = Number(meses);

        if (
            !Number.isInteger(livroID) ||
            livroID <= 0 ||
            !Number.isInteger(quantidadeMeses) ||
            quantidadeMeses <= 0
        ) {
            return res.status(422).json({
                erro: "Informe um livro válido e a quantidade de meses"
            });
        }

        const livro = await pool.query(
            `SELECT id FROM livros WHERE id = $1`,
            [livroID]
        );

        if (livro.rows.length === 0) {
            return res.status(404).json({
                erro: "Livro não encontrado"
            });
        }

        const resultado = await pool.query(
            `INSERT INTO alugueis
                (usuario_id, livro_id, meses, data_inicio)
             VALUES ($1, $2, $3, CURRENT_DATE)
             RETURNING *`,
            [usuarioID, livroID, quantidadeMeses]
        );

        return res.status(201).json({
            mensagem: "Aluguel cadastrado com sucesso",
            aluguel: resultado.rows[0]
        });
    } catch (erro) {
        console.error("ERRO AO CADASTRAR ALUGUEL:", erro.message);

        if (erro.code === "42P01") {
            return res.status(500).json({
                erro: "A tabela alugueis não existe no banco de dados"
            });
        }

        return res.status(500).json({
            erro: "Erro ao cadastrar aluguel"
        });
    }
});

// =====================================================
// ROTA INICIAL PARA TESTAR A API
// =====================================================

app.get("/", (req, res) => {
    res.status(200).json({
        mensagem: "API do Paginarium funcionando!"
    });
});

// =====================================================
// INICIAR SERVIDOR
// =====================================================

app.listen(porta, () => {
    console.log(`Servidor rodando na porta ${porta}`);
});
