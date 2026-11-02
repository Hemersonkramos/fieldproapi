// Cria (ou atualiza a senha de) dois usuarios de teste para o TCC/demonstracao:
// um do escritorio e um da equipe EPI01. Le usuario/senha de ../../usuarios-teste.txt.
// Uso, na pasta fieldpro-api:  node scripts/criar-usuarios-teste.cjs
require('dotenv').config({ quiet: true });
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise');

function hashSenha(senha) {
  // Mesmo formato da API (server.ts > criarHashSenha)
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(senha, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function lerCredenciais() {
  const texto = fs.readFileSync(path.join(__dirname, '..', '..', 'usuarios-teste.txt'), 'utf8');
  const linha = (rotulo) => {
    const achado = texto.split(/\r?\n/).find((l) => l.startsWith(rotulo));
    if (!achado) throw new Error(`Linha "${rotulo}" nao encontrada em usuarios-teste.txt`);
    const [user, senha] = achado.slice(achado.indexOf(':') + 1).split('/').map((v) => v.trim());
    return { user, senha };
  };
  return { escritorio: linha('Web (escritorio)'), equipe: linha('App (equipe EPI01)') };
}

async function main() {
  const cred = lerCredenciais();
  const ssl = ['true', 'required'].includes(process.env.DB_SSL);
  const conexao = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: ssl ? { rejectUnauthorized: true } : undefined,
  });

  try {
    const [equipes] = await conexao.query("SELECT id_equipe FROM equipes WHERE numero_equipe = 'EPI01' LIMIT 1");
    const idEquipe = equipes[0]?.id_equipe ?? null;
    if (!idEquipe) console.warn('Aviso: equipe EPI01 nao encontrada; o usuario de equipe ficara sem equipe.');

    const usuarios = [
      { nome: 'Teste Escritorio (TCC)', ...cred.escritorio, perfil: 'escritorio', idEquipe: null },
      { nome: 'Teste Equipe EPI01 (TCC)', ...cred.equipe, perfil: 'equipe', idEquipe },
    ];

    for (const u of usuarios) {
      const [existentes] = await conexao.query('SELECT id FROM usuarios WHERE user = ? LIMIT 1', [u.user]);
      if (existentes.length > 0) {
        await conexao.query(
          'UPDATE usuarios SET nome_completo = ?, password = ?, perfil = ?, id_equipe = ? WHERE id = ?',
          [u.nome, hashSenha(u.senha), u.perfil, u.idEquipe, existentes[0].id]
        );
        console.log(`Atualizado: ${u.user} (${u.perfil})`);
      } else {
        await conexao.query(
          'INSERT INTO usuarios (nome_completo, user, password, perfil, id_equipe) VALUES (?, ?, ?, ?, ?)',
          [u.nome, u.user, hashSenha(u.senha), u.perfil, u.idEquipe]
        );
        console.log(`Criado: ${u.user} (${u.perfil})`);
      }
    }
  } finally {
    await conexao.end();
  }
}

main().catch((erro) => {
  console.error('Erro:', erro.message);
  process.exit(1);
});
