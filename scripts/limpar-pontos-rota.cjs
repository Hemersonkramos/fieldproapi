// Remove pontos de rota (trajeto GPS das equipes, tabela pontos_rota) registrados
// FORA de um dia escolhido. Por padrao so mostra o que seria apagado (simulacao).
//
// Uso, na pasta fieldpro-api:
//   node scripts/limpar-pontos-rota.cjs --manter-dia=2026-10-18              (simulacao, nao apaga)
//   node scripts/limpar-pontos-rota.cjs --manter-dia=2026-10-18 --confirmar  (apaga, com backup antes)
//
// Antes de apagar, grava um backup JSON em ../backups/ com todos os registros
// removidos (pontos e rotas que ficarem vazias), para poder restaurar se preciso.
// Pontos sem data (data_hora nulo) NAO sao apagados.
require('dotenv').config({ quiet: true });
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

const argumentos = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const [chave, valor] = a.replace(/^--/, '').split('=');
    return [chave, valor ?? true];
  })
);

const dia = String(argumentos['manter-dia'] || '');
const confirmar = argumentos.confirmar === true;

if (!/^\d{4}-\d{2}-\d{2}$/.test(dia)) {
  console.error('Informe o dia a manter no formato AAAA-MM-DD, ex.: --manter-dia=2026-10-18');
  process.exit(1);
}

function conectar() {
  const ssl = ['true', 'required'].includes(process.env.DB_SSL);
  const ca = process.env.DB_SSL_CA
    ? process.env.DB_SSL_CA.replace(/\\n/g, '\n')
    : process.env.DB_SSL_CA_PATH
      ? fs.readFileSync(process.env.DB_SSL_CA_PATH, 'utf8')
      : undefined;
  return mysql.createConnection({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    // DATETIME do projeto e horario de Brasilia: compara a data como esta gravada.
    timezone: '-03:00',
    dateStrings: true,
    ssl: ssl ? { rejectUnauthorized: true, ...(ca ? { ca } : {}) } : undefined,
  });
}

async function main() {
  const conexao = await conectar();
  console.log(`Banco: ${process.env.DB_NAME} em ${process.env.DB_HOST}`);
  console.log(`Dia mantido: ${dia}\n`);

  try {
    const [porDia] = await conexao.query(
      `SELECT DATE(pr.data_hora) AS dia, e.numero_equipe AS equipe, COUNT(*) AS pontos
       FROM pontos_rota pr
       JOIN rotas_equipe re ON re.id = pr.id_rota
       LEFT JOIN equipes e ON e.id_equipe = re.id_equipe
       GROUP BY DATE(pr.data_hora), e.numero_equipe
       ORDER BY dia, equipe`
    );

    console.log('Pontos de rota por dia e equipe:');
    for (const linha of porDia) {
      const marca = linha.dia === dia ? 'MANTER' : linha.dia === null ? 'sem data (mantido)' : 'APAGAR';
      console.log(`  ${linha.dia ?? '----------'}  ${String(linha.equipe ?? '-').padEnd(10)} ${String(linha.pontos).padStart(6)}  ${marca}`);
    }

    const [pontosApagar] = await conexao.query(
      'SELECT * FROM pontos_rota WHERE data_hora IS NOT NULL AND DATE(data_hora) <> ? ORDER BY id',
      [dia]
    );
    const [[{ mantidos }]] = await conexao.query(
      'SELECT COUNT(*) AS mantidos FROM pontos_rota WHERE data_hora IS NULL OR DATE(data_hora) = ?',
      [dia]
    );

    // Rotas que ficariam sem nenhum ponto depois da limpeza.
    const [rotasVazias] = await conexao.query(
      `SELECT re.* FROM rotas_equipe re
       WHERE NOT EXISTS (
         SELECT 1 FROM pontos_rota pr
         WHERE pr.id_rota = re.id AND (pr.data_hora IS NULL OR DATE(pr.data_hora) = ?)
       )
       ORDER BY re.id`,
      [dia]
    );

    console.log(`\nSerao apagados: ${pontosApagar.length} ponto(s) de rota e ${rotasVazias.length} rota(s) que ficariam vazias.`);
    console.log(`Permanecem: ${mantidos} ponto(s).`);

    if (!confirmar) {
      console.log('\nSIMULACAO: nada foi apagado. Para apagar, rode de novo com --confirmar');
      return;
    }

    if (pontosApagar.length === 0 && rotasVazias.length === 0) {
      console.log('\nNada a apagar.');
      return;
    }

    const pastaBackup = path.join(__dirname, '..', '..', 'backups');
    fs.mkdirSync(pastaBackup, { recursive: true });
    const carimbo = new Date().toISOString().replace(/[:.]/g, '-');
    const arquivoBackup = path.join(pastaBackup, `pontos-rota-antes-limpeza-${carimbo}.json`);
    fs.writeFileSync(
      arquivoBackup,
      JSON.stringify({ banco: process.env.DB_NAME, diaMantido: dia, criadoEm: new Date().toISOString(), pontos_rota: pontosApagar, rotas_equipe: rotasVazias }, null, 2)
    );
    console.log(`\nBackup salvo em: ${arquivoBackup}`);

    await conexao.beginTransaction();
    const [resultadoPontos] = await conexao.query(
      'DELETE FROM pontos_rota WHERE data_hora IS NOT NULL AND DATE(data_hora) <> ?',
      [dia]
    );
    const idsRotasVazias = rotasVazias.map((rota) => rota.id);
    let rotasRemovidas = 0;
    if (idsRotasVazias.length > 0) {
      const [resultadoRotas] = await conexao.query('DELETE FROM rotas_equipe WHERE id IN (?)', [idsRotasVazias]);
      rotasRemovidas = resultadoRotas.affectedRows;
    }
    // Atualiza o contador de pontos das rotas que continuam.
    await conexao.query(
      `UPDATE rotas_equipe re
       SET quantidade_pontos = (SELECT COUNT(*) FROM pontos_rota pr WHERE pr.id_rota = re.id)`
    );
    await conexao.commit();

    console.log(`Apagados: ${resultadoPontos.affectedRows} ponto(s) de rota e ${rotasRemovidas} rota(s) vazia(s).`);
  } catch (erro) {
    try {
      await conexao.rollback();
    } catch {
      // sem transacao aberta
    }
    throw erro;
  } finally {
    await conexao.end();
  }
}

main().catch((erro) => {
  console.error('Erro:', erro.message);
  process.exit(1);
});
