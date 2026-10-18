// Execute antes de publicar: node scripts/persistir-fotos.cjs
require('dotenv').config({ quiet: true });
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

async function main() {
  const ssl = ['true', 'required'].includes(process.env.DB_SSL);
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: ssl ? {
      rejectUnauthorized: true,
      ...(process.env.DB_SSL_CA_PATH ? { ca: fs.readFileSync(process.env.DB_SSL_CA_PATH) } : {}),
    } : undefined,
  });
  try {
    const [columns] = await connection.query('SHOW COLUMNS FROM fotos_ponto');
    const additions = [];
    if (!columns.some(c => c.Field === 'conteudo')) additions.push('ADD COLUMN conteudo LONGBLOB NULL');
    if (!columns.some(c => c.Field === 'tipo_arquivo')) additions.push('ADD COLUMN tipo_arquivo VARCHAR(100) NULL');
    if (additions.length) await connection.query('ALTER TABLE fotos_ponto ' + additions.join(', '));
    const [photos] = await connection.query('SELECT id, nome_arquivo FROM fotos_ponto WHERE conteudo IS NULL');
    const types = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.pdf': 'application/pdf' };
    let recovered = 0;
    for (const photo of photos) {
      const file = path.join(__dirname, '../uploads/pontos', path.basename(photo.nome_arquivo));
      if (!fs.existsSync(file)) continue;
      await connection.query('UPDATE fotos_ponto SET conteudo=?, tipo_arquivo=? WHERE id=? AND conteudo IS NULL',
        [fs.readFileSync(file), types[path.extname(file).toLowerCase()] || 'application/octet-stream', photo.id]);
      recovered++;
    }
    console.log(JSON.stringify({ recovered, missingFiles: photos.length - recovered }));
  } finally {
    await connection.end();
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
