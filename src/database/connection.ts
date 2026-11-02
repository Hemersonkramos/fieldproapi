import fs from "fs";
import mysql from "mysql2";
import dotenv from "dotenv";

dotenv.config();

const usarSsl = process.env.DB_SSL === "true" || process.env.DB_SSL === "required";

// Certificado CA do Aiven (opcional): conteudo PEM em DB_SSL_CA ou caminho em DB_SSL_CA_PATH.
// Mesmo comportamento do script scripts/persistir-fotos.cjs.
function obterCaSsl() {
  if (process.env.DB_SSL_CA) {
    return process.env.DB_SSL_CA.replace(/\\n/g, "\n");
  }

  if (process.env.DB_SSL_CA_PATH) {
    return fs.readFileSync(process.env.DB_SSL_CA_PATH, "utf-8");
  }

  return undefined;
}

const caSsl = usarSsl ? obterCaSsl() : undefined;

const connection = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT || 3306),
  // DATETIME do projeto representa o horario de Brasilia, nao UTC.
  timezone: "-03:00",
  ssl: usarSsl ? { rejectUnauthorized: true, ...(caSsl ? { ca: caSsl } : {}) } : undefined,
  connectionLimit: Number(process.env.DB_POOL_LIMIT || 10),
  // Bancos gerenciados (Aiven) encerram conexoes ociosas. Mantendo as conexoes
  // vivas e descartando as paradas ha muito tempo, a primeira requisicao depois de
  // um periodo sem uso nao precisa esperar um novo handshake TLS nem falhar com ECONNRESET.
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,
  maxIdle: Number(process.env.DB_POOL_MAX_IDLE || 4),
  idleTimeout: 5 * 60 * 1000,
  connectTimeout: 15000,
});

connection.on("connection", (session) => {
  session.query("SET time_zone = '-03:00'", (error) => {
    if (error) session.destroy();
  });
});

export default connection.promise();
