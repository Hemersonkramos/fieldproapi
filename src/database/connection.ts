import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

const usarSsl = process.env.DB_SSL === "true" || process.env.DB_SSL === "required";

const connection = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT || 3306),
  ssl: usarSsl ? { rejectUnauthorized: true } : undefined,
});

export default connection;
