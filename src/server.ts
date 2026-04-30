import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import type { NextFunction, Request, Response } from "express";
import type { ResultSetHeader } from "mysql2";
import pool from "./database/connection";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const uploadsDir = path.resolve(__dirname, "..", "uploads");
const uploadsPontosDir = path.join(uploadsDir, "pontos");
const uploadsSolicitacoesDir = path.join(uploadsDir, "solicitacoes");

type PerfilUsuario = "admin" | "escritorio" | "equipe";

type UsuarioAutenticado = {
  id: number;
  user: string;
  perfil: PerfilUsuario;
  id_equipe: number | null;
};

type TokenPayload = UsuarioAutenticado & {
  exp: number;
};

type RequestAutenticado = Request & {
  usuario?: UsuarioAutenticado;
};

const TOKEN_TTL_SEGUNDOS = 60 * 60 * 12;
const PRESENCA_EQUIPE_TTL_MS = 2 * 60 * 1000;
const AUTH_SECRET =
  process.env.AUTH_SECRET || process.env.JWT_SECRET || process.env.DB_PASSWORD || "fieldpro-dev-secret";
const allowedOrigins = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const presencasEquipe = new Map<number, Map<number, number>>();

function base64Url(valor: string | Buffer) {
  return Buffer.from(valor)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64UrlParaBuffer(valor: string) {
  const base64 = valor.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(base64, "base64");
}

function assinarToken(usuario: UsuarioAutenticado) {
  const header = base64Url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64Url(
    JSON.stringify({
      ...usuario,
      exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SEGUNDOS,
    } satisfies TokenPayload)
  );
  const assinatura = base64Url(
    crypto.createHmac("sha256", AUTH_SECRET).update(`${header}.${payload}`).digest()
  );

  return `${header}.${payload}.${assinatura}`;
}

function verificarToken(token: string): UsuarioAutenticado | null {
  const partes = token.split(".");

  if (partes.length !== 3) {
    return null;
  }

  const [header, payload, assinatura] = partes;
  const assinaturaEsperada = base64Url(
    crypto.createHmac("sha256", AUTH_SECRET).update(`${header}.${payload}`).digest()
  );

  const assinaturaBuffer = Buffer.from(assinatura);
  const assinaturaEsperadaBuffer = Buffer.from(assinaturaEsperada);

  if (
    assinaturaBuffer.length !== assinaturaEsperadaBuffer.length ||
    !crypto.timingSafeEqual(assinaturaBuffer, assinaturaEsperadaBuffer)
  ) {
    return null;
  }

  try {
    const dados = JSON.parse(base64UrlParaBuffer(payload).toString("utf-8")) as TokenPayload;

    if (!dados.exp || dados.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return {
      id: Number(dados.id),
      user: String(dados.user),
      perfil: dados.perfil,
      id_equipe: dados.id_equipe ?? null,
    };
  } catch {
    return null;
  }
}

function criarHashSenha(senha: string) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(senha, salt, 64).toString("hex");

  return `scrypt$${salt}$${hash}`;
}

function senhaEstaComHash(senhaSalva: string) {
  return senhaSalva.startsWith("scrypt$");
}

function conferirSenha(senhaInformada: string, senhaSalva: string) {
  if (!senhaEstaComHash(senhaSalva)) {
    return senhaInformada === senhaSalva;
  }

  const [, salt, hashSalvo] = senhaSalva.split("$");
  const hashInformado = crypto.scryptSync(senhaInformada, salt, 64);
  const hashSalvoBuffer = Buffer.from(hashSalvo, "hex");

  return (
    hashInformado.length === hashSalvoBuffer.length &&
    crypto.timingSafeEqual(hashInformado, hashSalvoBuffer)
  );
}

async function atualizarSenhaLegada(id: number, senhaInformada: string, senhaSalva: string) {
  if (senhaEstaComHash(senhaSalva)) {
    return;
  }

  await pool.query("UPDATE usuarios SET password = ? WHERE id = ?", [
    criarHashSenha(senhaInformada),
    id,
  ]);
}

function obterTokenReq(req: Request) {
  const header = req.header("authorization") || "";

  if (header.toLowerCase().startsWith("bearer ")) {
    return header.slice(7).trim();
  }

  return typeof req.query.token === "string" ? req.query.token : "";
}

function autenticar(req: RequestAutenticado, res: Response, next: NextFunction) {
  const usuario = verificarToken(obterTokenReq(req));

  if (!usuario) {
    return res.status(401).json({ erro: "Autenticacao obrigatoria" });
  }

  req.usuario = usuario;
  next();
}

function autenticarRotasPrivadas(req: RequestAutenticado, res: Response, next: NextFunction) {
  const rotaPublica =
    req.path === "/" ||
    req.path === "/health/db" ||
    (req.method === "POST" && ["/login", "/login-web"].includes(req.path)) ||
    (req.method === "GET" && req.path === "/equipes");

  if (rotaPublica) {
    return next();
  }

  return autenticar(req, res, next);
}

function exigirPerfis(...perfis: PerfilUsuario[]) {
  return (req: RequestAutenticado, res: Response, next: NextFunction) => {
    if (!req.usuario || !perfis.includes(req.usuario.perfil)) {
      return res.status(403).json({ erro: "Acesso nao autorizado" });
    }

    next();
  };
}

const tentativasPorIp = new Map<string, { total: number; resetEm: number }>();

function limitarRequisicoes(req: Request, res: Response, next: NextFunction) {
  const agora = Date.now();
  const ip = req.ip || req.socket.remoteAddress || "desconhecido";
  const limite = req.path.includes("login") ? 30 : 600;
  const janelaMs = 15 * 60 * 1000;
  const atual = tentativasPorIp.get(ip);

  if (!atual || atual.resetEm <= agora) {
    tentativasPorIp.set(ip, { total: 1, resetEm: agora + janelaMs });
    return next();
  }

  atual.total += 1;

  if (atual.total > limite) {
    return res.status(429).json({ erro: "Muitas requisicoes. Tente novamente em alguns minutos." });
  }

  next();
}

function limparPresencasExpiradas(agora = Date.now()) {
  for (const [idEquipe, usuarios] of presencasEquipe.entries()) {
    for (const [idUsuario, ultimoSinal] of usuarios.entries()) {
      if (agora - ultimoSinal > PRESENCA_EQUIPE_TTL_MS) {
        usuarios.delete(idUsuario);
      }
    }

    if (usuarios.size === 0) {
      presencasEquipe.delete(idEquipe);
    }
  }
}

function registrarPresencaEquipe(usuario: UsuarioAutenticado) {
  if (usuario.perfil !== "equipe" || !usuario.id_equipe) {
    return;
  }

  limparPresencasExpiradas();

  const usuarios = presencasEquipe.get(usuario.id_equipe) ?? new Map<number, number>();
  usuarios.set(usuario.id, Date.now());
  presencasEquipe.set(usuario.id_equipe, usuarios);
}

function removerPresencaEquipe(usuario: UsuarioAutenticado) {
  if (usuario.perfil !== "equipe" || !usuario.id_equipe) {
    return;
  }

  const usuarios = presencasEquipe.get(usuario.id_equipe);

  if (!usuarios) {
    return;
  }

  usuarios.delete(usuario.id);

  if (usuarios.size === 0) {
    presencasEquipe.delete(usuario.id_equipe);
  }
}

function equipeEstaOnline(idEquipe: number) {
  limparPresencasExpiradas();
  return (presencasEquipe.get(idEquipe)?.size ?? 0) > 0;
}

function totalEquipesOnline() {
  limparPresencasExpiradas();
  return Array.from(presencasEquipe.values()).filter((usuarios) => usuarios.size > 0).length;
}

app.use((_, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  next();
});

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error("Origem nao permitida pelo CORS"));
    },
  })
);
app.use(limitarRequisicoes);
app.use(express.json({ limit: process.env.JSON_LIMIT || "10mb" }));
app.use("/uploads", autenticar, express.static(uploadsDir));
app.use(autenticarRotasPrivadas);
app.use("/admin", exigirPerfis("admin"));
app.use("/escritorio", exigirPerfis("admin", "escritorio"));

if (!fs.existsSync(uploadsPontosDir)) {
  fs.mkdirSync(uploadsPontosDir, { recursive: true });
}

if (!fs.existsSync(uploadsSolicitacoesDir)) {
  fs.mkdirSync(uploadsSolicitacoesDir, { recursive: true });
}

type FotoUploadPayload = {
  nome: string;
  tipo: string;
  conteudoBase64: string;
};

type SolicitacaoLotePayload = {
  solicitacao: string;
  nome?: string;
  cliente?: string;
  regional?: string;
  municipio?: string;
  prazo?: string | null;
  id_equipe?: number | null;
  equipe?: string | null;
  detalhes?: string | null;
  telefone?: string | null;
  latitude?: string | number | null;
  longitude?: string | number | null;
  prioridade?: "Normal" | "Emergencial" | null;
};

function normalizarTextoComparacao(valor: string | null | undefined) {
  return String(valor ?? "")
    .trim()
    .toLowerCase();
}

function parseCsvLine(linha: string, delimitador: string) {
  const colunas: string[] = [];
  let atual = "";
  let emAspas = false;

  for (let i = 0; i < linha.length; i += 1) {
    const caractere = linha[i];
    const proximo = linha[i + 1];

    if (caractere === '"') {
      if (emAspas && proximo === '"') {
        atual += '"';
        i += 1;
      } else {
        emAspas = !emAspas;
      }
      continue;
    }

    if (caractere === delimitador && !emAspas) {
      colunas.push(atual.trim());
      atual = "";
      continue;
    }

    atual += caractere;
  }

  colunas.push(atual.trim());
  return colunas;
}

function parseCsvTexto(conteudo: string) {
  const linhas = conteudo
    .split(/\r?\n/)
    .map((linha) => linha.trim())
    .filter(Boolean);

  if (linhas.length < 2) {
    throw new Error("A planilha precisa ter cabeçalho e ao menos uma linha.");
  }

  const delimitador =
    (linhas[0].match(/;/g) || []).length >= (linhas[0].match(/,/g) || []).length ? ";" : ",";
  const cabecalhos = parseCsvLine(linhas[0], delimitador).map((cabecalho) =>
    normalizarTextoComparacao(cabecalho)
  );

  return linhas.slice(1).map((linha, indice) => {
    const valores = parseCsvLine(linha, delimitador);
    const registro = cabecalhos.reduce<Record<string, string>>((atual, cabecalho, posicao) => {
      atual[cabecalho] = valores[posicao] ?? "";
      return atual;
    }, {});

    return {
      linha: indice + 2,
      registro,
    };
  });
}

type AnexoUploadPayload = {
  nome: string;
  tipo: string;
  conteudoBase64: string;
};

type AnexoSolicitacao = {
  id: string;
  nome: string;
  tipo: string;
  caminho_arquivo: string;
  criado_em: string;
};

function obterExtensao(nome: string, tipo: string) {
  const extensaoNome = path.extname(nome).toLowerCase();
  const extensoesPermitidas = new Set([".jpg", ".jpeg", ".png", ".webp", ".pdf"]);

  if (extensaoNome && extensoesPermitidas.has(extensaoNome)) {
    return extensaoNome;
  }

  if (tipo === "image/png") {
    return ".png";
  }

  if (tipo === "image/webp") {
    return ".webp";
  }

  if (tipo === "application/pdf") {
    return ".pdf";
  }

  return ".jpg";
}

function normalizarBase64(conteudoBase64: string) {
  const prefixo = ";base64,";

  if (conteudoBase64.includes(prefixo)) {
    return conteudoBase64.split(prefixo)[1] || "";
  }

  return conteudoBase64;
}

function validarUploadBase64(upload: FotoUploadPayload | AnexoUploadPayload) {
  const tamanhoMaximoBytes = Number(process.env.UPLOAD_MAX_BYTES || 5 * 1024 * 1024);
  const tiposPermitidos = new Set(["image/jpeg", "image/jpg", "image/png", "image/webp", "application/pdf"]);

  if (!tiposPermitidos.has(upload.tipo)) {
    throw new Error("Tipo de arquivo nao permitido.");
  }

  const base64 = normalizarBase64(upload.conteudoBase64);
  const tamanhoEstimadoBytes = Math.ceil((base64.length * 3) / 4);

  if (tamanhoEstimadoBytes > tamanhoMaximoBytes) {
    throw new Error("Arquivo maior que o limite permitido.");
  }
}

function removerArquivoSeExistir(caminhoArquivo?: string) {
  if (!caminhoArquivo) {
    return;
  }

  const caminhoRelativo = caminhoArquivo.replace(/^\/+/, "");
  const caminhoCompleto = path.resolve(__dirname, "..", caminhoRelativo);

  if (fs.existsSync(caminhoCompleto)) {
    fs.unlinkSync(caminhoCompleto);
  }
}

function calcularDistanciaKm(
  latitude1: number,
  longitude1: number,
  latitude2: number,
  longitude2: number
) {
  const raioTerraKm = 6371;
  const toRad = (valor: number) => (valor * Math.PI) / 180;
  const diferencaLatitude = toRad(latitude2 - latitude1);
  const diferencaLongitude = toRad(longitude2 - longitude1);
  const a =
    Math.sin(diferencaLatitude / 2) * Math.sin(diferencaLatitude / 2) +
    Math.cos(toRad(latitude1)) *
      Math.cos(toRad(latitude2)) *
      Math.sin(diferencaLongitude / 2) *
      Math.sin(diferencaLongitude / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return raioTerraKm * c;
}

function obterDiretorioSolicitacao(idSolicitacao: number) {
  return path.join(uploadsSolicitacoesDir, String(idSolicitacao));
}

function obterArquivoMetadadosSolicitacao(idSolicitacao: number) {
  return path.join(obterDiretorioSolicitacao(idSolicitacao), "anexos.json");
}

function garantirDiretorioSolicitacao(idSolicitacao: number) {
  const diretorio = obterDiretorioSolicitacao(idSolicitacao);

  if (!fs.existsSync(diretorio)) {
    fs.mkdirSync(diretorio, { recursive: true });
  }

  return diretorio;
}

function lerAnexosSolicitacao(idSolicitacao: number): AnexoSolicitacao[] {
  const arquivoMetadados = obterArquivoMetadadosSolicitacao(idSolicitacao);

  if (!fs.existsSync(arquivoMetadados)) {
    return [];
  }

  try {
    const conteudo = fs.readFileSync(arquivoMetadados, "utf-8");
    const dados = JSON.parse(conteudo) as AnexoSolicitacao[];

    if (!Array.isArray(dados)) {
      return [];
    }

    return dados;
  } catch (error) {
    console.error("Erro ao ler anexos da solicitacao:", error);
    return [];
  }
}

function salvarAnexosSolicitacao(idSolicitacao: number, anexos: AnexoSolicitacao[]) {
  garantirDiretorioSolicitacao(idSolicitacao);
  const arquivoMetadados = obterArquivoMetadadosSolicitacao(idSolicitacao);

  fs.writeFileSync(arquivoMetadados, JSON.stringify(anexos, null, 2), "utf-8");
}

async function buscarSolicitacaoEscritorioPorId(id: number | string) {
  const [rows]: any = await pool.query(
    `
    SELECT
      s.id,
      s.solicitacao,
      s.nome AS cliente,
      s.municipio,
      s.regional,
      s.prazo,
      s.id_equipe,
      e.numero_equipe AS equipe,
      s.detalhes,
      s.telefone,
      s.latitude,
      s.longitude,
      s.prioridade,
      s.data_servico,
      s.status,
      s.created_at,
      s.data_conclusao,
      s.data_finalizacao
    FROM solicitacoes s
    LEFT JOIN equipes e ON s.id_equipe = e.id_equipe
    WHERE s.id = ?
    LIMIT 1
    `,
    [id]
  );

  return rows[0] || null;
}

app.get("/", (req, res) => {
  res.send("API FieldPro funcionando");
});

app.get("/health/db", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch (error) {
    console.error("Erro no healthcheck do banco:", error);
    res.status(500).json({ ok: false, database: "disconnected" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { user, password } = req.body;

    if (!user || !password) {
      return res.status(400).json({ erro: "Informe usuario e senha" });
    }

    const [rows]: any = await pool.query(
      `
      SELECT 
        u.id,
        u.nome_completo,
        u.user,
        u.perfil,
        u.password,
        u.id_equipe,
        e.numero_equipe,
        e.veiculo,
        e.placa,
        e.status
      FROM usuarios u
      LEFT JOIN equipes e ON u.id_equipe = e.id_equipe
      WHERE u.user = ?
      LIMIT 1
      `,
      [user]
    );

    if (rows.length === 0 || !conferirSenha(password, rows[0].password)) {
      return res.status(401).json({ erro: "Usuário ou senha inválidos" });
    }

    const usuario = rows[0];

    if (usuario.perfil !== "equipe") {
      return res.status(403).json({ erro: "Este acesso é somente para equipes" });
    }

    await atualizarSenhaLegada(usuario.id, password, usuario.password);
    delete usuario.password;

    const token = assinarToken({
      id: usuario.id,
      user: usuario.user,
      perfil: usuario.perfil,
      id_equipe: usuario.id_equipe ?? null,
    });

    registrarPresencaEquipe({
      id: usuario.id,
      user: usuario.user,
      perfil: usuario.perfil,
      id_equipe: usuario.id_equipe ?? null,
    });

    res.json({
      mensagem: "Login realizado com sucesso",
      usuario,
      token,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao realizar login" });
  }
});

app.get("/demandas/:id_equipe", async (req, res) => {
  try {
    const { id_equipe } = req.params;

    const [rows]: any = await pool.query(
      `
      SELECT * FROM solicitacoes
      WHERE id_equipe = ?
      ORDER BY id DESC
      `,
      [id_equipe]
    );

    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao buscar demandas" });
  }
});

app.put("/solicitacoes/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body as {
      status?: "Concluida";
    };

    const statusValidos = ["Concluida"];

    if (!status || !statusValidos.includes(status)) {
      return res.status(400).json({ erro: "Status inválido" });
    }

    const [atualRows]: any = await pool.query(
      `
      SELECT id, status
      FROM solicitacoes
      WHERE id = ?
      LIMIT 1
      `,
      [id]
    );

    if (atualRows.length === 0) {
      return res.status(404).json({ erro: "Solicitação não encontrada" });
    }

    const statusAtual = atualRows[0].status as
      | "Andamento"
      | "Concluida"
      | "Devolvida"
      | "Finalizada";

    const transicoesPermitidas: Record<string, string[]> = {
      Andamento: ["Concluida"],
      Concluida: [],
      Devolvida: ["Concluida"],
      Finalizada: [],
    };

    if (!transicoesPermitidas[statusAtual]?.includes(status)) {
      return res.status(400).json({
        erro: `Transição inválida de ${statusAtual} para ${status}`,
      });
    }

    const [resultado]: any = await pool.query(
      `
      UPDATE solicitacoes
      SET status = ?,
          data_conclusao = CASE
            WHEN ? = 'Concluida' THEN NOW()
            ELSE data_conclusao
          END
      WHERE id = ?
      `,
      [status, status, id]
    );

    if (resultado.affectedRows === 0) {
      return res.status(404).json({ erro: "Solicitação não encontrada" });
    }

    const [rows]: any = await pool.query(
      `
      SELECT * FROM solicitacoes
      WHERE id = ?
      LIMIT 1
      `,
      [id]
    );

    res.json({
      mensagem: "Status atualizado com sucesso",
      demanda: rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao atualizar status" });
  }
});

app.put("/solicitacoes/:id/concluir", async (req, res) => {
  try {
    const { id } = req.params;

    const [atualRows]: any = await pool.query(
      `
      SELECT id, status
      FROM solicitacoes
      WHERE id = ?
      LIMIT 1
      `,
      [id]
    );

    if (atualRows.length === 0) {
      return res.status(404).json({ erro: "Solicitação não encontrada" });
    }

    const statusAtual = atualRows[0].status as
      | "Andamento"
      | "Concluida"
      | "Devolvida"
      | "Finalizada";

    if (!["Andamento", "Devolvida"].includes(statusAtual)) {
      return res.status(400).json({
        erro: `Não é possível concluir uma solicitação em ${statusAtual}`,
      });
    }

    const [resultado] = await pool.query<ResultSetHeader>(
      `
      UPDATE solicitacoes
      SET status = 'Concluida',
          data_conclusao = NOW()
      WHERE id = ?
      `,
      [id]
    );

    const [rows]: any = await pool.query(
      `
      SELECT * FROM solicitacoes
      WHERE id = ?
      LIMIT 1
      `,
      [id]
    );

    res.json({
      mensagem: "Solicitação concluída com sucesso",
      demanda: rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao concluir solicitação" });
  }
});
app.get("/equipes", async (req, res) => {
  try {
    const [rows]: any = await pool.query(`
      SELECT 
        id_equipe,
        numero_equipe,
        veiculo,
        placa,
        status
      FROM equipes
    `);

    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao buscar equipes" });
  }
});

app.post("/presenca/equipe", (req: RequestAutenticado, res) => {
  if (!req.usuario || req.usuario.perfil !== "equipe") {
    return res.status(403).json({ erro: "Acesso permitido apenas para equipes" });
  }

  registrarPresencaEquipe(req.usuario);
  res.json({ online: true });
});

app.delete("/presenca/equipe", (req: RequestAutenticado, res) => {
  if (!req.usuario || req.usuario.perfil !== "equipe") {
    return res.status(403).json({ erro: "Acesso permitido apenas para equipes" });
  }

  removerPresencaEquipe(req.usuario);
  res.json({ online: false });
});

app.post("/rota", async (req, res) => {
  const connection = await pool.getConnection();

  try {
    const { id_equipe, latitude, longitude } = req.body;
    const idEquipe = Number(id_equipe);
    const lat = Number(latitude);
    const lng = Number(longitude);

    if (!Number.isFinite(idEquipe) || !Number.isFinite(lat) || !Number.isFinite(lng)) {
      return res.status(400).json({ erro: "Dados do ponto de rota invalidos" });
    }

    await connection.beginTransaction();

    await connection.query(
      `
      INSERT INTO pontos_rota (id_equipe, latitude, longitude, data_hora)
      VALUES (?, ?, ?, NOW())
      `,
      [idEquipe, lat, lng]
    );

    await connection.query(
      `
      UPDATE equipes
      SET ultima_latitude = ?, ultima_longitude = ?
      WHERE id_equipe = ?
      `,
      [lat, lng, idEquipe]
    );

    await connection.commit();

    res.json({ ok: true });
  } catch (error) {
    await connection.rollback();
    console.error(error);
    res.status(500).json({
      erro: error instanceof Error ? error.message : "Erro ao salvar rota",
    });
  } finally {
    connection.release();
  }
});

app.get("/solicitacoes/:id/anexos", async (req, res) => {
  try {
    const { id } = req.params;
    const demandaAtual = await buscarSolicitacaoEscritorioPorId(id);

    if (!demandaAtual) {
      return res.status(404).json({ erro: "Solicitação não encontrada" });
    }

    const anexos = lerAnexosSolicitacao(Number(id)).map((anexo) => ({
      id: anexo.id,
      nome_arquivo: anexo.nome,
      caminho_arquivo: anexo.caminho_arquivo,
      tipo: anexo.tipo,
      criado_em: anexo.criado_em,
    }));

    res.json(anexos);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao carregar anexos da solicitação" });
  }
});

app.post("/pontos-coletados", async (req, res) => {
  const connection = await pool.getConnection();
  const arquivosCriados: string[] = [];

  try {
    const {
      id_solicitacao,
      ordem_ponto,
      latitude,
      longitude,
      observacao,
      fotos,
    } = req.body as {
      id_solicitacao?: number | string;
      ordem_ponto?: number | string;
      latitude?: number | string;
      longitude?: number | string;
      observacao?: string;
      fotos?: FotoUploadPayload[];
    };

    if (!id_solicitacao || !latitude || !longitude) {
      return res.status(400).json({ erro: "Dados do ponto inválidos" });
    }

    if (!Array.isArray(fotos) || fotos.length === 0) {
      return res.status(400).json({ erro: "Envie pelo menos uma foto" });
    }

    const demandaAtual = await buscarSolicitacaoEscritorioPorId(id_solicitacao);

    if (!demandaAtual) {
      return res.status(404).json({
        erro: `Solicitacao ${id_solicitacao} nao encontrada. Atualize as demandas antes de sincronizar.`,
      });
    }

    await connection.beginTransaction();

    const [resultadoPonto]: any = await connection.query(
      `
      INSERT INTO pontos_coletados (
        id_solicitacao,
        ordem_ponto,
        latitude,
        longitude,
        data_coleta,
        observacao
      )
      VALUES (?, ?, ?, ?, NOW(), ?)
      `,
      [
        Number(id_solicitacao),
        Number(ordem_ponto) || 1,
        String(latitude),
        String(longitude),
        observacao || null,
      ]
    );

    const idPontoColetado = resultadoPonto.insertId as number;

    for (const foto of fotos) {
      validarUploadBase64(foto);
      const extensao = obterExtensao(foto.nome, foto.tipo);
      const nomeArquivo = `ponto-${idPontoColetado}-${Date.now()}-${Math.round(
        Math.random() * 100000
      )}${extensao}`;
      const caminhoArquivo = path.join(uploadsPontosDir, nomeArquivo);
      const buffer = Buffer.from(normalizarBase64(foto.conteudoBase64), "base64");

      fs.writeFileSync(caminhoArquivo, buffer);
      arquivosCriados.push(caminhoArquivo);

      await connection.query(
        `
        INSERT INTO fotos_ponto (
          id_ponto_coletado,
          nome_arquivo,
          caminho_arquivo,
          data_foto
        )
        VALUES (?, ?, ?, NOW())
        `,
        [idPontoColetado, nomeArquivo, `/uploads/pontos/${nomeArquivo}`]
      );
    }

    await connection.commit();

    res.status(201).json({
      mensagem: "Ponto salvo com sucesso",
      id_ponto_coletado: idPontoColetado,
    });
  } catch (error) {
    await connection.rollback();
    console.error(error);

    for (const arquivo of arquivosCriados) {
      if (fs.existsSync(arquivo)) {
        fs.unlinkSync(arquivo);
      }
    }

    res.status(500).json({
      erro: error instanceof Error ? error.message : "Erro ao salvar ponto coletado",
    });
  } finally {
    connection.release();
  }
});

app.delete("/fotos/:id", async (req, res) => {
  const connection = await pool.getConnection();

  try {
    const { id } = req.params;

    const [rows]: any = await connection.query(
      `
      SELECT id, caminho_arquivo
      FROM fotos_ponto
      WHERE id = ?
      LIMIT 1
      `,
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ erro: "Foto nao encontrada" });
    }

    const foto = rows[0] as { id: number; caminho_arquivo: string };

    await connection.query(
      `
      DELETE FROM fotos_ponto
      WHERE id = ?
      `,
      [id]
    );

    removerArquivoSeExistir(foto.caminho_arquivo);

    res.json({ mensagem: "Foto excluida com sucesso" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao excluir foto" });
  } finally {
    connection.release();
  }
});

app.delete("/pontos-coletados/:id", async (req, res) => {
  const connection = await pool.getConnection();

  try {
    const { id } = req.params;

    const [pontos]: any = await connection.query(
      `
      SELECT id
      FROM pontos_coletados
      WHERE id = ?
      LIMIT 1
      `,
      [id]
    );

    if (pontos.length === 0) {
      return res.status(404).json({ erro: "Ponto nao encontrado" });
    }

    const [fotos]: any = await connection.query(
      `
      SELECT id, caminho_arquivo
      FROM fotos_ponto
      WHERE id_ponto_coletado = ?
      `,
      [id]
    );

    await connection.beginTransaction();

    await connection.query(
      `
      DELETE FROM fotos_ponto
      WHERE id_ponto_coletado = ?
      `,
      [id]
    );

    await connection.query(
      `
      DELETE FROM pontos_coletados
      WHERE id = ?
      `,
      [id]
    );

    await connection.commit();

    for (const foto of fotos as Array<{ caminho_arquivo: string }>) {
      removerArquivoSeExistir(foto.caminho_arquivo);
    }

    res.json({ mensagem: "Ponto excluido com sucesso" });
  } catch (error) {
    await connection.rollback();
    console.error(error);
    res.status(500).json({ erro: "Erro ao excluir ponto" });
  } finally {
    connection.release();
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});

app.get("/solicitacoes/:id/pontos", async (req, res) => {
  try {
    const { id } = req.params;

    const [pontos]: any = await pool.query(
      `
      SELECT 
        id,
        id_solicitacao,
        ordem_ponto,
        latitude,
        longitude,
        data_coleta,
        observacao
      FROM pontos_coletados
      WHERE id_solicitacao = ?
      ORDER BY data_coleta DESC
      `,
      [id]
    );

    for (const ponto of pontos) {
      const [fotos]: any = await pool.query(
        `
        SELECT 
          id,
          id_ponto_coletado,
          nome_arquivo,
          caminho_arquivo,
          data_foto
        FROM fotos_ponto
        WHERE id_ponto_coletado = ?
        ORDER BY data_foto DESC
        `,
        [ponto.id]
      );

      ponto.fotos = fotos;
    }

    res.json(pontos);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao buscar pontos da solicitação" });
  }
});

app.post("/login-web", async (req, res) => {
  try {
    const { user, senha } = req.body;

    if (!user || !senha) {
      return res.status(400).json({ erro: "Informe usuario e senha" });
    }

    const [rows]: any = await pool.query(
      `
      SELECT 
        id,
        nome_completo,
        user,
        perfil,
        password,
        id_equipe
      FROM usuarios
      WHERE user = ?
      LIMIT 1
      `,
      [user]
    );

    if (rows.length === 0 || !conferirSenha(senha, rows[0].password)) {
      return res.status(401).json({ erro: "Usuário ou senha inválidos" });
    }

    const usuario = rows[0];

    if (usuario.perfil !== "escritorio" && usuario.perfil !== "admin") {
      return res.status(403).json({ erro: "Acesso permitido apenas ao escritório" });
    }

    await atualizarSenhaLegada(usuario.id, senha, usuario.password);
    delete usuario.password;

    const token = assinarToken({
      id: usuario.id,
      user: usuario.user,
      perfil: usuario.perfil,
      id_equipe: usuario.id_equipe ?? null,
    });

    res.json({
      mensagem: "Login realizado com sucesso",
      usuario,
      token,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao realizar login web" });
  }
});

app.get("/admin/usuarios", async (_req, res) => {
  try {
    const [rows]: any = await pool.query(
      `
      SELECT
        u.id,
        u.nome_completo,
        u.user,
        u.perfil,
        u.id_equipe,
        e.numero_equipe AS equipe
      FROM usuarios u
      LEFT JOIN equipes e ON u.id_equipe = e.id_equipe
      ORDER BY u.nome_completo ASC
      `
    );

    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao buscar usuários" });
  }
});

app.post("/admin/usuarios", async (req, res) => {
  try {
    const { nome_completo, user, password, perfil, id_equipe } = req.body;

    if (!nome_completo || !user || !password || !perfil) {
      return res.status(400).json({ erro: "Preencha os dados obrigatorios do usuario" });
    }

    const [resultado] = await pool.query<ResultSetHeader>(
      `
      INSERT INTO usuarios (nome_completo, user, password, perfil, id_equipe)
      VALUES (?, ?, ?, ?, ?)
      `,
      [nome_completo, user, criarHashSenha(password), perfil, id_equipe || null]
    );

    res.status(201).json({ mensagem: "Usuário criado com sucesso" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao criar usuário" });
  }
});

app.put("/admin/usuarios/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { nome_completo, user, perfil, id_equipe } = req.body;

    await pool.query(
      `
      UPDATE usuarios
      SET nome_completo = ?, user = ?, perfil = ?, id_equipe = ?
      WHERE id = ?
      `,
      [nome_completo, user, perfil, id_equipe || null, id]
    );

    res.json({ mensagem: "Usuário atualizado com sucesso" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao atualizar usuário" });
  }
});

app.put("/admin/usuarios/:id/senha", async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ erro: "Informe a nova senha" });
    }

    await pool.query(
      `
      UPDATE usuarios
      SET password = ?
      WHERE id = ?
      `,
      [criarHashSenha(password), id]
    );

    res.json({ mensagem: "Senha alterada com sucesso" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao alterar senha" });
  }
});

app.delete("/admin/usuarios/:id", async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query(
      `
      DELETE FROM usuarios
      WHERE id = ?
      `,
      [id]
    );

    res.json({ mensagem: "Usuário excluído com sucesso" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao excluir usuário" });
  }
});

app.get("/admin/equipes", async (_req, res) => {
  try {
    const [rows]: any = await pool.query(
      `
      SELECT
        id_equipe,
        numero_equipe,
        veiculo,
        placa,
        status
      FROM equipes
      ORDER BY numero_equipe ASC
      `
    );

    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao buscar equipes" });
  }
});

app.post("/admin/equipes", async (req, res) => {
  try {
    const { numero_equipe, veiculo, placa, status } = req.body;

    await pool.query(
      `
      INSERT INTO equipes (numero_equipe, veiculo, placa, status)
      VALUES (?, ?, ?, ?)
      `,
      [numero_equipe, veiculo || null, placa || null, status || "Ativo"]
    );

    res.status(201).json({ mensagem: "Equipe criada com sucesso" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao criar equipe" });
  }
});

app.put("/admin/equipes/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { numero_equipe, veiculo, placa, status } = req.body;

    await pool.query(
      `
      UPDATE equipes
      SET numero_equipe = ?, veiculo = ?, placa = ?, status = ?
      WHERE id_equipe = ?
      `,
      [numero_equipe, veiculo || null, placa || null, status || "Ativo", id]
    );

    res.json({ mensagem: "Equipe atualizada com sucesso" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao atualizar equipe" });
  }
});

app.delete("/admin/equipes/:id", async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query(
      `
      DELETE FROM equipes
      WHERE id_equipe = ?
      `,
      [id]
    );

    res.json({ mensagem: "Equipe excluída com sucesso" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao excluir equipe" });
  }
});

app.get("/escritorio/demandas", async (req, res) => {
  try {
    const [rows]: any = await pool.query(
      `
      SELECT
        s.id,
        s.solicitacao,
        s.nome AS cliente,
        s.municipio,
        s.regional,
        s.prazo,
        s.id_equipe,
        e.numero_equipe AS equipe,
        s.detalhes,
        s.telefone,
        s.latitude,
        s.longitude,
        s.prioridade,
        s.data_servico,
        s.status,
        s.created_at,
        s.data_conclusao,
        s.data_finalizacao,
        COALESCE(pc.total_pontos, 0) AS total_pontos
      FROM solicitacoes s
      LEFT JOIN equipes e ON s.id_equipe = e.id_equipe
      LEFT JOIN (
        SELECT
          id_solicitacao,
          COUNT(*) AS total_pontos
        FROM pontos_coletados
        GROUP BY id_solicitacao
      ) pc ON pc.id_solicitacao = s.id
      ORDER BY s.id DESC
      `
    );

    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao buscar demandas do escritório" });
  }
});

app.get("/escritorio/equipes", async (req, res) => {
  try {
    const [rows]: any = await pool.query(
      `
      SELECT
        id_equipe,
        numero_equipe AS numero,
        veiculo,
        placa,
        status,
        ultima_latitude,
        ultima_longitude
      FROM equipes
      ORDER BY numero_equipe ASC
      `
    );

    res.json(
      rows.map((equipe: any) => ({
        ...equipe,
        online: equipeEstaOnline(Number(equipe.id_equipe)),
      }))
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao buscar equipes" });
  }
});

app.get("/escritorio/dashboard", async (req, res) => {
  try {
    const [andamento]: any = await pool.query(
      `
      SELECT COUNT(*) AS total
      FROM solicitacoes
      WHERE status IN ('Andamento', 'Devolvida')
      `
    );

    const [foraPrazo]: any = await pool.query(
      `
      SELECT COUNT(*) AS total
      FROM solicitacoes
      WHERE prazo < CURDATE()
      AND status <> 'Finalizada'
      `
    );

    const [emergenciais]: any = await pool.query(
      `
      SELECT COUNT(*) AS total
      FROM solicitacoes
      WHERE prioridade = 'Emergencial'
      AND status IN ('Andamento', 'Devolvida')
      `
    );

    res.json({
      andamento: andamento[0].total,
      foraPrazo: foraPrazo[0].total,
      emergenciais: emergenciais[0].total,
      equipesOnline: totalEquipesOnline(),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao carregar dashboard" });
  }
});

app.post("/escritorio/solicitacoes", async (req, res) => {
  try {
    const {
      solicitacao,
      nome,
      regional,
      municipio,
      prazo,
      id_equipe,
      detalhes,
      telefone,
      latitude,
      longitude,
      prioridade,
      data_servico,
    } = req.body;

    const [existente] = await pool.query(
      `
      SELECT id
      FROM solicitacoes
      WHERE LOWER(TRIM(solicitacao)) = LOWER(TRIM(?))
      LIMIT 1
      `,
      [solicitacao]
    );

    if (Array.isArray(existente) && existente.length > 0) {
      return res.status(409).json({ erro: "Nome utilizado. Informe outra solicitação." });
    }

    const [resultado] = await pool.query<ResultSetHeader>(
      `
      INSERT INTO solicitacoes
      (
        solicitacao,
        nome,
        regional,
        municipio,
        prazo,
        id_equipe,
        detalhes,
        telefone,
        latitude,
        longitude,
        prioridade,
        data_servico,
        status
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Andamento')
      `,
      [
        solicitacao,
        nome,
        regional,
        municipio,
        prazo,
        id_equipe,
        detalhes,
        telefone,
        latitude,
        longitude,
        prioridade,
        data_servico,
      ]
    );

    res.json({
      mensagem: "Solicitação criada com sucesso",
      id: resultado.insertId,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao criar solicitação" });
  }
});

app.post("/escritorio/solicitacoes/lote-csv", async (req, res) => {
  try {
    const { conteudo } = req.body as { conteudo?: string };

    if (!conteudo?.trim()) {
      return res.status(400).json({ erro: "Envie o conteúdo da planilha CSV." });
    }

    const linhas = parseCsvTexto(conteudo);
    const [equipesRows] = await pool.query(
      `
      SELECT id_equipe, numero_equipe
      FROM equipes
      `
    );
    const [solicitacoesExistentes] = await pool.query(
      `
      SELECT solicitacao
      FROM solicitacoes
      `
    );

    const equipesPorNome = new Map<string, number>();
    if (Array.isArray(equipesRows)) {
      equipesRows.forEach((equipe: any) => {
        equipesPorNome.set(normalizarTextoComparacao(equipe.numero_equipe), Number(equipe.id_equipe));
      });
    }

    const nomesExistentes = new Set<string>();
    if (Array.isArray(solicitacoesExistentes)) {
      solicitacoesExistentes.forEach((item: any) => {
        nomesExistentes.add(normalizarTextoComparacao(item.solicitacao));
      });
    }

    const importadas: Array<{ linha: number; solicitacao: string }> = [];
    const ignoradas: Array<{ linha: number; motivo: string; solicitacao: string }> = [];

    for (const item of linhas) {
      const registro = item.registro;
      const solicitacao = (
        registro.solicitacao ||
        registro.nota ||
        registro["nome da nota"] ||
        registro["nome_nota"]
      ).trim();

      if (!solicitacao) {
        ignoradas.push({ linha: item.linha, motivo: "Solicitação vazia.", solicitacao: "" });
        continue;
      }

      const chaveSolicitacao = normalizarTextoComparacao(solicitacao);
      if (nomesExistentes.has(chaveSolicitacao)) {
        ignoradas.push({
          linha: item.linha,
          motivo: "Nome utilizado.",
          solicitacao,
        });
        continue;
      }

      const equipeInformada = registro.id_equipe || registro.equipe || registro.numero_equipe;
      let idEquipe: number | null = null;

      if (equipeInformada) {
        const porNumero = Number(equipeInformada);
        if (!Number.isNaN(porNumero) && String(porNumero) === String(equipeInformada).trim()) {
          idEquipe = porNumero;
        } else {
          idEquipe = equipesPorNome.get(normalizarTextoComparacao(equipeInformada)) ?? null;
        }
      }

      const prioridadeTexto = normalizarTextoComparacao(registro.prioridade);
      const prioridade =
        prioridadeTexto === "emergencial" ? "Emergencial" : "Normal";

      await pool.query(
        `
        INSERT INTO solicitacoes
        (
          solicitacao,
          nome,
          regional,
          municipio,
          prazo,
          id_equipe,
          detalhes,
          telefone,
          latitude,
          longitude,
          prioridade,
          data_servico,
          status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'Andamento')
        `,
        [
          solicitacao,
          registro.nome || registro.cliente || "",
          registro.regional || "",
          registro.municipio || "",
          registro.prazo || null,
          idEquipe,
          registro.detalhes || "",
          registro.telefone || "",
          registro.latitude || null,
          registro.longitude || null,
          prioridade,
        ]
      );

      nomesExistentes.add(chaveSolicitacao);
      importadas.push({ linha: item.linha, solicitacao });
    }

    res.json({
      mensagem: "Importação concluída.",
      importadas,
      ignoradas,
      totalImportadas: importadas.length,
      totalIgnoradas: ignoradas.length,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: error instanceof Error ? error.message : "Erro ao importar planilha." });
  }
});

app.put("/escritorio/solicitacoes/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const {
      solicitacao,
      cliente,
      regional,
      municipio,
      prazo,
      id_equipe,
      detalhes,
      telefone,
      latitude,
      longitude,
      prioridade,
      data_servico,
      status,
    } = req.body as {
      solicitacao?: string;
      cliente?: string;
      regional?: string;
      municipio?: string;
      prazo?: string;
      id_equipe?: number | string | null;
      detalhes?: string;
      telefone?: string;
      latitude?: number | string | null;
      longitude?: number | string | null;
      prioridade?: "Normal" | "Emergencial";
      data_servico?: string | null;
      status?: "Andamento" | "Concluida" | "Devolvida" | "Finalizada";
    };

    const demandaAtual = await buscarSolicitacaoEscritorioPorId(id);

    if (!demandaAtual) {
      return res.status(404).json({ erro: "Solicitação não encontrada" });
    }

    await pool.query(
      `
      UPDATE solicitacoes
      SET
        solicitacao = ?,
        nome = ?,
        regional = ?,
        municipio = ?,
        prazo = ?,
        id_equipe = ?,
        detalhes = ?,
        telefone = ?,
        latitude = ?,
        longitude = ?,
        prioridade = ?,
        data_servico = ?,
        status = ?
      WHERE id = ?
      `,
      [
        solicitacao ?? demandaAtual.solicitacao,
        cliente ?? demandaAtual.cliente,
        regional ?? demandaAtual.regional,
        municipio ?? demandaAtual.municipio,
        prazo ?? demandaAtual.prazo,
        id_equipe ?? demandaAtual.id_equipe,
        detalhes ?? demandaAtual.detalhes,
        telefone ?? demandaAtual.telefone,
        latitude ?? demandaAtual.latitude,
        longitude ?? demandaAtual.longitude,
        prioridade ?? demandaAtual.prioridade,
        data_servico ?? demandaAtual.data_servico,
        status ?? demandaAtual.status,
        id,
      ]
    );

    const demanda = await buscarSolicitacaoEscritorioPorId(id);

    res.json({
      mensagem: "Solicitação atualizada com sucesso",
      demanda,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao atualizar solicitação" });
  }
});

app.delete("/escritorio/solicitacoes/:id", async (req, res) => {
  const connection = await pool.getConnection();

  try {
    const { id } = req.params;
    const idSolicitacao = Number(id);

    const demandaAtual = await buscarSolicitacaoEscritorioPorId(idSolicitacao);

    if (!demandaAtual) {
      return res.status(404).json({ erro: "Solicitação não encontrada" });
    }

    const anexos = lerAnexosSolicitacao(idSolicitacao);

    const [pontos]: any = await connection.query(
      `
      SELECT id
      FROM pontos_coletados
      WHERE id_solicitacao = ?
      `,
      [idSolicitacao]
    );

    const idsPontos = (pontos as Array<{ id: number }>).map((ponto) => ponto.id);

    let fotos: Array<{ caminho_arquivo: string }> = [];

    if (idsPontos.length > 0) {
      const placeholders = idsPontos.map(() => "?").join(", ");
      const [fotosRows]: any = await connection.query(
        `
        SELECT caminho_arquivo
        FROM fotos_ponto
        WHERE id_ponto_coletado IN (${placeholders})
        `,
        idsPontos
      );

      fotos = fotosRows;
    }

    await connection.beginTransaction();

    if (idsPontos.length > 0) {
      const placeholders = idsPontos.map(() => "?").join(", ");

      await connection.query(
        `
        DELETE FROM fotos_ponto
        WHERE id_ponto_coletado IN (${placeholders})
        `,
        idsPontos
      );

      await connection.query(
        `
        DELETE FROM pontos_coletados
        WHERE id IN (${placeholders})
        `,
        idsPontos
      );
    }

    await connection.query(
      `
      DELETE FROM solicitacoes
      WHERE id = ?
      `,
      [idSolicitacao]
    );

    await connection.commit();

    for (const foto of fotos) {
      removerArquivoSeExistir(foto.caminho_arquivo);
    }

    for (const anexo of anexos) {
      removerArquivoSeExistir(anexo.caminho_arquivo);
    }

    const diretorioSolicitacao = obterDiretorioSolicitacao(idSolicitacao);

    if (fs.existsSync(diretorioSolicitacao)) {
      fs.rmSync(diretorioSolicitacao, { recursive: true, force: true });
    }

    res.json({ mensagem: "Solicitação excluída com sucesso" });
  } catch (error) {
    await connection.rollback();
    console.error(error);
    res.status(500).json({ erro: "Erro ao excluir solicitação" });
  } finally {
    connection.release();
  }
});

app.get("/escritorio/solicitacoes/:id/anexos", async (req, res) => {
  try {
    const { id } = req.params;
    const demandaAtual = await buscarSolicitacaoEscritorioPorId(id);

    if (!demandaAtual) {
      return res.status(404).json({ erro: "Solicitação não encontrada" });
    }

    res.json(lerAnexosSolicitacao(Number(id)));
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao carregar anexos" });
  }
});

app.post("/escritorio/solicitacoes/:id/anexos", async (req, res) => {
  try {
    const { id } = req.params;
    const idSolicitacao = Number(id);
    const { anexos } = req.body as {
      anexos?: AnexoUploadPayload[];
    };

    const demandaAtual = await buscarSolicitacaoEscritorioPorId(idSolicitacao);

    if (!demandaAtual) {
      return res.status(404).json({ erro: "Solicitação não encontrada" });
    }

    if (!Array.isArray(anexos) || anexos.length === 0) {
      return res.status(400).json({ erro: "Envie pelo menos um anexo" });
    }

    const anexosAtuais = lerAnexosSolicitacao(idSolicitacao);
    const diretorioSolicitacao = garantirDiretorioSolicitacao(idSolicitacao);

    const novosAnexos = anexos.map((anexo) => {
      validarUploadBase64(anexo);
      const extensao = obterExtensao(anexo.nome, anexo.tipo);
      const idAnexo = `anexo-${Date.now()}-${Math.round(Math.random() * 100000)}`;
      const nomeArquivo = `${idAnexo}${extensao}`;
      const caminhoArquivo = path.join(diretorioSolicitacao, nomeArquivo);

      fs.writeFileSync(
        caminhoArquivo,
        Buffer.from(normalizarBase64(anexo.conteudoBase64), "base64")
      );

      return {
        id: idAnexo,
        nome: anexo.nome,
        tipo: anexo.tipo,
        caminho_arquivo: `/uploads/solicitacoes/${idSolicitacao}/${nomeArquivo}`,
        criado_em: new Date().toISOString(),
      } satisfies AnexoSolicitacao;
    });

    const listaFinal = [...anexosAtuais, ...novosAnexos];
    salvarAnexosSolicitacao(idSolicitacao, listaFinal);

    res.status(201).json({
      mensagem: "Anexos adicionados com sucesso",
      anexos: listaFinal,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao salvar anexos" });
  }
});

app.delete("/escritorio/solicitacoes/:id/anexos/:anexoId", async (req, res) => {
  try {
    const { id, anexoId } = req.params;
    const idSolicitacao = Number(id);
    const anexosAtuais = lerAnexosSolicitacao(idSolicitacao);
    const anexo = anexosAtuais.find((item) => item.id === anexoId);

    if (!anexo) {
      return res.status(404).json({ erro: "Anexo não encontrado" });
    }

    const anexosRestantes = anexosAtuais.filter((item) => item.id !== anexoId);
    salvarAnexosSolicitacao(idSolicitacao, anexosRestantes);
    removerArquivoSeExistir(anexo.caminho_arquivo);

    res.json({
      mensagem: "Anexo excluído com sucesso",
      anexos: anexosRestantes,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao excluir anexo" });
  }
});

app.put("/escritorio/solicitacoes/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body as {
      status?: "Finalizada" | "Devolvida";
    };

    const statusValidos = ["Finalizada", "Devolvida"];

    if (!status || !statusValidos.includes(status)) {
      return res.status(400).json({ erro: "Status inválido para o escritório" });
    }

    const [atualRows]: any = await pool.query(
      `
      SELECT id, status
      FROM solicitacoes
      WHERE id = ?
      LIMIT 1
      `,
      [id]
    );

    if (atualRows.length === 0) {
      return res.status(404).json({ erro: "Solicitação não encontrada" });
    }

    const statusAtual = atualRows[0].status as
      | "Andamento"
      | "Concluida"
      | "Devolvida"
      | "Finalizada";

    const transicoesPermitidas: Record<string, string[]> = {
      Andamento: [],
      Concluida: ["Finalizada", "Devolvida"],
      Devolvida: [],
      Finalizada: [],
    };

    if (!transicoesPermitidas[statusAtual]?.includes(status)) {
      return res.status(400).json({
        erro: `Transição inválida de ${statusAtual} para ${status}`,
      });
    }

    await pool.query(
      `
      UPDATE solicitacoes
      SET status = ?,
          data_finalizacao = CASE
            WHEN ? = 'Finalizada' THEN NOW()
            ELSE data_finalizacao
          END
      WHERE id = ?
      `,
      [status, status, id]
    );

    const [rows]: any = await pool.query(
      `
      SELECT * FROM solicitacoes
      WHERE id = ?
      LIMIT 1
      `,
      [id]
    );

    res.json({
      mensagem: "Status atualizado com sucesso",
      demanda: rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao atualizar status da solicitação" });
  }
});

app.get("/escritorio/producao", async (req, res) => {
  try {
    const { data_inicial, data_final } = req.query as {
      data_inicial?: string;
      data_final?: string;
    };

    const [equipesRows]: any = await pool.query(
      `
      SELECT
        e.numero_equipe AS equipe,
        e.id_equipe,
        e.veiculo,
        e.placa,
        CASE
          WHEN e.status = 'Ativo' THEN 'Online'
          ELSE 'Offline'
        END AS status
      FROM equipes e
      ORDER BY e.numero_equipe ASC
      `
    );

    const filtrosRota: string[] = [];
    const parametrosRota: string[] = [];

    if (data_inicial) {
      filtrosRota.push("pr.data_hora >= ?");
      parametrosRota.push(data_inicial);
    }

    if (data_final) {
      filtrosRota.push("pr.data_hora < DATE_ADD(?, INTERVAL 1 DAY)");
      parametrosRota.push(data_final);
    }

    const whereRota = filtrosRota.length > 0 ? `WHERE ${filtrosRota.join(" AND ")}` : "";

    let rotasRows: any[] = [];

    try {
      const [rotasResultado]: any = await pool.query(
        `
        SELECT pr.id_equipe, pr.latitude, pr.longitude, pr.data_hora
        FROM pontos_rota pr
        ${whereRota}
        ORDER BY pr.id_equipe ASC, pr.data_hora ASC
        `,
        parametrosRota
      );

      rotasRows = rotasResultado;
    } catch (error) {
      console.error("Aviso ao carregar rotas da produção:", error);
      rotasRows = [];
    }

    const filtrosPontos: string[] = [];
    const parametrosPontos: string[] = [];

    if (data_inicial) {
      filtrosPontos.push("pc.data_coleta >= ?");
      parametrosPontos.push(data_inicial);
    }

    if (data_final) {
      filtrosPontos.push("pc.data_coleta < DATE_ADD(?, INTERVAL 1 DAY)");
      parametrosPontos.push(data_final);
    }

    const wherePontos =
      filtrosPontos.length > 0 ? `WHERE ${filtrosPontos.join(" AND ")}` : "";

    let pontosRows: any[] = [];

    try {
      const [pontosResultado]: any = await pool.query(
        `
        SELECT
          s.id_equipe,
          COUNT(pc.id) AS total_pontos
        FROM solicitacoes s
        LEFT JOIN pontos_coletados pc ON pc.id_solicitacao = s.id
        ${wherePontos}
        GROUP BY s.id_equipe
        `,
        parametrosPontos
      );

      pontosRows = pontosResultado;
    } catch (error) {
      console.error("Aviso ao carregar pontos da produção:", error);
      pontosRows = [];
    }

    const filtrosNotas: string[] = ["s.status IN ('Concluida', 'Finalizada')"];
    const parametrosNotas: string[] = [];

    if (data_inicial) {
      filtrosNotas.push("COALESCE(s.data_finalizacao, s.data_conclusao) >= ?");
      parametrosNotas.push(data_inicial);
    }

    if (data_final) {
      filtrosNotas.push("COALESCE(s.data_finalizacao, s.data_conclusao) < DATE_ADD(?, INTERVAL 1 DAY)");
      parametrosNotas.push(data_final);
    }

    let notasRows: any[] = [];

    try {
      const [notasResultado]: any = await pool.query(
        `
        SELECT
          s.id_equipe,
          COUNT(*) AS total_notas
        FROM solicitacoes s
        WHERE ${filtrosNotas.join(" AND ")}
        GROUP BY s.id_equipe
        `,
        parametrosNotas
      );

      notasRows = notasResultado;
    } catch (error) {
      console.error("Aviso ao carregar notas da produção:", error);
      notasRows = [];
    }

    const rotasPorEquipe = new Map<number, Array<{ latitude: number; longitude: number }>>();
    const pontosPorEquipe = new Map<number, number>();
    const notasPorEquipe = new Map<number, number>();

    (rotasRows as Array<{ id_equipe: number; latitude: number | string; longitude: number | string }>)
      .forEach((row) => {
        const idEquipe = Number(row.id_equipe);
        const latitude = Number(row.latitude);
        const longitude = Number(row.longitude);

        if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
          return;
        }

        const rotaAtual = rotasPorEquipe.get(idEquipe) || [];
        rotaAtual.push({ latitude, longitude });
        rotasPorEquipe.set(idEquipe, rotaAtual);
      });

    (pontosRows as Array<{ id_equipe: number; total_pontos: number | string }>).forEach((row) => {
      pontosPorEquipe.set(Number(row.id_equipe), Number(row.total_pontos) || 0);
    });

    (notasRows as Array<{ id_equipe: number; total_notas: number | string }>).forEach((row) => {
      notasPorEquipe.set(Number(row.id_equipe), Number(row.total_notas) || 0);
    });

    const resposta = (equipesRows as Array<{
      id_equipe: number;
      equipe: string;
      veiculo: string | null;
      placa: string | null;
      status: string;
    }>).map((equipe) => {
      const rotaEquipe = rotasPorEquipe.get(Number(equipe.id_equipe)) || [];
      let km = 0;

      for (let index = 1; index < rotaEquipe.length; index += 1) {
        km += calcularDistanciaKm(
          rotaEquipe[index - 1].latitude,
          rotaEquipe[index - 1].longitude,
          rotaEquipe[index].latitude,
          rotaEquipe[index].longitude
        );
      }

      return {
        ...equipe,
        km: Number(km.toFixed(2)),
        pontos: pontosPorEquipe.get(Number(equipe.id_equipe)) || 0,
        notas: notasPorEquipe.get(Number(equipe.id_equipe)) || 0,
      };
    });

    res.json(resposta);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao buscar produção" });
  }
});

app.get("/escritorio/rota", async (req, res) => {
  try {
    const { id_equipe, data_inicial, data_final } = req.query as {
      id_equipe?: string;
      data_inicial?: string;
      data_final?: string;
    };

    let equipeId = Number(id_equipe);

    if (!Number.isFinite(equipeId) || equipeId <= 0) {
      const [equipesAtivas]: any = await pool.query(
        `
        SELECT id_equipe
        FROM equipes
        WHERE status = 'Ativo'
        ORDER BY numero_equipe ASC
        LIMIT 1
        `
      );

      if (equipesAtivas.length === 0) {
        return res.json([]);
      }

      equipeId = Number(equipesAtivas[0].id_equipe);
    }

    const filtrosRota = ["id_equipe = ?"];
    const parametrosRota: Array<number | string> = [equipeId];

    if (data_inicial) {
      filtrosRota.push("data_hora >= ?");
      parametrosRota.push(data_inicial);
    }

    if (data_final) {
      filtrosRota.push("data_hora < DATE_ADD(?, INTERVAL 1 DAY)");
      parametrosRota.push(data_final);
    }

    let rows: any[] = [];

    try {
      const [rotaRows]: any = await pool.query(
        `
        SELECT latitude, longitude, data_hora
        FROM pontos_rota
        WHERE ${filtrosRota.join(" AND ")}
        ORDER BY data_hora ASC
        LIMIT 500
        `,
        parametrosRota
      );

      rows = rotaRows;
    } catch (error) {
      console.error("Aviso ao carregar rota do escritório:", error);
      rows = [];
    }

    const rota = rows
      .map((row: { latitude: number | string; longitude: number | string }) => {
        const latitude = Number(row.latitude);
        const longitude = Number(row.longitude);

        if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
          return null;
        }

        return [latitude, longitude];
      })
      .filter(Boolean);

    res.json(rota);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao buscar rota da equipe" });
  }
});

app.get("/api/demandas", async (req, res) => {
  const [rows] = await pool.query("SELECT * FROM demandas");
  res.json(rows);
});

app.use((error: Error & { type?: string; status?: number }, _req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) {
    return next(error);
  }

  if (error.type === "entity.too.large" || error.status === 413) {
    return res.status(413).json({
      erro: "Fotos muito grandes para envio. Tente coletar menos fotos neste ponto.",
    });
  }

  console.error(error);
  return res.status(500).json({ erro: "Erro interno do servidor" });
});
