import pool from "./connection";

type IndiceDesejado = {
  tabela: string;
  nome: string;
  // Colunas na ordem do indice. Use "coluna(191)" para indice por prefixo em texto.
  colunas: string[];
};

// Indices usados pelas consultas mais frequentes da API. Sem eles o MySQL percorre
// a tabela inteira a cada busca; em fotos_ponto (com as imagens em LONGBLOB) isso
// deixa lenta cada foto aberta no app e no escritorio.
const INDICES: IndiceDesejado[] = [
  { tabela: "fotos_ponto", nome: "idx_fotos_ponto_caminho", colunas: ["caminho_arquivo(191)"] },
  { tabela: "fotos_ponto", nome: "idx_fotos_ponto_ponto", colunas: ["id_ponto_coletado"] },
  { tabela: "pontos_coletados", nome: "idx_pontos_coletados_solicitacao", colunas: ["id_solicitacao"] },
  { tabela: "pontos_coletados", nome: "idx_pontos_coletados_data", colunas: ["data_coleta"] },
  { tabela: "pontos_rota", nome: "idx_pontos_rota_rota_data", colunas: ["id_rota", "data_hora"] },
  { tabela: "pontos_rota", nome: "idx_pontos_rota_data", colunas: ["data_hora"] },
  { tabela: "rotas_equipe", nome: "idx_rotas_equipe_equipe_data", colunas: ["id_equipe", "data_deslocamento"] },
  { tabela: "solicitacoes", nome: "idx_solicitacoes_equipe", colunas: ["id_equipe"] },
  { tabela: "solicitacoes", nome: "idx_solicitacoes_status", colunas: ["status"] },
];

function nomeColuna(coluna: string) {
  return coluna.replace(/\(.*\)$/, "");
}

/**
 * Cria os indices que ainda nao existem. E idempotente: se ja houver qualquer
 * indice (inclusive o criado por uma chave estrangeira) comecando pelas mesmas
 * colunas, nada e feito. Falhas so geram aviso no log; a API continua no ar.
 * Para desligar, defina DB_AUTO_INDEX=false.
 */
export async function garantirIndices() {
  try {
    const [linhas]: any = await pool.query(
      `
      SELECT TABLE_NAME AS tabela, INDEX_NAME AS indice, SEQ_IN_INDEX AS seq, COLUMN_NAME AS coluna
      FROM information_schema.STATISTICS
      WHERE TABLE_SCHEMA = DATABASE()
      ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX
      `
    );

    const existentes = new Map<string, string[][]>();
    const porIndice = new Map<string, string[]>();

    for (const linha of linhas as Array<{ tabela: string; indice: string; coluna: string }>) {
      const chave = `${linha.tabela}.${linha.indice}`;
      const colunas = porIndice.get(chave) ?? [];
      colunas.push(String(linha.coluna).toLowerCase());
      porIndice.set(chave, colunas);
    }

    for (const [chave, colunas] of porIndice.entries()) {
      const tabela = chave.slice(0, chave.indexOf(".")).toLowerCase();
      const lista = existentes.get(tabela) ?? [];
      lista.push(colunas);
      existentes.set(tabela, lista);
    }

    for (const indice of INDICES) {
      const indicesTabela = existentes.get(indice.tabela.toLowerCase());

      // Tabela inexistente neste banco: ignora.
      if (!indicesTabela && !(await tabelaExiste(indice.tabela))) {
        continue;
      }

      const desejadas = indice.colunas.map((coluna) => nomeColuna(coluna).toLowerCase());
      const jaCoberto = (indicesTabela ?? []).some((colunas) =>
        desejadas.every((coluna, posicao) => colunas[posicao] === coluna)
      );

      if (jaCoberto) {
        continue;
      }

      const montarColunas = (comPrefixo: boolean) =>
        indice.colunas
          .map((coluna) => {
            const nome = nomeColuna(coluna);
            return "`" + nome + "`" + (comPrefixo ? coluna.slice(nome.length) : "");
          })
          .join(", ");
      const criar = (colunasSql: string) =>
        pool.query(
          `ALTER TABLE \`${indice.tabela}\` ADD INDEX \`${indice.nome}\` (${colunasSql}), ALGORITHM=INPLACE, LOCK=NONE`
        );

      try {
        try {
          await criar(montarColunas(true));
        } catch (erroPrefixo) {
          // Coluna VARCHAR menor que o prefixo (ou nao textual): tenta sem prefixo.
          if (!indice.colunas.some((coluna) => coluna.includes("("))) throw erroPrefixo;
          await criar(montarColunas(false));
        }
        console.log(`Indice criado: ${indice.tabela}.${indice.nome}`);
      } catch (error) {
        console.warn(
          `Aviso: nao foi possivel criar o indice ${indice.tabela}.${indice.nome}:`,
          error instanceof Error ? error.message : error
        );
      }
    }
  } catch (error) {
    console.warn(
      "Aviso: verificacao de indices nao executada:",
      error instanceof Error ? error.message : error
    );
  }
}

async function tabelaExiste(tabela: string) {
  const [linhas]: any = await pool.query(
    "SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? LIMIT 1",
    [tabela]
  );
  return linhas.length > 0;
}
