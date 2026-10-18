# Persistencia das fotos de levantamento

Antes do primeiro deploy desta versao, execute na pasta da API:

```sh
node scripts/persistir-fotos.cjs
```

O script usa as variaveis DB_* do ambiente, adiciona as colunas `conteudo`
e `tipo_arquivo` em `fotos_ponto` sem remover registros e copia para o banco
as imagens ainda existentes em `uploads/pontos`. Pode ser executado novamente.
Para SSL com certificado CA, configure `DB_SSL_CA_PATH` com o caminho do PEM.

As novas fotos ficam no MySQL, na mesma transacao do levantamento. A URL
autenticada existente entrega o conteudo do banco, com fallback para arquivos
locais de fotos antigas. Arquivos antigos que ja desapareceram do servidor
precisam ser recuperados de um backup ou do aparelho original.

Os campos DATETIME representam horario de Brasilia. A conexao usa `-03:00`
tanto para interpretar os valores como para a sessao MySQL (NOW()). Nao
aplique novamente um deslocamento aos registros antigos para corrigir a tela.
