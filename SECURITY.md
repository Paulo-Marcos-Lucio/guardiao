# Política de Segurança

## Divulgação responsável

Encontrou uma vulnerabilidade no Guardião? Reporte **de forma privada**:

- E-mail: **pmlsp23@gmail.com** (assunto começando com `[security]`)

Por favor, dê um prazo razoável para correção antes de divulgar publicamente.

## Escopo e princípio

O Guardião é uma ferramenta **defensiva**. Ele foi desenhado para **nunca**
expor o segredo cru nos relatórios (console, JSON, SARIF ou baseline) — apenas
um valor ocultado. Um bug que faça um segredo vazar num relatório é tratado
como **falha de segurança** desta ferramenta, não como falha de estilo.

## Uso responsável

Use o Guardião apenas em repositórios que você possui ou tem autorização para
analisar. Todo segredo encontrado deve ser considerado comprometido — a resposta
correta é **rotacionar/revogar**, não apenas remover do histórico.
