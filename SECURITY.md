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

A *fingerprint* publicada em SARIF, JSON e baseline é derivada de
`(regra, arquivo, valor ocultado)` — **não** do segredo cru. Um hash truncado do
segredo pareceria seguro, mas para uma senha humana (`Brasil@2024`) um dicionário
o reverte em dezenas de tentativas — e esses três canais são justamente os que
saem do seu computador.

## Uso responsável e enquadramento legal (Brasil)

Use o Guardião apenas em repositórios que você **possui** ou para os quais tem
**autorização formal** de análise. Ainda que a ferramenta seja passiva (ela apenas
lê arquivos e objetos Git locais), o acesso ao repositório em si precisa ser
legítimo.

No Brasil, acessar sistema/dispositivo informático alheio sem autorização é crime
tipificado no **art. 154-A do Código Penal** (invasão de dispositivo informático,
com redação da Lei 14.155/2021). O tratamento de dados pessoais encontrados —
CPF, CNPJ e credenciais que identifiquem pessoas — é regido pela
**LGPD (Lei 13.709/2018)**, cujo **art. 46** exige medidas técnicas de proteção.
Um relatório de varredura **é** dado sensível: guarde-o com o mesmo cuidado que
você daria ao segredo que ele aponta.

Todo segredo encontrado deve ser considerado comprometido — a resposta correta é
**rotacionar/revogar**, não apenas remover do histórico.
