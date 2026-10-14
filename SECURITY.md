<p align="center"><a href="SECURITY.en.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/guardiao/main/assets/btn-lang-en.svg" alt="Read this document in English" width="300"/></a></p>

# Política de Segurança

## Divulgação responsável

Encontrou uma vulnerabilidade no Guardião? Reporte **de forma privada**:

- E-mail: **contatopml26@gmail.com** (assunto começando com `[security]`)

Por favor, dê um prazo razoável para correção antes de divulgar publicamente.

## Escopo e princípio

O Guardião é uma ferramenta **defensiva**. Ele foi desenhado para **nunca**
expor o segredo cru nos relatórios (console, JSON, SARIF ou baseline) — apenas
um valor ocultado. Um bug que faça um segredo vazar num relatório é tratado
como **falha de segurança** desta ferramenta, não como falha de estilo.

O **quanto** do valor ocultado aparece depende de para onde ele vai: console e
JSON mostram 4 caracteres de cada ponta; o **baseline** (feito para ser
commitado) e o **SARIF** (que sobe para o Code Scanning) mostram **2** — 4+4
revelava 8 caracteres de qualquer segredo com 13+, o bastante para reconstruir
uma senha humana com um dicionário.

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

## Modelo de ameaças da suíte

Como a suíte AppSec se defende de um alvo hostil — e o que ainda não está
fechado — está documentado em
[`modelo-de-ameacas.md`](https://github.com/Paulo-Marcos-Lucio/sentinela/blob/main/docs/modelo-de-ameacas.md),
no repositório da [Sentinela](https://github.com/Paulo-Marcos-Lucio/sentinela): é
ela quem tem superfície de rede (fala HTTP com o alvo escolhido pelo operador). O
Guardião lê arquivo e histórico de Git locais — não recebe resposta de rede
arbitrária —, por isso o modelo de ameaça correspondente aqui é mais estreito: a
seção **Escopo e princípio** acima já cobre o que interessa (nunca vazar o
segredo cru no relatório).
