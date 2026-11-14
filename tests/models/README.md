# Fixtures de modelo externo

## `whatwg.json`

Cópia de `url/resources/urltestdata.json` do
[web-platform-tests/wpt](https://github.com/web-platform-tests/wpt)
(3-Clause BSD), baixada em 2026-10-04. É a suíte de referência que browsers
usam para testar o parser de URL do padrão WHATWG — citada desde a calibração
0.5.0 como a origem da classe de falso-positivo de `basic-auth-url` (host
degenerado, userinfo inválido, senha percent-encoded), mas nunca tinha sido
versionada neste repositório. `tests/test_corpus_whatwg.py` varre o arquivo
inteiro e trava que nenhuma das 896 entradas gera achado `basic-auth-url`.

Não editar à mão — é cópia fiel do upstream, para que uma atualização futura
seja um `curl` + `git diff`, não uma reconciliação manual.
