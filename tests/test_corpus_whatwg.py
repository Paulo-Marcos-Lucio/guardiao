"""Corpus de conformidade real contra falso-positivo de `basic-auth-url` (G02b).

`tests/models/whatwg.json` é o `urltestdata.json` do projeto web-platform-tests
(3-Clause BSD, https://github.com/web-platform-tests/wpt), a suíte de referência
que browsers usam para testar o parser de URL do WHATWG. O docstring de
`_basic_auth_url_e_vazamento` já citava este arquivo como a CAUSA-RAIZ da classe
de falso-positivo (URLs sintaticamente válidas mas absurdas: host vazio, host de
1 caractere, senha URL-encoded) — mas o corpus nunca tinha sido versionado nem
varrido de verdade. Rodar contra ele (em vez de só os 2 exemplos do critério de
aceite) revelou 2 falso-positivos que os exemplos isolados não cobriam: senha
percent-encoded (emoji) contra host de FORMA de domínio, fechado em
`_pw_looks_real` (ver `tests/test_propriedades.py::
test_senha_percent_encoded_contra_host_de_dominio_nao_e_vazamento`).
"""

from __future__ import annotations

from pathlib import Path

from guardiao.core.engine import Scanner

_WHATWG_FIXTURE = Path(__file__).resolve().parent / "models" / "whatwg.json"


def test_corpus_whatwg_nao_gera_achado_basic_auth_url() -> None:
    """O corpus de conformidade whatwg completo não gera NENHUM achado `basic-auth-url`.

    896 entradas de URL, muitas com credencial Basic-Auth sintaticamente válida mas
    de teste de parser (host vazio/degenerado, userinfo inválido, senha percent-
    encoded) — exatamente a classe que `_basic_auth_url_e_vazamento` existe para
    descartar. Zero é o número certo: nenhuma delas é uma credencial real.
    """
    texto = _WHATWG_FIXTURE.read_text(encoding="utf-8")
    achados = [
        a
        for a in Scanner().scan_text("tests/models/whatwg.json", texto)
        if a.rule_id == "basic-auth-url"
    ]
    assert achados == [], (
        f"{len(achados)} achado(s) basic-auth-url no corpus de conformidade whatwg: "
        + ", ".join(a.secret for a in achados)
    )
