"""Testes property-based (Hypothesis) das INVARIANTES de classe do motor.

Os testes por exemplo (test_engine, test_rules…) cobrem só os casos que ALGUÉM pensou.
Estes geram milhares de entradas e afirmam uma PROPRIEDADE que precisa valer para TODAS —
a rede contra "defeito de classe". Foi um corpo base64 de PEM com `/` que rendeu 821 falsos
positivos num único `cacert.pem` (P0-03): um exemplo que nenhum fixture cobria. Uma vez
codificada a invariante "corpo de PEM nunca gera achado de entropia", essa classe inteira
de regressão fica barrada no CI, para sempre.
"""

from __future__ import annotations

import base64

from hypothesis import given, settings
from hypothesis import strategies as st

from guardiao.core.engine import Scanner
from guardiao.rules.definitions import looks_like_secret_token
from guardiao.sources.files import decode_text_bytes

# Palavras legíveis (com vogal) para montar identificadores de código sintéticos.
_PALAVRAS = [
    "cert",
    "encrypted",
    "private",
    "public",
    "key",
    "file",
    "token",
    "secret",
    "config",
    "user",
    "session",
    "handler",
    "factory",
    "service",
    "manager",
    "context",
    "default",
    "value",
]

# Assinaturas de contêiner binário conhecidas (subconjunto do motor).
_MAGIC_BINARIO = [
    b"%PDF",
    b"%!PS-Adobe-3.0",
    b"\x89PNG\r\n\x1a\n",
    b"GIF89a",
    b"\xff\xd8\xff\xe0",
    b"PK\x03\x04",
    b"\x7fELF",
    b"\x1f\x8b\x08",
]

_PEM_TIPOS = ["CERTIFICATE", "RSA PRIVATE KEY", "PUBLIC KEY", "EC PRIVATE KEY", "X509 CRL"]


def _pem(corpo_b64: str, tipo: str = "CERTIFICATE") -> str:
    linhas = [corpo_b64[i : i + 64] for i in range(0, len(corpo_b64), 64)] or [""]
    return f"-----BEGIN {tipo}-----\n" + "\n".join(linhas) + f"\n-----END {tipo}-----\n"


@settings(max_examples=300)
@given(dados=st.binary(min_size=48, max_size=4096), tipo=st.sampled_from(_PEM_TIPOS))
def test_corpo_pem_nunca_gera_achado_de_entropia(dados: bytes, tipo: str) -> None:
    """INVARIANTE 1 (P0-03): nenhum corpo base64 dentro de bloco PEM produz achado `entropy`.

    Vale para QUALQUER conteúdo de qualquer tipo de bloco — é a classe que rendeu os 821 FP.
    """
    texto = _pem(base64.b64encode(dados).decode(), tipo)
    de_entropia = [a for a in Scanner().scan_text("qualquer.pem", texto) if a.category == "entropy"]
    assert de_entropia == [], f"corpo PEM gerou {len(de_entropia)} achado(s) de entropia"


@settings(max_examples=200)
@given(dados=st.binary(min_size=48, max_size=1024))
def test_pem_nao_cega_o_detector_de_fornecedor(dados: bytes) -> None:
    """INVARIANTE 2: suprimir entropia no PEM NÃO pode cegar as regras de fornecedor.

    O oposto do FP é o falso-negativo: um `ghp_` real dentro de um PEM tem de continuar pego.
    """
    ghp = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    corpo = base64.b64encode(dados).decode()
    texto = (
        "-----BEGIN CERTIFICATE-----\n"
        + corpo[:64]
        + f"\n{ghp}\n"
        + corpo[64:128]
        + "\n-----END CERTIFICATE-----\n"
    )
    achados = list(Scanner().scan_text("vazou.pem", texto))
    assert any("ghp_" in a.secret for a in achados), "ghp_ dentro do PEM não foi detectado"


@settings(max_examples=200)
@given(
    chave=st.sampled_from(["password", "api_key", "secret", "token", "senha"]),
    placeholder=st.sampled_from(
        ["changeme", "xxxxxxxx", "your-token-here", "<REDACTED>", "example", "TODO", "..."]
    ),
)
def test_placeholder_nunca_vira_achado(chave: str, placeholder: str) -> None:
    """INVARIANTE 3: atribuição a um placeholder óbvio não é segredo, em nenhum contexto."""
    achados = list(Scanner().scan_text("config.py", f'{chave} = "{placeholder}"\n'))
    assert achados == [], f"placeholder {placeholder!r} virou achado"


@settings(max_examples=300)
@given(
    partes=st.lists(st.sampled_from(_PALAVRAS), min_size=3, max_size=6),
    sep=st.sampled_from(["_", "-"]),
)
def test_identificador_de_codigo_nunca_e_segredo(partes: list[str], sep: str) -> None:
    """INVARIANTE 4: um identificador de código (palavras legíveis unidas por `_`/`-`) nunca
    é classificado como token de segredo.

    Classe do FP de campo (httpx): `cert_encrypted_private_key_file` virava achado porque a
    palavra ``encrypted`` tem corrida de 6 consoantes. Vale para QUALQUER identificador
    formado por sub-palavras legíveis, com 24+ caracteres.
    """
    ident = sep.join(partes)
    if len(ident) < 24:  # a regra de entropia só considera cadeias longas
        return
    assert not looks_like_secret_token(ident), f"identificador {ident!r} tratado como segredo"


@settings(max_examples=200)
@given(
    ruido=st.binary(min_size=32, max_size=2048),
    magic=st.sampled_from(_MAGIC_BINARIO),
)
def test_assinatura_binaria_nunca_e_lida_como_texto(ruido: bytes, magic: bytes) -> None:
    """INVARIANTE 5: um arquivo que abre com assinatura de contêiner binário é sempre tratado
    como binário — independente de a extensão ser desconhecida e de não haver NUL no início.

    Classe do FP de campo (requests): `requests-logo.ai` (Adobe Illustrator, cabeçalho ASCII)
    era lido como texto e o corpo comprimido rendia achado de entropia.
    """
    assert decode_text_bytes(magic + ruido) is None, f"assinatura {magic!r} lida como texto"


@settings(max_examples=200)
@given(
    esquema=st.sampled_from(["http", "https"]),
    user=st.sampled_from(["user", "admin", "jo%40email.com", "&a"]),
    pw_junk=st.sampled_from(["pass", "a%20secret", "foo(b%5Dc", "%60%7B%7D", "changeme"]),
    host_degenerado=st.sampled_from(["", "d", "h", "d:2"]),
)
def test_url_de_fixture_de_parser_nao_e_vazamento(
    esquema: str, user: str, pw_junk: str, host_degenerado: str
) -> None:
    """INVARIANTE 6: URL Basic-Auth com host degenerado (fixture de parser) e senha não-real
    nunca vira achado `basic-auth-url`.

    Classe do FP de campo (httpx/whatwg.json): `http://user:pass@/`, `http://&a:foo@d:2/`.
    Um vazamento real tem host de domínio E senha de aparência real — nenhum destes tem.
    """
    url = f"{esquema}://{user}:{pw_junk}@{host_degenerado}/path?q=1"
    achados = [
        a
        for a in Scanner().scan_text("teste.py", f'url = "{url}"\n')
        if a.rule_id == "basic-auth-url"
    ]
    assert achados == [], f"URL de fixture {url!r} virou achado basic-auth-url"


def _achados_basic_auth(url: str) -> list:
    return [
        a
        for a in Scanner().scan_text("teste.py", f'url = "{url}"\n')
        if a.rule_id == "basic-auth-url"
    ]


@settings(max_examples=200)
@given(
    esquema=st.sampled_from(["http", "https"]),
    host=st.sampled_from(["host", "user", "hostname", "Host", "USER", "mueller.de", "dbhost"]),
    bytes_pw=st.lists(st.integers(min_value=0, max_value=255), min_size=4, max_size=16),
)
def test_senha_predominantemente_url_encoded_nao_e_vazamento(
    esquema: str, host: str, bytes_pw: list[int]
) -> None:
    """INVARIANTE 7a: senha PREDOMINANTEMENTE `%XX` (dado de URL/fixture, ex. emoji
    URL-encoded) nunca vira achado `basic-auth-url`, nem contra host com forma de
    domínio — o `%` de percent-encoding não pode contar como a 3ª classe de caractere
    que, por si só, validaria a senha como real.

    Classe do FP de campo (WHATWG `tests/models/whatwg.json`): `%F0%9F%92%A9` (emoji
    URL-encoded) contra `müller.de` tinha 3 classes de caractere (maiúscula/dígito/`%`)
    e virava achado sem a senha carregar segredo nenhum.
    """
    pw = "".join(f"%{b:02X}" for b in bytes_pw)
    url = f"{esquema}://user:{pw}@{host}/path?q=1"
    assert _achados_basic_auth(url) == [], f"URL com senha URL-encoded {url!r} virou achado"


@settings(max_examples=200)
@given(
    esquema=st.sampled_from(["http", "https"]),
    host=st.sampled_from(["host", "user", "hostname", "Host", "USER"]),
    pw=st.sampled_from(["pass", "a secret-ish pwd", "x" * 20, "foo.bar-baz_qux", "%41%42%43"]),
)
def test_host_rotulo_de_papel_e_placeholder_textual(esquema: str, host: str, pw: str) -> None:
    """INVARIANTE 7b: host que é o RÓTULO literal do papel na URL de doc (`host`, `user`,
    `hostname`) — não um domínio real — nunca sustenta `basic-auth-url` sozinho: exige
    senha de ALTA ENTROPIA, igual a um host degenerado.

    Classe do FP de campo: `http://user:pass@host:5432/db`, exemplo canônico de doc de
    conexão de banco, tinha host de 4+ chars e caía no ramo fraco (`_pw_looks_real`,
    3 classes de caractere bastam) em vez do ramo forte de alta entropia.
    """
    url = f"{esquema}://admin:{pw}@{host}:5432/db"
    assert _achados_basic_auth(url) == [], f"URL com host-placeholder {url!r} virou achado"


@settings(max_examples=50)
@given(
    host=st.sampled_from(["host", "user", "hostname", "mueller.de", "db.prod.internal"]),
)
def test_segredo_real_contra_host_rotulo_ou_dominio_ainda_dispara(host: str) -> None:
    """CONTRAPROVA de 7a/7b: um segredo real de alta entropia continua detectado contra
    QUALQUER host — rótulo de papel ou domínio real. Os dois guards novos (senha
    URL-encoded, host-rótulo) não podem cegar um vazamento de verdade.
    """
    pw = "Xk9E7pQ2mZ4tR8sV1nW6bL3jC5xN0oDM1"
    url = f"https://admin:{pw}@{host}:5432/db"
    achados = _achados_basic_auth(url)
    assert achados != [], f"segredo real {url!r} não virou achado basic-auth-url"
