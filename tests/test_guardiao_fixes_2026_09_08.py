"""Invariantes de CLASSE das 6 correções P0/P1 do Guardião (auditoria 2026-09-08).

Cada família (3 FN + 2 FP + 1 mista) ganha o teste da PROPRIEDADE — property-based
onde cabe — junto de uma CONTRAPROVA que trava o OUTRO lado: o segredo real dispara e
o não-segredo/exemplo não. Desfazer a correção correspondente deixa este arquivo
vermelho. Nenhum teste ataca o exemplo isolado do `reproduzi`; todos afirmam a causa-raiz.
"""

from __future__ import annotations

import base64
import string

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from guardiao.core.engine import Scanner
from guardiao.rules.definitions import (
    PLACEHOLDER_SUBSTRINGS,
    is_obvious_fake,
    looks_like_secret_token,
    looks_like_secret_value,
    placeholder_domina,
)
from tests.conftest import (
    ANTHROPIC_KEY,
    CONNSTRING_SECRET,
    GH_TOKEN,
    OPENAI_KEY,
)


def _ids(text: str, path: str = "x.py") -> set[str]:
    return {f.rule_id for f in Scanner().scan_text(path, text)}


# Marcadores de placeholder ALFANUMÉRICOS (cabem no meio de um token de formato sem
# quebrar a classe `[A-Za-z0-9]`) — subconjunto de PLACEHOLDER_SUBSTRINGS.
_MARCADORES_ALNUM = tuple(sorted({m for m in PLACEHOLDER_SUBSTRINGS if m.isalnum()}))


# --------------------------------------------------------------------------- #
# Classe 1 (FN P0) — placeholder por SUBSTRING não pode suprimir segredo real
# --------------------------------------------------------------------------- #
@settings(max_examples=200)
@given(
    marcador=st.sampled_from(_MARCADORES_ALNUM),
    pos=st.integers(min_value=1, max_value=36),
)
def test_marcador_embutido_nao_suprime_token_de_formato(marcador: str, pos: int) -> None:
    """INVARIANTE (a): uma regra de FORMATO/fornecedor (regex+shape já valida o valor) NÃO
    pode ser suprimida por uma substring de placeholder perdida no meio do token — só por
    um valor de exemplo por INTEIRO. Um `ghp_…todo…` continua sendo `github-token`."""
    corpo = GH_TOKEN[len("ghp_") :]  # 37 alnum válidos
    p = min(pos, len(corpo))
    body = corpo[:p] + marcador + corpo[p:]  # marcador alnum -> run contígua permanece
    token = "ghp_" + body
    assert "github-token" in _ids(f'gh = "{token}"'), f"marcador {marcador!r} suprimiu formato"


@settings(max_examples=200)
@given(cauda=st.text(alphabet=string.ascii_letters + string.digits, min_size=24, max_size=48))
def test_marcador_embutido_nao_suprime_segredo_de_alta_entropia(cauda: str) -> None:
    """INVARIANTE (b): para uma regra HEURÍSTICA, um segredo de ALTA ENTROPIA com um
    marcador embutido não é placeholder — o marcador teria de DOMINAR o valor. Propriedade
    central: se S sozinho não é placeholder, S+marcador embutido também não é."""
    secret = "Xk9" + cauda
    assume(not placeholder_domina(secret))  # S já não é placeholder por si
    for marcador in ("todo", "mock", "example"):
        alvo = secret[:6] + marcador + secret[6:]
        assert not placeholder_domina(alvo), f"{marcador!r} embutido virou placeholder"


def test_placeholder_dominante_e_exemplo_inteiro_ainda_suprimidos() -> None:
    """CONTRAPROVA: o filtro não pode ser desligado. Valor de exemplo por INTEIRO (regra de
    formato) e marcador que DOMINA o valor (heurística) continuam suprimidos."""
    # Formato: exemplo canônico da AWS por inteiro -> is_obvious_fake -> suprime.
    assert _ids('key = "AKIAIOSFODNN7EXAMPLE"') == set()
    assert is_obvious_fake("AKIAIOSFODNN7EXAMPLE")
    # Heurística: marcador cobre a maior parte do valor (baixa entropia) -> domina.
    assert placeholder_domina("changeme123")
    assert not _ids('api_key = "changeme1234"')


# --------------------------------------------------------------------------- #
# Classe 2 (FN P1) — chave privada PEM escondida sob base64
# --------------------------------------------------------------------------- #
_PEM_PRIVADA = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAUEwggE9AgEAAkEAr4zP\n"
    "B7tmCiDVd1EdK0FEqu2c6i9pWcW1vJ0aQx2n3KpQ0y6mN4pQ7wL\n"
    "-----END PRIVATE KEY-----\n"
)


@settings(max_examples=100)
@given(prefixo=st.sampled_from(['{"payload":"', "cert = '", "data: ", '"key":"']))
def test_chave_privada_base64_e_decodificada_e_reportada(prefixo: str) -> None:
    """INVARIANTE: antes de tratar um blob base64 como payload opaco, decodifica-o e
    re-roda a regra de ESTRUTURA. Um PEM de chave privada codificado em base64 (o cabeçalho
    vira `LS0tLS1CRUdJTi…`) é reportado como `private-key`, em qualquer envelope."""
    b64 = base64.b64encode(_PEM_PRIVADA.encode()).decode()
    assert "private-key" in _ids(f"{prefixo}{b64}")


@settings(max_examples=200)
@given(dados=st.binary(min_size=48, max_size=512))
def test_base64_de_binario_nao_vira_private_key(dados: bytes) -> None:
    """CONTRAPROVA: um blob base64 que decodifica para binário/lixo NÃO vira achado — a
    decodificação só reporta quando bate a estrutura de chave privada."""
    b64 = base64.b64encode(dados).decode()
    assert "private-key" not in _ids(f'blob = "{b64}"', "x.json")


# --------------------------------------------------------------------------- #
# Classe 3 (FN P1) — chaves de IA por PREFIXO, sem refém de keyword
# --------------------------------------------------------------------------- #
@settings(max_examples=100)
@given(
    chave=st.sampled_from([OPENAI_KEY, ANTHROPIC_KEY]),
    contexto=st.sampled_from(
        [
            "{}",  # bare
            "func({})",  # argumento
            'logger.info("using {}")',  # log
            "https://api.example.com/?k={}",  # URL
            "keys = [{}]",  # item de lista
        ]
    ),
)
def test_chave_de_ia_dispara_em_qualquer_contexto(chave: str, contexto: str) -> None:
    """INVARIANTE: uma chave OpenAI/Anthropic que casa o prefixo canônico dispara em
    QUALQUER contexto — sem depender de `key`/`token`/`secret` na linha (o refém de
    keyword que a deixava passar num `logger.info`/lista)."""
    linha = contexto.format(chave)
    achados = _ids(linha)
    assert ("openai-api-key" in achados) or ("anthropic-api-key" in achados), linha


def test_stripe_e_sk_generico_nao_sao_openai() -> None:
    """CONTRAPROVA: o prefixo `sk-` da OpenAI não pode roubar a Stripe (`sk_live_`, com
    underscore) nem casar um `sk-` curto qualquer."""
    # Chave Stripe de teste partida em dois literais (o `sk_live_` não fica contíguo aos 24
    # alnum no fonte) para não tropeçar no push-protection do GitHub; o valor em runtime é o
    # completo, então o detector vê a chave inteira. Mesma convenção do split da chave canônica.
    stripe = "sk_live_" + "51H9xQmKz3PqRtYuVwXqBnDzFgHiJkLmN"
    assert "openai-api-key" not in _ids(f'k = "{stripe}"')
    assert "openai-api-key" not in _ids('x = "sk-short"')


# --------------------------------------------------------------------------- #
# Classe 4 (FN P1) — senha em connection string estilo chave=valor
# --------------------------------------------------------------------------- #
@settings(max_examples=100)
@given(
    ext=st.sampled_from(["appsettings.json", "Program.cs", "conn.txt", "web.xml", "a.ini"]),
    chave=st.sampled_from(["Password", "PASSWORD", "pwd", "Pwd", "AccountKey"]),
)
def test_senha_em_connection_string_dispara_em_qualquer_extensao(ext: str, chave: str) -> None:
    """INVARIANTE: `Password=`/`Pwd=`/`AccountKey=` dentro de uma connection string
    delimitada por `;` é credencial — independente da extensão e do formato URI. O valor
    é testado pelo piso multi-sinal, embutido no meio de uma string maior."""
    linha = f'c = "Server=tcp:prod.db.net;{chave}={CONNSTRING_SECRET};Encrypt=true"'
    achados = _ids(linha, ext)
    # arquivo de config pode etiquetar como config-file-secret; o essencial é NÃO passar batido
    assert achados & {"connection-string-password", "config-file-secret"}, linha


def test_connection_string_nao_rouba_atribuicao_solta_nem_aceita_placeholder() -> None:
    """CONTRAPROVA dupla: (1) uma atribuição SOLTA `DB_PASSWORD=valor` de `.env` (sem `;`)
    continua sendo `dotenv-assignment`, não vira connection-string; (2) `Password=changeme;`
    e `Pwd=$(VAR);` (template) não disparam."""
    env = _ids(f"DB_PASSWORD={CONNSTRING_SECRET}", ".env")
    assert "dotenv-assignment" in env and "connection-string-password" not in env
    assert _ids('c = "Server=x;Password=changeme;Encrypt=true"', "a.cs") == set()
    assert _ids('c = "Server=x;Pwd=$(DB_PW);Encrypt=true"', "a.cs") == set()


# --------------------------------------------------------------------------- #
# Classe 5 (FP P1) — segmento estrutural de recurso PÚBLICO não é segredo
# --------------------------------------------------------------------------- #
def test_segmento_de_recurso_publico_nao_e_secret_in_path() -> None:
    """INVARIANTE: um token de alta entropia que é SEGMENTO ESTRUTURAL de recurso público
    reconhecível não é 'segredo embutido' — reconhecer a FORMA antes de pontuar entropia."""
    # (a) slug num host de asset/CDN + extensão de imagem
    assert (
        _ids(
            '{"imageUrl": "https://images.opencollective.com/x/buy-instagram-followers-cc8dc394/avatar.png"}',
            "sponsors.json",
        )
        == set()
    )
    # (b) identificador de recurso cloud dentro de um ARN
    assert (
        _ids('p = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicyABCDEFGH12345"', "main.tf")
        == set()
    )
    # (b) placeholder ssoins-<hex> como segmento de path
    assert "secret-in-path" not in _ids('u = "/instances/ssoins-1234567890abcdef/config"', "x.tf")
    # (c) WWID/WWN de hardware logo após /dev/mapper
    assert _ids('dev = "/dev/mapper/36001405e3f8a9b2c1d4e5f60718293a"', "pv.md") == set()


def test_segredo_real_em_path_e_hex_ainda_disparam() -> None:
    """CONTRAPROVA: as correções reconhecem a FORMA pública — não desligam a detecção. Um
    token aleatório num path de host NÃO-asset e um hex de segredo FORA de /dev/mapper
    continuam pegos."""
    assert "secret-in-path" in _ids(
        'u = "https://api.acme.com/_internal/aB9xK2mQ7pL4vW8nZ1cD5fG6/intel"'
    )
    # mesmo WWID hex, mas num path de recurso comum (não /dev/mapper): segue sendo segredo
    assert "secret-in-path" in _ids(
        'u = "https://api.acme.com/t/36001405e3f8a9b2c1d4e5f60718293a/x"'
    )


# --------------------------------------------------------------------------- #
# Classe 6 (FP P1) — corrida de consoantes refutada por variedade insuficiente
# --------------------------------------------------------------------------- #
@settings(max_examples=300)
@given(
    base=st.sampled_from("abcdxyz0129"),
    repete=st.integers(min_value=16, max_value=40),
    cauda=st.text(alphabet="AbC12", min_size=2, max_size=4),
)
def test_variedade_insuficiente_nunca_e_segredo(base: str, repete: int, cauda: str) -> None:
    """INVARIANTE (a): variedade insuficiente de símbolos REFUTA a aleatoriedade — um
    caractere que domina o valor (≥40%) torna a cadeia repetição, não segredo, INDEPENDENTE
    de haver uma corrida de consoantes. Vale para `xkkk…`/`AQBQyyyy…`/`ABCzzz==`."""
    valor = base * repete + cauda  # base domina >= 16/(16+4) = 80%
    assert not looks_like_secret_token(valor), f"{valor!r} aceito como token"
    assert not looks_like_secret_value(valor), f"{valor!r} aceito como valor"


def test_config_repetido_nao_dispara_mas_segredo_real_dispara() -> None:
    """CONTRAPROVA no motor: o `PREFIXsss…`/saída de `ceph auth` some, mas uma senha de
    alta variedade no MESMO arquivo/regra continua reportada."""
    assert _ids("api_key: PREFIXssssssssssssssssss", "repeated.yaml") == set()
    assert _ids("auth_token: AQBQyyyyyyyyyyyyyyyyyyyyyyyy==", "repeated.yaml") == set()
    assert "config-file-secret" in _ids("api_key: Xk9Q2mNpR7wLvB3cD5fG6hJ", "real.yaml")


def test_vocabulario_tecnico_escapa_mas_ruido_com_simbolo_nao() -> None:
    """INVARIANTE (b): a fuga de 'palavra/identificador' não exige `isalpha()` puro — um
    token técnico pronunciável com dígito/`-`/`_`/`/` (MIME/algoritmo/identificador) escapa
    do gate de consoantes; a MESMA cadeia com um símbolo de ruído (`$`) volta a ser segredo.

    Par anti-mutação: os dois caem no ramo de corrida-de-consoante (baixa entropia, corrida
    ≥6, não refutados); só o discriminante das não-letras separa um do outro."""
    assert not looks_like_secret_token("gethttpstransportmanager2")  # dígito = decoração
    assert looks_like_secret_token("gethttpstransportmanag$r2")  # `$` = ruído de token
