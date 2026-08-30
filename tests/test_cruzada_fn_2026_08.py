"""Invariantes de CLASSE das famílias de falso-negativo fechadas na cruzada de 2026-08-29.

Espelha `test_cruzada_fp_2026_08.py`: cada família de FN (URI de conexão, `.env`, config
YAML/INI/XML, `.pgpass`, `.npmrc`/netrc, chave PEM de outras ferramentas, concatenação,
UTF-16 sem BOM, nome de ref no histórico) ganha um teste que afirma a PROPRIEDADE — o
segredo real dispara — junto de uma CONTRAPROVA de que o benigno equivalente NÃO dispara.
Desfazer a correção correspondente deixa este arquivo vermelho.
"""

from __future__ import annotations

import string
import subprocess
from pathlib import Path

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from guardiao.core.engine import Scanner
from guardiao.rules.definitions import looks_like_placeholder
from guardiao.sources.files import decode_text_bytes
from tests.conftest import GH_TOKEN as TOKEN_GH  # ghp_ + 37 chars (formato válido)

# Segredo forte de teste: 3+ classes de caractere, sem substring de placeholder.
SENHA = "Xk9Q2mNpR7wLvB3"


def _ids(text: str, path: str = "x") -> set[str]:
    return {f.rule_id for f in Scanner().scan_text(path, text)}


# Alfabeto e estratégia de senha forte para os testes property-based: qualquer coisa
# com 3 classes de caractere é credencial; o prefixo fixo garante as 3 sem depender do
# sorteio, e o corpo aleatório varre o espaço de valores.
_ALNUM = st.text(alphabet=string.ascii_letters + string.digits, min_size=10, max_size=30)


def _senha_forte(draw) -> str:
    return "Xk9" + draw


# --------------------------------------------------------------------------- #
# Família 1 — URI de conexão (esquema://user:senha@host, jdbc:, +driver)
# --------------------------------------------------------------------------- #
_ESQUEMAS = [
    "postgres",
    "postgresql",
    "postgresql+psycopg",
    "mysql",
    "mariadb",
    "mssql",
    "sqlserver",
    "mongodb+srv",
    "redis",
    "amqp",
    "smtp",
    "jdbc:postgresql",
    "jdbc:mariadb",
]


@settings(max_examples=200)
@given(corpo=_ALNUM, esquema=st.sampled_from(_ESQUEMAS))
def test_uri_de_conexao_com_senha_real_dispara(corpo: str, esquema: str) -> None:
    """Qualquer esquema de banco/serviço com `user:senha@host` real é vazamento —
    inclusive os que a lista antiga não cobria (mariadb/mssql/smtp) e o prefixo jdbc:."""
    senha = _senha_forte(corpo)
    linha = f'URL = "{esquema}://app:{senha}@db.prod.internal:5432/main"'
    assert "db-connection-uri" in _ids(linha)


def test_uri_host_com_substring_de_placeholder_ainda_dispara() -> None:
    """CAUSA-RAIZ do FN: `looks_like_placeholder` casava `sample`/`mock` no NOME do
    banco/host e engolia a URI inteira. A regra `composto` julga só a senha."""
    assert "db-connection-uri" in _ids(
        f'u = "postgres://app:{SENHA}@db.prod.internal:5432/sample_reports"'
    )
    assert "db-connection-uri" in _ids(f'u = "mysql://root:{SENHA}@dbmock.prod.internal/prod"')


def test_uri_de_conexao_exemplo_nao_dispara() -> None:
    """CONTRAPROVA: senha placeholder, host de dev e template continuam suprimidos."""
    assert "db-connection-uri" not in _ids('u = "postgres://postgres:postgres@localhost:5432/dev"')
    assert "db-connection-uri" not in _ids('u = "redis://foo:bar@somehost:6379/0"')
    assert "db-connection-uri" not in _ids('u = "postgres://app:${DB_PASS}@db:5432/app"')


# --------------------------------------------------------------------------- #
# Família 2 — arquivo .env (cifrão, comentário inline, DB_PASS, senha PT-BR, passphrase)
# --------------------------------------------------------------------------- #
def test_dotenv_variantes_de_valor_disparam() -> None:
    assert "dotenv-assignment" in _ids(f"DB_PASSWORD={SENHA}$q", ".env")  # cifrão no valor
    assert "dotenv-assignment" in _ids(f"DB_PASSWORD={SENHA} # prod", ".env")  # comentário
    assert "dotenv-assignment" in _ids(f"DB_PASS={SENHA}", ".env")  # abreviação
    assert "dotenv-assignment" in _ids(f"SENHA_BANCO={SENHA}", ".env")  # chave PT-BR
    assert "dotenv-quoted" in _ids(f'GPG_PASSPHRASE="{SENHA} outra parte"', ".env")  # espaço


def test_dotenv_template_e_example_nao_disparam() -> None:
    """CONTRAPROVA: ref de shell/template não é segredo; `.env.example` é doc."""
    assert _ids("DB_PASSWORD=${DB_PASSWORD}", ".env") == set()
    assert _ids("DB_PASSWORD=$OUTRA_VAR", ".env") == set()
    assert "dotenv-assignment" not in _ids(f"DB_PASSWORD={SENHA}", ".env.example")


# --------------------------------------------------------------------------- #
# Família 3-8 — arquivo de configuração (YAML compose/k8s/Helm, INI, XML, npmrc, netrc)
# --------------------------------------------------------------------------- #
def test_config_file_secret_formatos_disparam() -> None:
    assert "config-file-secret" in _ids(f"      - POSTGRES_PASSWORD={SENHA}", "docker-compose.yml")
    assert "config-file-secret" in _ids(f"    POSTGRES_PASSWORD: {SENHA}", "docker-compose.yml")
    assert "config-file-secret" in _ids(f"    password: {SENHA}", "values.yaml")
    assert "config-file-secret" in _ids("  password: WGs5UTJtTnBSN3dMdjM=", "secret.yaml")  # base64
    assert "config-file-secret" in _ids(f"password={SENHA}", ".my.cnf")
    assert "config-file-secret" in _ids(f"password = {SENHA}", ".pypirc-legacy")
    assert "config-file-secret" in _ids(f"      <password>{SENHA}</password>", "settings.xml")
    assert "config-file-secret" in _ids(
        f'connectionString="Server=x;User Id=sa;Password={SENHA};"', "web.config"
    )
    assert "config-file-secret" in _ids(f"//registry.npmjs.org/:_authToken={SENHA}", ".npmrc")
    assert "config-file-secret" in _ids(f"machine api.x.org login me password {SENHA}", "netrc")


@settings(max_examples=100)
@given(corpo=_ALNUM)
def test_config_password_unquoted_dispara(corpo: str) -> None:
    """Invariante: `password: <segredo>` sem aspas num YAML é credencial em claro.

    ``assume`` descarta o valor aleatório que POR ACASO contém uma substring de
    placeholder (`mock`/`todo`/`stub`…) — esses são suprimidos por design (tradeoff
    documentado do filtro de placeholder), não são a propriedade sob teste."""
    senha = _senha_forte(corpo)
    assume(not looks_like_placeholder(senha))
    assert "config-file-secret" in _ids(f"    password: {senha}", "values.yaml")


def test_config_file_secret_i18n_e_template_nao_disparam() -> None:
    """CONTRAPROVA (a classe i18n do corpus FP): a palavra sensível precisa estar COLADA
    ao delimitador — `auth.password.error=texto` tem `.error` no meio e não casa; hash de
    senha, template e valor placeholder tampouco."""
    assert _ids("auth.password.error=Datenschutzgrundverordnung", "de.properties") == set()
    assert _ids("password: ${DB_PASSWORD}", "values.yaml") == set()
    assert _ids("password: REPLACE_ME", "values.yaml") == set()
    assert (
        _ids("password: $2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW", "seeds.yaml")
        == set()
    )


def test_config_scope_nao_alcanca_codigo() -> None:
    """CONTRAPROVA: a regra é ESCOPADA por nome de arquivo — `password: str` (anotação de
    tipo) num `.py` não pode virar achado, senão a classe de FP volta."""
    assert "config-file-secret" not in _ids(f"    password: {SENHA}", "models.py")
    assert "config-file-secret" not in _ids("password: SecretStr", "schema.py")


# --------------------------------------------------------------------------- #
# Família 7 — .pgpass (posicional host:porta:db:usuário:senha)
# --------------------------------------------------------------------------- #
def test_pgpass_dispara_e_dev_nao() -> None:
    assert "pgpass-credential" in _ids(f"db.internal:5432:app:app:{SENHA}", ".pgpass")
    # CONTRAPROVA: senha de dev padrão (postgres) não é vazamento.
    assert "pgpass-credential" not in _ids("localhost:5432:*:postgres:postgres", ".pgpass")


# --------------------------------------------------------------------------- #
# Família 9 — atribuição PT-BR / abreviada em código (DB_PASS, senha)
# --------------------------------------------------------------------------- #
def test_generic_pass_e_senha_em_codigo() -> None:
    assert "generic-assignment" in _ids(f'DB_PASS = "{SENHA}"', "settings.py")
    assert "generic-assignment" in _ids(f'senha = "{SENHA}"', "config.py")
    # CONTRAPROVA: `pass` só casa em fronteira de palavra/`_`, e o valor precisa parecer
    # segredo — `compass`/`bypass` e valor legível não disparam.
    assert "generic-assignment" not in _ids('compass = "north-star"', "app.py")
    assert "generic-assignment" not in _ids('bypass_cache = "enabled"', "app.py")


# --------------------------------------------------------------------------- #
# Família 12 — chaves privadas de outras ferramentas (PGP block, SSH2, PuTTY)
# --------------------------------------------------------------------------- #
def test_pem_formatos_de_ferramenta_disparam() -> None:
    assert "private-key" in _ids("-----BEGIN PGP PRIVATE KEY BLOCK-----", "k.key")
    assert "private-key" in _ids("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----", "k.key")
    assert "private-key" in _ids("PuTTY-User-Key-File-3: ssh-ed25519", "k.ppk")


def test_pem_bloco_publico_nao_dispara() -> None:
    """CONTRAPROVA: o par PÚBLICO nunca é chave privada."""
    assert "private-key" not in _ids("-----BEGIN PGP PUBLIC KEY BLOCK-----", "k.key")
    assert "private-key" not in _ids("-----BEGIN PUBLIC KEY-----", "k.key")


# --------------------------------------------------------------------------- #
# Família 11 — evasão por concatenação de literais ("AKIA" + "…")
# --------------------------------------------------------------------------- #
def test_concatenacao_reconstroi_segredo_de_fornecedor() -> None:
    assert "aws-access-key-id" in _ids('KEY = "AKIA" + "XVNR3OB5RYXH8FNG"', "evade.py")
    assert "stripe-secret-key" in _ids('SK = "sk_live_" + "wO90cYrsMk1Hje1QKOhX7oi3"', "evade.py")


def test_concatenacao_de_texto_benigno_nao_dispara() -> None:
    """CONTRAPROVA: juntar texto comum não pode fabricar segredo; só junta literal+literal."""
    assert _ids('msg = "hello " + "world"', "app.py") == set()
    assert _ids('url = "https://api." + host', "app.py") == set()  # literal + variável


# --------------------------------------------------------------------------- #
# Família 10 — UTF-16 sem BOM (PowerShell ISE)
# --------------------------------------------------------------------------- #
def test_utf16_sem_bom_e_decodificado() -> None:
    conteudo = f'$env:DB_PASSWORD = "{SENHA}"\n'.encode("utf-16-le")
    texto = decode_text_bytes(conteudo)
    assert texto is not None and SENHA in texto
    assert "generic-assignment" in _ids(texto, "script.ps1")


def test_binario_com_nul_continua_binario() -> None:
    """CONTRAPROVA: NUL espalhado (binário real) não pode ser lido como UTF-16."""
    assert decode_text_bytes(b"\x00\x01\x02\x03prod\x00\xff\xfe\x10secret\x00\x00\x07") is None


@settings(max_examples=100)
@given(corpo=_ALNUM)
def test_utf16_le_qualquer_texto_ascii_decodifica(corpo: str) -> None:
    """Invariante: texto ASCII em UTF-16-LE sem BOM sempre volta como texto (nunca None)."""
    linha = f"TOKEN={_senha_forte(corpo)}\n"
    assert decode_text_bytes(linha.encode("utf-16-le")) is not None


# --------------------------------------------------------------------------- #
# Família 13 — segredo no NOME de branch/tag (refs, não em blob nem mensagem)
# --------------------------------------------------------------------------- #
def _git(repo: Path, *args: str) -> None:
    env = {
        "GIT_AUTHOR_NAME": "c",
        "GIT_AUTHOR_EMAIL": "c@x",
        "GIT_COMMITTER_NAME": "c",
        "GIT_COMMITTER_EMAIL": "c@x",
    }
    import os

    subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, env={**os.environ, **env}
    )


def test_segredo_em_nome_de_branch_e_tag(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "README.md").write_text("# x\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "init")
    _git(tmp_path, "branch", f"hotfix/token-{TOKEN_GH}")
    _git(tmp_path, "tag", f"rel-{TOKEN_GH}")
    achados = Scanner().scan_git_history(tmp_path, permitir_shallow=True).findings
    tokens = {f.secret for f in achados if f.rule_id == "github-token"}
    assert TOKEN_GH in tokens, "o token no NOME do branch/tag não foi varrido"
