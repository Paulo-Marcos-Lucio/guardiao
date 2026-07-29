"""Testes de regressão dos bugs achados nas revisões adversariais.

Cada teste aqui existe porque uma sabotagem do código de produção passava com a
suíte verde. Se você desfizer a correção correspondente, este arquivo fica
vermelho — é essa a função dele.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardiao.cli import app
from guardiao.core.config import Config
from guardiao.core.engine import Scanner
from guardiao.core.redaction import redact, redact_spans
from tests.conftest import (
    AWS_KEY_ID,
    CPF_VALIDO,
    GH_TOKEN,
    SENHA_DE_PRODUCAO,
    STRIPE_KEY_COM_ALFABETO,
)

runner = CliRunner()


def _ids(text: str, path: str = "x") -> set[str]:
    return {f.rule_id for f in Scanner().scan_text(path, text)}


# HIGH — o preview vazava segredo cru quando havia mais de um segredo na linha.
def test_preview_never_leaks_with_multiple_secrets_on_line() -> None:
    line = f'a = "{AWS_KEY_ID}"; b = "{AWS_KEY_ID}"; gh = "{GH_TOKEN}"'
    findings = list(Scanner().scan_text("x.py", line))
    assert findings
    for finding in findings:
        assert AWS_KEY_ID not in finding.line_preview
        assert GH_TOKEN not in finding.line_preview


def test_redact_spans_masks_every_secret() -> None:
    line = f"{AWS_KEY_ID} {AWS_KEY_ID}"
    n = len(AWS_KEY_ID)
    spans = [(0, n, AWS_KEY_ID), (n + 1, 2 * n + 1, AWS_KEY_ID)]
    assert AWS_KEY_ID not in redact_spans(line, spans)


# MEDIUM — segredo de 9-12 chars revelava 8 chars e mantinha o comprimento.
def test_redact_short_secret_hides_almost_everything() -> None:
    assert redact("ABCDEFGHI") == "A…"  # 9 chars
    long = "AKIAZ7Q2LMN4XYWV8RPD"
    assert len(redact(long)) < len(long)


# LOW — a contagem de linha deve seguir só o \n (igual ao editor/GitHub).
def test_line_numbers_count_only_newlines() -> None:
    text = 'topo\x0cmesma-linha\naqui = "AKIAZ7Q2LMN4XYWV8RPD"'
    findings = list(Scanner().scan_text("x", text))
    assert findings
    assert findings[0].location.line == 2


# MEDIUM — entropia agora exige CONTEXTO de segredo na linha (precisão de campo) e
# --no-entropy a desliga. Perto de 'bearer/token' dispara; solta, não (mata o falso-positivo).
def test_high_entropy_detection_toggle() -> None:
    ctx = "Authorization: Bearer Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zA"
    on = {f.rule_id for f in Scanner().scan_text("x", ctx)}
    assert "high-entropy-string" in on
    off = {f.rule_id for f in Scanner(config=Config(use_entropy=False)).scan_text("x", ctx)}
    assert "high-entropy-string" not in off
    # sem contexto de segredo → NÃO dispara (era o falso-positivo de campo).
    bare = 'value = "Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zA"'
    assert "high-entropy-string" not in {f.rule_id for f in Scanner().scan_text("x", bare)}


# LOW — scan --git-history fora de repo Git sai limpo (exit 2), sem traceback.
def test_scan_git_history_outside_repo_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--git-history"])
    assert result.exit_code == 2


# HIGH — pre-commit varre o conteúdo EM STAGE e inclui arquivos renomeados.
@pytest.mark.skipif(shutil.which("git") is None, reason="git indisponível")
def test_pre_commit_blocks_secret_in_renamed_staged_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.email=t@t.com", "-c", "user.name=t",
             "-c", "commit.gpgsign=false", *args],
            cwd=tmp_path, check=True, capture_output=True,
        )  # fmt: skip

    git("init", "-b", "main")
    (tmp_path / "old.py").write_text("x = 1\n", encoding="utf-8")
    git("add", "old.py")
    git("commit", "-m", "init")
    git("mv", "old.py", "new.py")
    (tmp_path / "new.py").write_text(f'AWS = "{AWS_KEY_ID}"\n', encoding="utf-8")
    git("add", "new.py")

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["pre-commit"])
    assert result.exit_code == 1


# =========================================================================== #
# Precisão de campo (2026-07-22): FPs em massa em código real — bateria em 8
# repos públicos deu 4018→29 achados (-99.3%) sem perder recall.
# =========================================================================== #


def test_git_sha_and_uuid_are_hash_not_secret() -> None:
    from guardiao.rules.definitions import is_probable_hash_or_id

    assert is_probable_hash_or_id("de0fac2e4500dabe0009e67214ff5f5447ce83dd")  # SHA-1
    assert is_probable_hash_or_id("550e8400-e29b-41d4-a716-446655440000")  # UUID
    assert not is_probable_hash_or_id("Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zA")  # segredo real


def test_guarda_de_hash_e_de_pin_sao_independentes() -> None:
    """As duas guardas do ramo de entropia se mascaravam: com só um dos testes,
    remover qualquer uma delas mantinha a suíte verde."""
    # SHA-1 SEM '@' na frente e SEM palavra de contexto de hash na linha (senão a
    # guarda de HASH_CONTEXT mascara esta): só `is_probable_hash_or_id` pode matar.
    assert "high-entropy-string" not in _ids("api_key: de0fac2e4500dabe0009e67214ff5f5447ce83dd")
    # Alta entropia que NÃO é hash, precedida de '@': só a guarda do pin pode matar.
    assert "high-entropy-string" not in _ids(
        "image key: repo/app@Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zA"
    )


def test_entropy_requires_secret_context() -> None:
    val = "Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zAwBcDeF"
    assert "high-entropy-string" in _ids(f"token: {val}")  # perto de 'token' → dispara
    assert "high-entropy-string" not in _ids(f"result = {val}")  # sem contexto → não (era o FP)


def test_contexto_de_hash_desliga_a_entropia() -> None:
    """Entropia não distingue digest de credencial: MD5 e SHA-256 são tão aleatórios
    quanto uma chave. O discriminante é o contexto da linha."""
    assert "high-entropy-string" not in _ids(
        'CACHE_KEY = "5d41402abc4b2a76b9719d911017c592"  # md5'
    )
    assert "high-entropy-string" not in _ids('etag_key = "9e107d9d372bb6826bd81d3542a419d6"')
    assert "high-entropy-string" not in _ids('idempotency_key = "6f4922f45568161a8cdf4ad2299f6d23"')
    # controle: o MESMO valor sem contexto de hash continua sendo achado
    assert "high-entropy-string" in _ids("api_key: 5d41402abc4b2a76b9719d911017c592")


def test_action_pin_sha_not_flagged() -> None:
    line = "- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6"
    assert "high-entropy-string" not in _ids(line)


def test_lockfile_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        'wheels = [{ hash = "sha256:9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928d" }]\n',
        encoding="utf-8",
    )
    assert Scanner().scan_paths([tmp_path]).findings == []


def test_example_url_credentials_suppressed() -> None:
    for url in (
        'url = "http://user:pass@localhost:8080"',
        'proxy = "http://user:pass@10.10.1.10:3128"',
        'x = "redis://foo:bar@somehost:6379/0"',
        'y = "http://{ENCODED_USER}:{ENCODED_PASSWORD}@request.com/"',
    ):
        ids = _ids(url)
        assert "basic-auth-url" not in ids and "db-connection-uri" not in ids


def test_real_url_credential_still_flagged() -> None:
    line = 'db = "postgres://dbadmin:Zx9r2Pq8LmNv3@prod-db.company.com:5432/main"'
    assert "db-connection-uri" in _ids(line)


def test_uri_de_redis_sem_usuario_e_detectada() -> None:
    """`redis://:senha@host` é a forma canônica do Redis/AMQP — exigir usuário
    não-vazio perdia a URL exatamente como o redis-cli e o Heroku a escrevem."""
    assert "db-connection-uri" in _ids('REDIS_URL = "redis://:Xq7pL2mNv9@cache.acme.com.br:6379/0"')
    assert "db-connection-uri" in _ids('u = "mongodb+srv://:Xq7pL2mNv9@c0.mongodb.net/db"')


def test_weak_example_password_suppressed() -> None:
    assert "generic-assignment" not in _ids('password = "password123"')
    assert "generic-assignment" not in _ids('secret = "changeme"')


def test_fp_fixes_preserve_recall() -> None:
    # os fixes de precisão NÃO podem quebrar a detecção de segredo real.
    cases = {
        "aws-access-key-id": 'AWS = "AKIAZQ3M7X9WPLKV2NRT"',
        "github-token": 'GH = "ghp_9zQ2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zAwX"',
        "high-entropy-string": "Authorization: Bearer Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zAwBcDeF",
        "private-key": "-----BEGIN RSA PRIVATE KEY-----",
    }
    for rule_id, line in cases.items():
        assert rule_id in _ids(line), rule_id


def test_overlapping_findings_deduped_to_most_specific() -> None:
    # GITHUB_TOKEN casa github-token (HIGH) e seria high-entropy (MEDIUM) — vira 1 achado só.
    line = 'GITHUB_TOKEN = "ghp_9zQ2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zAwX"'
    findings = list(Scanner().scan_text("x.py", line))
    assert len(findings) == 1
    assert findings[0].rule_id == "github-token"


def test_two_distinct_secrets_on_line_both_kept() -> None:
    line = f'a = "{AWS_KEY_ID}"; b = "{GH_TOKEN}"'  # spans distintos → não deduplica
    rules = {f.rule_id for f in Scanner().scan_text("x.py", line)}
    assert "aws-access-key-id" in rules
    assert "github-token" in rules


# =========================================================================== #
# Auditoria adversarial de 2026-07-29.
# =========================================================================== #


def test_prefixo_de_fornecedor_nao_e_engolido_por_substring_de_placeholder() -> None:
    """`abcdefgh` e `1234567890` em PLACEHOLDER_SUBSTRINGS suprimiam em SILÊNCIO
    valores legítimos que contivessem a sequência — inclusive uma senha humana
    como `Cliente1234567890`."""
    assert "stripe-secret-key" in _ids(f'STRIPE_SECRET_KEY = "{STRIPE_KEY_COM_ALFABETO}"')
    assert "generic-assignment" in _ids('password = "Cliente1234567890"')


def test_segredo_longo_nao_e_menos_visivel_que_um_curto() -> None:
    """O teto de 120 chars invertia a lógica: quanto mais longo o segredo, menos
    visível. `secret_key_base` do Rails (128 hex) era invisível."""
    hex128 = "9f3c1a7e5b2d48c06e1f9a3b7d5c2e04" * 4
    assert "high-entropy-string" in _ids(f"secret_key_base: {hex128}")
    urlsafe172 = "Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zAwBcDeF" * 4 + "Gh12"
    assert _ids(f"HMAC_KEY = '{urlsafe172}'")


def test_entropia_captura_o_valor_e_nao_o_par_nome_igual_valor() -> None:
    """Com `=` dentro do corpo do regex, o achado apontava para `NOME=VALOR` inteiro:
    a coluna vinha errada e o preview escondia o NOME e revelava o fim do segredo."""
    valor = "Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zAwBcDeF"
    linha = f"API_TOKEN={valor}"
    achado = next(f for f in Scanner().scan_text("deploy.sh", linha) if f.category == "entropy")
    assert achado.secret == valor
    assert linha[achado.location.column - 1 :].startswith(valor)
    assert "API_TOKEN" in achado.line_preview


def test_dotenv_sem_aspas_e_detectado() -> None:
    """`DB_PASSWORD=Nordeste2019!Rj` num .env real passava batido: a regra genérica
    exige aspas em volta do valor."""
    ids = _ids(f"DB_PASSWORD={SENHA_DE_PRODUCAO}", ".env")
    assert "dotenv-assignment" in ids
    assert "dotenv-assignment" in _ids(f"export JWT_SECRET={SENHA_DE_PRODUCAO}", ".env")
    assert "dotenv-assignment" in _ids(f"AWS_SECRET={SENHA_DE_PRODUCAO}", "producao.env")


def test_cpf_e_cnpj_conferem_digito_verificador() -> None:
    """Sem o módulo 11, qualquer número formatado virava 'dado pessoal'."""
    assert "cpf" in _ids(f"cliente: {CPF_VALIDO}")
    assert "cpf" not in _ids("pedido: 000.000.000-00")
    assert "cpf" not in _ids("codigo: 123.456.789-10")
    assert "cnpj" not in _ids("nota: 12.345.678/0001-00")


def test_fingerprint_publicada_nao_permite_recuperar_o_segredo() -> None:
    """A fingerprint viaja no SARIF que o CI publica e no baseline que o README manda
    versionar. Derivada do segredo CRU, um dicionário recuperava `Brasil@2024` em
    dezenas de tentativas — derivada do valor OCULTADO, não há o que quebrar."""
    achado = next(iter(Scanner().scan_text("app/settings.py", 'password = "Brasil@2024"')))
    alvo = achado.fingerprint
    candidatos = [
        f"{base}@{ano}"
        for base in ("Brasil", "Flamengo", "Palmeiras", "Corinthians")
        for ano in range(2000, 2031)
    ]
    from dataclasses import replace

    from guardiao.core.redaction import redact

    casaram = [
        c for c in candidatos if replace(achado, secret=c, redacted=redact(c)).fingerprint == alvo
    ]
    assert len(casaram) > 1, "a fingerprint publicada identifica um único segredo"
    # e o segredo cru não é ingrediente: trocar só o valor cru não muda a identidade
    assert replace(achado, secret="outra-coisa").fingerprint == alvo


def test_fingerprint_muda_com_arquivo_e_com_o_valor_ocultado() -> None:
    achado = next(iter(Scanner().scan_text("a.py", f'k = "{AWS_KEY_ID}"')))
    outro_arquivo = next(iter(Scanner().scan_text("b.py", f'k = "{AWS_KEY_ID}"')))
    outro_valor = next(iter(Scanner().scan_text("a.py", 'k = "AKIAZQ3M7X9WPLKV2NRT"')))
    assert achado.fingerprint != outro_arquivo.fingerprint
    assert achado.fingerprint != outro_valor.fingerprint
    # ...mas NÃO muda quando o código só muda de linha (senão o alerta do GitHub reabre).
    movido = next(iter(Scanner().scan_text("a.py", f'# nova linha\nk = "{AWS_KEY_ID}"')))
    assert movido.location.line == 2
    assert movido.fingerprint == achado.fingerprint
