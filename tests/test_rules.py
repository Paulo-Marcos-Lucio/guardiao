from __future__ import annotations

from pathlib import Path

import pytest

from guardiao.core.engine import Scanner
from guardiao.rules.definitions import OWASP_EDITION, looks_like_placeholder
from guardiao.rules.registry import all_rules
from tests.conftest import (
    AWS_KEY_ID,
    AWS_SECRET_KEY,
    BASIC_AUTH_URL,
    CNPJ_VALIDO,
    CPF_VALIDO,
    DB_URI,
    DIGITALOCEAN_TOKEN,
    DOPPLER_TOKEN,
    GH_TOKEN,
    GITHUB_PAT_FG,
    GITLAB_PAT,
    GOOGLE_KEY,
    HUGGINGFACE_TOKEN,
    JWT,
    LINEAR_KEY,
    MERCADOPAGO_PUBLIC_KEY,
    MERCADOPAGO_TOKEN,
    NPM_TOKEN,
    PRIVATE_KEY_HEADER,
    SENDGRID_KEY,
    SENHA_DE_PRODUCAO,
    SHOPIFY_TOKEN,
    SLACK_TOKEN,
    SLACK_WEBHOOK,
    STRIPE_KEY,
    TWILIO_API_KEY,
)

# (arquivo, texto, id de regra esperado). O caminho importa: `dotenv-assignment`
# só vale em arquivos de ambiente.
CASOS_POSITIVOS: list[tuple[str, str, str]] = [
    ("x.txt", f'k = "{AWS_KEY_ID}"', "aws-access-key-id"),
    ("x.py", f'aws_secret_access_key = "{AWS_SECRET_KEY}"', "aws-secret-access-key"),
    ("x.txt", f'k = "{GH_TOKEN}"', "github-token"),
    ("x.txt", f'k = "{GITHUB_PAT_FG}"', "github-pat-fine-grained"),
    ("x.txt", f'k = "{GOOGLE_KEY}"', "google-api-key"),
    ("x.txt", f'k = "{SLACK_TOKEN}"', "slack-token"),
    ("x.txt", f'url = "{SLACK_WEBHOOK}"', "slack-webhook"),
    ("x.txt", f'url = "{DB_URI}"', "db-connection-uri"),
    ("x.txt", f'url = "{BASIC_AUTH_URL}"', "basic-auth-url"),
    ("x.txt", f'jwt = "{JWT}"', "jwt"),
    ("x.txt", f'k = "{GITLAB_PAT}"', "gitlab-pat"),
    ("x.txt", f'k = "{NPM_TOKEN}"', "npm-token"),
    ("x.txt", f'k = "{SENDGRID_KEY}"', "sendgrid-api-key"),
    ("x.txt", f'k = "{TWILIO_API_KEY}"', "twilio-api-key"),
    ("x.txt", f'k = "{DIGITALOCEAN_TOKEN}"', "digitalocean-token"),
    ("x.txt", f'k = "{HUGGINGFACE_TOKEN}"', "huggingface-token"),
    ("x.txt", f'k = "{MERCADOPAGO_TOKEN}"', "mercadopago-access-token"),
    ("x.txt", f'k = "{STRIPE_KEY}"', "stripe-secret-key"),
    ("x.txt", f'k = "{SHOPIFY_TOKEN}"', "shopify-token"),
    ("x.txt", f'k = "{DOPPLER_TOKEN}"', "doppler-token"),
    ("x.txt", f'k = "{LINEAR_KEY}"', "linear-api-key"),
    ("x.pem", PRIVATE_KEY_HEADER, "private-key"),
    ("x.py", 'api_key = "S3cr3tP4ssw0rdX9zQvB"', "generic-assignment"),
    (".env", f"DB_PASSWORD={SENHA_DE_PRODUCAO}", "dotenv-assignment"),
    ("x.yml", "api_token: Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zAwBcDeF", "high-entropy-string"),
    ("x.txt", f"meu cpf: {CPF_VALIDO}", "cpf"),
    ("x.txt", f"cnpj da empresa: {CNPJ_VALIDO}", "cnpj"),
]


def _rule_ids(text: str, path: str = "x.txt") -> set[str]:
    return {f.rule_id for f in Scanner().scan_text(path, text)}


@pytest.mark.parametrize(("path", "text", "expected"), CASOS_POSITIVOS)
def test_rule_positive(path: str, text: str, expected: str) -> None:
    assert expected in _rule_ids(text, path)


def test_toda_regra_do_catalogo_tem_caso_positivo() -> None:
    """Meta-teste: um id novo no catálogo nasce coberto, ou o CI reprova.

    Sem isto, acrescentar uma regra sem teste é indistinguível de acrescentar uma
    regra que nunca casa nada.
    """
    testados = {esperado for _, _, esperado in CASOS_POSITIVOS}
    assert {rule.id for rule in all_rules()} - testados == set()


@pytest.mark.parametrize(
    "text",
    [
        'name = "john"',
        'greeting = "hello world"',
        "x = 42",
        'password = "password"',  # valor de exemplo canônico
        'key = "AKIAIOSFODNN7EXAMPLE"',  # exemplo canônico da AWS
        'token = "your-token-here"',  # placeholder
        'label = "glpat-demo"',  # curto demais para ser um glpat real
        'note = "npm_install runs quickly"',  # 'npm_' sem token de 36 chars
        'msg = "SG is the SendGrid abbreviation"',  # 'SG' sem estrutura de chave
        'sku = "SKU-12345 é um código de produto"',  # 'SK' sem 32 hex → não é Twilio
        'doc = "dop_v1_ is our internal doc prefix"',  # 'dop_v1_' sem os 64 hex
        'path = "hf_model_config.json"',  # 'hf_' sem run alfanumérico de 34+
        'note = "shpat_ is the Shopify admin token prefix"',  # 'shpat_' sem 32 hex
        'cfg = "dp.pt. marca nosso deploy-pipeline tag"',  # 'dp.pt.' sem os 43 chars
        'doc = "lin_api_ delimita a seção do Linear"',  # 'lin_api_' sem 40 chars
        'api_key = "${STRIPE_API_KEY}"',  # interpolação de template, não é o segredo
        "numero do pedido: 000.000.000-00",  # dígito verificador inválido → não é CPF
        "cnpj: 12.345.678/0001-00",  # dígito verificador inválido → não é CNPJ
    ],
)
def test_rule_negative(text: str) -> None:
    assert _rule_ids(text) == set()


def test_mercadopago_public_key_is_not_flagged() -> None:
    """A public key do Mercado Pago (uso no frontend) NÃO é o access token de backend:
    o primeiro segmento é hexadecimal, não uma sequência de dígitos."""
    ids = _rule_ids(f'public_key = "{MERCADOPAGO_PUBLIC_KEY}"')
    assert "mercadopago-access-token" not in ids


def test_mercadopago_access_token_is_flagged() -> None:
    ids = _rule_ids(f'access_token = "{MERCADOPAGO_TOKEN}"')
    assert "mercadopago-access-token" in ids


def test_all_rules_have_metadata() -> None:
    for rule in all_rules():
        assert rule.recommendation, f"{rule.id} sem recomendação"
        assert rule.owasp, f"{rule.id} sem mapeamento OWASP"
        assert rule.severity is not None


def test_owasp_e_todo_da_edicao_2025() -> None:
    """Trava a edição do OWASP: 'A03' significa coisas opostas em 2021 e em 2025."""
    prefixos = tuple(f"A{i:02d}:{OWASP_EDITION}" for i in range(1, 11))
    for rule in all_rules():
        assert rule.owasp is not None and rule.owasp.startswith(prefixos), rule.id


def test_ids_duplicados_sao_rejeitados() -> None:
    from guardiao.core.models import Severity
    from guardiao.rules.base import compile_rule
    from guardiao.rules.registry import _assert_unique_ids

    duplicada = compile_rule("dup", "t", Severity.LOW, "x")
    with pytest.raises(ValueError, match="regra duplicada"):
        _assert_unique_ids([duplicada, duplicada])


def test_placeholder_detection() -> None:
    assert looks_like_placeholder("AKIAIOSFODNN7EXAMPLE")
    assert looks_like_placeholder("your_api_key_here")
    assert looks_like_placeholder("xxxxxxxxxxxxxxxx")
    assert not looks_like_placeholder(AWS_KEY_ID)


def test_dotenv_so_vale_em_arquivo_de_ambiente(tmp_path: Path) -> None:
    """`token = expressao` é uma das linhas mais comuns em código: a regra sem aspas
    só pode valer onde `CHAVE=valor` é o formato, senão é falso-positivo em massa."""
    linha = f"DB_PASSWORD={SENHA_DE_PRODUCAO}"
    assert "dotenv-assignment" in _rule_ids(linha, ".env")
    assert "dotenv-assignment" in _rule_ids(linha, "producao.env")
    assert "dotenv-assignment" not in _rule_ids(linha, "settings.py")
    assert "dotenv-assignment" not in _rule_ids(linha, ".env.example")
