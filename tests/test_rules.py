from __future__ import annotations

import pytest

from guardiao.core.engine import Scanner
from guardiao.rules.definitions import looks_like_placeholder
from guardiao.rules.registry import all_rules, rules_by_id
from tests.conftest import (
    AWS_KEY_ID,
    DB_URI,
    GH_TOKEN,
    GITLAB_PAT,
    GOOGLE_KEY,
    JWT,
    MERCADOPAGO_PUBLIC_KEY,
    MERCADOPAGO_TOKEN,
    NPM_TOKEN,
    PRIVATE_KEY_HEADER,
    SENDGRID_KEY,
)


def _rule_ids(text: str) -> set[str]:
    return {f.rule_id for f in Scanner().scan_text("x.txt", text)}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f'k = "{AWS_KEY_ID}"', "aws-access-key-id"),
        (f'k = "{GH_TOKEN}"', "github-token"),
        (f'k = "{GOOGLE_KEY}"', "google-api-key"),
        (f'url = "{DB_URI}"', "db-connection-uri"),
        (f'jwt = "{JWT}"', "jwt"),
        (f'k = "{GITLAB_PAT}"', "gitlab-pat"),
        (f'k = "{NPM_TOKEN}"', "npm-token"),
        (f'k = "{SENDGRID_KEY}"', "sendgrid-api-key"),
        (f'k = "{MERCADOPAGO_TOKEN}"', "mercadopago-access-token"),
        (PRIVATE_KEY_HEADER, "private-key"),
        ('api_key = "S3cr3tP4ssw0rdX9zQvB"', "generic-assignment"),
        ("meu cpf: 123.456.789-09", "cpf"),
    ],
)
def test_rule_positive(text: str, expected: str) -> None:
    assert expected in _rule_ids(text)


@pytest.mark.parametrize(
    "text",
    [
        'name = "john"',
        'greeting = "hello world"',
        "x = 42",
        'password = "password"',  # entropia baixa demais
        'key = "AKIAIOSFODNN7EXAMPLE"',  # exemplo canônico da AWS
        'token = "your-token-here"',  # placeholder
        'label = "glpat-demo"',  # curto demais para ser um glpat real
        'note = "npm_install runs quickly"',  # 'npm_' sem token de 36 chars
        'msg = "SG is the SendGrid abbreviation"',  # 'SG' sem estrutura de chave
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


def test_rule_ids_are_unique() -> None:
    assert len(rules_by_id()) == len(all_rules())


def test_placeholder_detection() -> None:
    assert looks_like_placeholder("AKIAIOSFODNN7EXAMPLE")
    assert looks_like_placeholder("your_api_key_here")
    assert looks_like_placeholder("xxxxxxxxxxxxxxxx")
    assert not looks_like_placeholder(AWS_KEY_ID)
