"""Fixtures compartilhadas: segredos de teste (falsos, mas que casam) e projeto plantado."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# Garante largura suficiente para o rich não truncar as tabelas nos testes.
os.environ["COLUMNS"] = "200"

# Segredos sintéticos: casam com as regras, mas não são reais nem placeholders.
# Os que têm formato reconhecido pelo secret-scanning do GitHub são montados por
# concatenação, para que o literal completo nunca exista no arquivo versionado.
AWS_KEY_ID = "AKIAZ7Q2LMN4XYWV8RPD"
GH_TOKEN = "ghp_Rk8xY2mN4pQ7wLvB3cD5fG6hJ9kMnP2qAtZ7u"
GOOGLE_KEY = "AIzaSyD9kQ2mN4pQ7wLvB3cD5fG6hJ9kMnP2qAt"
DB_URI = "postgres://appuser:S3cr3tPwd9xQ@db.internal:5432/app"
GENERIC_LINE = 'api_key = "S3cr3tP4ssw0rdX9zQvB"'
GENERIC_SECRET = "S3cr3tP4ssw0rdX9zQvB"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJhYmMiLCJyb2xlIjoiYWRtaW4ifQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
)
PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
CPF_VALIDO = "529.982.247-25"  # dígito verificador correto, fora dos CPFs de tutorial
CNPJ_VALIDO = "11.222.333/0001-81"

# Provedores adicionais: tokens sintéticos que respeitam o formato público (sem placeholders).
GITLAB_PAT = "glpat-" + "A1b2C3d4E5f6G7h8J9k0"  # glpat- + 20 chars
NPM_TOKEN = "npm_" + "A1b2C3d4E5f6G7h8J9k0L1m2N3o4P5q6R7s8"  # npm_ + 36 chars
SENDGRID_KEY = (
    "SG." + "A1b2C3d4E5f6G7h8J9k0L1" + "." + "M2n3O4p5Q6r7S8t9U0v1W2x3Y4z5A6b7C8d9E0f1G2h"
)
# Twilio API Key SID: SK + 32 hex minúsculo (34 chars no total). Sintético.
TWILIO_API_KEY = "SK" + "0a1b2c3d4e5f6071" + "8293a4b5c6d7e8f9"
# DigitalOcean personal access token: dop_v1_ + 64 hex. Sintético.
DIGITALOCEAN_TOKEN = (
    "dop_v1_" + "0a1b2c3d4e5f6071" + "8293a4b5c6d7e8f9" + "1f2e3d4c5b6a7988" + "9a8b7c6d5e4f3021"
)
# Hugging Face access token: hf_ + 36 alfanuméricos. Sintético.
HUGGINGFACE_TOKEN = "hf_" + "Rk8xY2mN4pQ7wLvB" + "3cD5fG6hJ9kMnP2q" + "AtZ7"
# Access token do Mercado Pago: APP_USR-<appid>-<MMDDHH>-<hash 32 hex>-<userid>
MERCADOPAGO_TOKEN = (
    "APP_USR-4934588586838432-071234-" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" + "-2880736"
)
# Public key do Mercado Pago (NÃO é segredo de backend): primeiro segmento é hex, não dígitos.
MERCADOPAGO_PUBLIC_KEY = "APP_USR-d0a26210-0b3e-4c1a-8f7a-479f0400869e"
# Shopify access token: shp<tipo>_ + 32 hex. Sintético.
SHOPIFY_TOKEN = "shp" + "at_" + "0a1b2c3d4e5f6071" + "8293a4b5c6d7e8f9"
# Doppler personal token: dp.pt. + 43 base62. Sintético.
DOPPLER_TOKEN = "dp." + "pt." + "A1b2C3d4E5f6G7h8J9k0" + "L1m2N3o4P5q6R7s8T9u0" + "vW1"
# Linear API key pessoal: lin_api_ + 40 base62. Sintético.
LINEAR_KEY = "lin_" + "api_" + "A1b2C3d4E5f6G7h8J9k0" + "L1m2N3o4P5q6R7s8T9u0"
# Stripe: sk_live_ + 24..99 alfanuméricos. Sintético.
STRIPE_KEY = "sk_" + "live_" + "51H9xQmKz3PqRtYuVwXqBnDzFgHiJkLmN"
# A MESMA chave contendo a sequência 'abcdefgh' — o filtro de placeholder por substring
# a suprimia em silêncio (uma CRITICAL sumindo por coincidência de 8 letras).
STRIPE_KEY_COM_ALFABETO = "sk_" + "live_" + "51H9xQmKz3PqRtYuVwXaBcDeFgHiJkLmN"
# AWS Secret Access Key: 40 chars [0-9a-zA-Z/+], entropia alta. Sintético.
AWS_SECRET_KEY = "wQ7z" + "Nv2Kp9Lx" + "3Ry6Tb8Md" + "4Fh1Jc5Gs" + "0Wq7Ze2XuB"
# GitHub fine-grained PAT: github_pat_ + 22..255 [0-9A-Za-z_]. Sintético.
GITHUB_PAT_FG = "github_" + "pat_" + "11ABCDEFG0" + "aZ9yX8wV7uT6sR5qP4oN3m"
# Slack bot token: xox<b|a|p|r|s>- + 10..48 [0-9A-Za-z-]. Sintético.
SLACK_TOKEN = "xox" + "b-" + "2417281839" + "-4Kd9Xm2Pq7Rt"
SLACK_WEBHOOK = (
    "https://hooks.slack.com/services/" + "T02K7QW9L/" + "B04MZ8XR1/" + "u7Kq2Xm9Pd4Rt6Wn1Zs8Yv3B"
)
BASIC_AUTH_URL = "https://operador:Zx9r2Pq8LmNv3@painel.acme.com.br/api"
# Valor humano forte, do tipo que aparece de verdade num .env de produção.
SENHA_DE_PRODUCAO = "Nordeste2019!Rj"


@pytest.fixture
def planted_dir(tmp_path: Path) -> Path:
    """Cria um mini-projeto com segredos plantados e ruído benigno."""
    (tmp_path / "settings.py").write_text(
        "\n".join(
            [
                "DEBUG = True",
                f'AWS_ACCESS_KEY_ID = "{AWS_KEY_ID}"',
                f'DATABASE_URL = "{DB_URI}"',
                GENERIC_LINE,
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "tokens.js").write_text(
        f'const gh = "{GH_TOKEN}";\nconst g = "{GOOGLE_KEY}";\n', encoding="utf-8"
    )
    (tmp_path / "key.pem").write_text(
        f"{PRIVATE_KEY_HEADER}\nMIIBOgIBAAJBAKQ...\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    (tmp_path / "benign.txt").write_text(
        'username = "john"\ngreeting = "hello world"\ncount = 42\n', encoding="utf-8"
    )
    (tmp_path / "allowed.py").write_text(
        f'demo = "{AWS_KEY_ID}"  # guardiao:allow\n', encoding="utf-8"
    )
    return tmp_path
