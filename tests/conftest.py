"""Fixtures compartilhadas: segredos de teste (falsos, mas que casam) e projeto plantado."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# Garante largura suficiente para o rich não truncar as tabelas nos testes.
os.environ["COLUMNS"] = "200"

# Segredos sintéticos: casam com as regras, mas não são reais nem placeholders.
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
