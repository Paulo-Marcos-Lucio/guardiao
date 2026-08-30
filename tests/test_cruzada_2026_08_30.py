"""Invariantes da 2ª onda da auditoria cruzada (2026-08-30).

Cada teste ataca a CLASSE (a causa-raiz), não o exemplo isolado, e traz CONTRAPROVA — a
correção não pode abrir falso-negativo. São de PERTINÊNCIA (o id certo aparece/não aparece),
nunca igualdade de conjunto de regras.

* #1  `config-file-secret`: valor SEM aspas com forma estrutural (caminho/versão/cipher/
      header/enum) caía no ramo "3 classes" e virava HIGH — regressão introduzida pelo recall.
* #2  `db-connection-uri`: não enxergava Oracle/Snowflake/ClickHouse/Cassandra nem a forma
      THIN do Oracle (`user/senha@`).
"""

from __future__ import annotations

import pytest

from guardiao.core.engine import Scanner


def _ids(path: str, text: str) -> list[str]:
    return [f.rule_id for f in Scanner().scan_text(path, text)]


# --------------------------------------------------------------------------- #
# #1  config-file-secret cega forma estrutural de NÃO-segredo
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "linha",
    [
        "token: v2.14.3-alpine",  # versão semver
        "secret: /etc/app/tls/Server.key",  # caminho POSIX
        "password: /var/run/secrets/DB_Pass",  # caminho de docker-secret
        "secret: TLSv1.3-AES256-SHA",  # cipher-suite
        "apikey: X-Company-ApiKey",  # nome de header
        "secret: HS256-RS512-mix",  # algoritmo/enum
        "secret: C:\\Users\\app\\Key.pem",  # caminho do Windows
        "token: 1.2.0",  # versão nua
        "secret: ../secrets/id_rsa",  # caminho relativo
    ],
)
def test_config_forma_estrutural_nao_e_segredo(linha: str) -> None:
    # A CLASSE: em arquivo de config o valor vem sem aspas; caminho/versão/cipher/header/enum
    # NÃO são credenciais e não podem virar `config-file-secret`.
    assert "config-file-secret" not in _ids("values.yaml", linha)


def test_config_alta_entropia_ainda_dispara() -> None:
    # CONTRAPROVA: um segredo real de alta entropia num config (o caso `Xk9E…oDM1` do corpus
    # FN) NÃO é uma forma estrutural e TEM de continuar disparando.
    assert "config-file-secret" in _ids("values.yaml", "apikey: Xk9E7pQ2mZ4tR8sV1nW6bL3jC5xN0oDM1")


def test_config_senha_humana_com_simbolo_ainda_dispara() -> None:
    # CONTRAPROVA: senha humana mista (não é caminho/versão/enum) segue reportada.
    assert "config-file-secret" in _ids("app.properties", "db.password=Br4sil@Prod2024x")


def test_forma_estrutural_nao_afeta_generic_assignment() -> None:
    # A correção é ESCOPADA a config (valor sem aspas); a genérica (valor entre aspas em
    # código) não é tocada — senha humana curta continua pega.
    assert "generic-assignment" in _ids("app.py", 'PASSWORD = "Brasil@2024"')


# --------------------------------------------------------------------------- #
# #2  db-connection-uri enxerga Oracle e dialetos SQLAlchemy
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "uri",
    [
        "oracle+cx_oracle://scott:Tigr3ssP4ss@dbhost:1521/?service_name=orcl",
        "oracle://scott:Tigr3ssP4ss@dbhost:1521/orcl",
        "jdbc:oracle:thin:scott/Tigr3ss3nha!@dbhost:1521:ORCL",  # forma THIN: user/senha@
        "snowflake://user:R3alP4ssXY@account/db",
        "clickhouse://user:R3alP4ssXY@host:9000/db",
        "cassandra://user:R3alP4ssXY@host/ks",
    ],
)
def test_db_uri_oracle_e_dialetos_disparam(uri: str) -> None:
    assert "db-connection-uri" in _ids("settings.py", f'DB_URL = "{uri}"')


def test_db_uri_oracle_sem_credencial_nao_dispara() -> None:
    # CONTRAPROVA: sem `user:senha@`/`user/senha@` não há vazamento — não pode disparar.
    assert "db-connection-uri" not in _ids("settings.py", 'DB_URL = "oracle://localhost/db"')
    assert "db-connection-uri" not in _ids(
        "settings.py", 'DB_URL = "jdbc:oracle:thin:@dbhost:1521:ORCL"'
    )


def test_db_uri_postgres_mysql_sustentados() -> None:
    # SUSTENTA: os esquemas antigos seguem intactos após ampliar a alternância.
    assert "db-connection-uri" in _ids(
        "app.py", "postgresql+psycopg://u:S3cretP4ss@db.prod.internal/app"
    )
    assert "db-connection-uri" in _ids(
        "app.py", "mysql://root:S3cretP4ssword@db.prod.internal:3306/prod"
    )
