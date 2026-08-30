"""Invariantes das correções de FALSO POSITIVO da auditoria cruzada (2026-08-28/29).

Cada teste ataca a CLASSE (a causa-raiz), não o caso isolado. A classe FP-01 (barra de
base64 lida como path) era a mãe dos ~98,6% de FP no terraform-aws.
"""

from __future__ import annotations

from guardiao.core.engine import Scanner


def _ids(path: str, text: str) -> list[str]:
    return [f.rule_id for f in Scanner().scan_text(path, text)]


# ---- FP-01: blob base64 público (SSH/data-URI/PEM inline/DKIM) não é "segredo em path" ----
def test_ssh_pubkey_nao_gera_secret_in_path() -> None:
    linha = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQPfbAqjz7lCLDcWyAE/hkkse4NI/rTuAMrZVf6 user@host"
    assert _ids("authorized_keys", linha) == []


def test_data_uri_base64_nao_gera_achado() -> None:
    linha = ".icon{background:url(data:image/png;base64,iVBORw0KGgqbsw2OKky4wjR8/HBaeHe/DztGgvEHx)}"
    assert _ids("icons.css", linha) == []


def test_pem_publico_inline_com_barra_nao_gera_achado() -> None:
    linha = 'const k = "-----BEGIN PUBLIC KEY-----\\n/PbdITT7ZGluh5O7/CbGV27uJfiu0/rizt7+38Ot7\\n-----END PUBLIC KEY-----"'
    assert _ids("verify.go", linha) == []


def test_dkim_public_key_blob_longo_nao_gera_secret_in_path() -> None:
    linha = 'records = ["v=DKIM1; k=rsa; p=Zw2YnjGpG8o22SKnoHIydgcCvhBHxRTv1NWkzTnI+9L35kzmyj/qszvr/23c9KvRmC9WN6wRL9Y1KCX0oOg3iZYbT3kIWKHrvnYX5xiICDG+Vv/fy3vUGBVH+b/lOItAkEcEbmWrN8D"]'
    assert "secret-in-path" not in _ids("dns/main.tf", linha)


# ---- FP-02: contexto de chave PÚBLICA suprime entropia ----
def test_jwks_modulus_nao_e_segredo() -> None:
    linha = '{"kty": "RSA", "use": "sig", "kid": "k1", "n": "HAjEAeSr_BSebAM_E00h_oGHYCdO10Qz9GbHV30afz", "e": "AQAB"}'
    assert _ids("jwks.json", linha) == []


def test_stripe_publishable_key_nao_e_segredo() -> None:
    assert (
        _ids("config.js", "STRIPE_PUBLISHABLE_KEY=pk_live_51H8xY2eZvKYlo2Cabcdefghijklmnop") == []
    )


# ---- FP-03: hash crypt/PHC não é a senha em claro ----
def test_bcrypt_hash_em_sql_nao_e_segredo() -> None:
    linha = "INSERT INTO users VALUES ('a@b.com', '$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW');"
    assert _ids("seeds.sql", linha) == []


def test_argon2_e_shacrypt_hash_nao_sao_segredo() -> None:
    assert _ids("u.yaml", "  pw: $argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$abcdefghijklmnop") == []
    assert (
        _ids("u.yaml", "  pw: $6$rounds=5000$abcd$Zz9Qe0kZ8t3aBcDeFgHiJkLmNoPqRsTuVwXyZ012345")
        == []
    )


# ---- FP-04: vocabulário de placeholder (EN/PT) ----
def test_placeholders_en_pt_descartados() -> None:
    assert _ids("v.yaml", '  token: "CHANGE_THIS_NOW_1234!"') == []
    assert _ids("v.yaml", '  token: "SUBSTITUA-PELO-TOKEN-REAL-1"') == []


# ---- FP-07: palavra natural (alemão) não é token aleatório ----
def test_palavra_natural_alema_nao_e_segredo() -> None:
    assert _ids("de.properties", "auth.token.label=Zugriffstokenaktualisierungsschluessel") == []


# ---- FP-08: bundle minificado não gera ruído de entropia ----
def test_bundle_minificado_pula_ruido_de_entropia() -> None:
    linha_longa = (
        "var a=" + "x" * 500 + ";var h='c633a1b2c3d4e5f6a7b8c9d0e1f2612f';var b=" + "y" * 200
    )
    assert "high-entropy-string" not in _ids("bundle.js", linha_longa)


# ---- Contraprova: um segredo REAL continua sendo pego (as correções não cegam) ----
def test_segredo_real_continua_detectado() -> None:
    # PERTINÊNCIA do id REAL da regra (`aws-access-key-id`), não "disparou qualquer coisa":
    # a versão antiga usava `"aws-access-key"` (id inexistente) `or _ids(...)`, o que degenerava
    # para "casou alguma regra" e teria passado mesmo se a regra AWS parasse de disparar.
    assert "aws-access-key-id" in _ids("app.py", 'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"')


def test_chave_privada_pem_inline_ainda_e_pega() -> None:
    # PEM PRIVADO inline: a regra de FORMATO (não-entropia) continua pegando pelo cabeçalho.
    linha = 'k = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA1234\\n-----END RSA PRIVATE KEY-----"'
    assert _ids("secret.py", linha) != []
