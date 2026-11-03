"""Testes dos verificadores estruturais offline (`rules/estrutural.py`).

Um verificador por família: o caso VALIDO (forma fina correta), o caso
INVALIDO (marcador grosseiro presente, forma fina quebrada — tipicamente um
fixture truncado) e o caso NAO_APLICAVEL (nem o marcador grosseiro). Mais
uma propriedade transversal: nenhum verificador levanta exceção para
qualquer entrada.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from guardiao.rules.estrutural import (
    Estado,
    verificar_aws_akid,
    verificar_git_sha,
    verificar_jwt,
    verificar_mercadopago,
    verificar_sendgrid,
    verificar_slack,
    verificar_stripe,
    verificar_uuid,
)

TODOS_OS_VERIFICADORES = (
    verificar_jwt,
    verificar_aws_akid,
    verificar_sendgrid,
    verificar_slack,
    verificar_stripe,
    verificar_mercadopago,
    verificar_uuid,
    verificar_git_sha,
)

# JWT real (header `{"alg":"HS256","typ":"JWT"}`, payload `{"sub":"abc"}`).
_JWT_VALIDO = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJhYmMifQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
)


def test_jwt_valido_decodifica_header_e_payload() -> None:
    assert verificar_jwt(_JWT_VALIDO) == Estado.VALIDA


def test_jwt_fixture_truncado_marca_invalida() -> None:
    # Documentação/log cortam o payload no meio — ainda tem 3 segmentos
    # separados por ponto (marcador grosseiro), mas o segmento cortado não
    # decodifica mais para JSON válido.
    header, payload, assinatura = _JWT_VALIDO.split(".")
    truncado = f"{header}.{payload[:6]}.{assinatura}"
    assert verificar_jwt(truncado) == Estado.INVALIDA


def test_jwt_sem_forma_de_jwt_e_nao_aplicavel() -> None:
    assert verificar_jwt("isto nao tem nem um ponto") == Estado.NAO_APLICAVEL


def test_aws_akid_valido() -> None:
    assert verificar_aws_akid("AKIA" + "Z7Q2LMN4XYWVERPD") == Estado.VALIDA


def test_aws_akid_truncado_marca_invalida() -> None:
    assert verificar_aws_akid("AKIA" + "Z7Q2LMN4") == Estado.INVALIDA


def test_aws_akid_sem_prefixo_conhecido_e_nao_aplicavel() -> None:
    assert verificar_aws_akid("XKIAZ7Q2LMN4XYWVERPD") == Estado.NAO_APLICAVEL


def test_sendgrid_valido() -> None:
    valor = "SG." + "A1b2C3d4E5f6G7h8J9k0L1" + "." + "M2n3O4p5Q6r7S8t9U0v1W2x3Y4z5A6b7C8d9E0f1G2h"
    assert verificar_sendgrid(valor) == Estado.VALIDA


def test_sendgrid_truncado_marca_invalida() -> None:
    valor = "SG." + "A1b2C3d4E5f6G7h8J9k0L1" + "." + "M2n3O4p5Q6r7"  # segundo segmento cortado
    assert verificar_sendgrid(valor) == Estado.INVALIDA


def test_sendgrid_sem_prefixo_e_nao_aplicavel() -> None:
    assert verificar_sendgrid("nao-e-sendgrid") == Estado.NAO_APLICAVEL


def test_slack_token_classico_valido() -> None:
    assert verificar_slack("xoxb-2417281839-9384756123-4Kd9Xm2Pq7Rt") == Estado.VALIDA


def test_slack_token_sem_separacao_marca_invalida() -> None:
    # Prefixo certo, mas um blob único em vez de workspace-id/actor-id/segredo.
    assert verificar_slack("xoxb-4Kd9Xm2Pq7RtBlobUnicoSemTracos") == Estado.INVALIDA


def test_slack_sem_prefixo_e_nao_aplicavel() -> None:
    assert verificar_slack("nao-e-slack") == Estado.NAO_APLICAVEL


def test_stripe_valido() -> None:
    assert verificar_stripe("sk_live_" + "51H9xQmKz3PqRtYuVwXqBnDzFgHiJkLmN") == Estado.VALIDA


def test_stripe_truncado_marca_invalida() -> None:
    assert verificar_stripe("sk_live_" + "51H9xQmKz3") == Estado.INVALIDA


def test_stripe_sem_prefixo_e_nao_aplicavel() -> None:
    assert verificar_stripe("nao-e-stripe") == Estado.NAO_APLICAVEL


def test_mercadopago_valido() -> None:
    # appid - data 07/12 10h - hash 32 hex - userid.
    valor = "APP_USR-4934588586838432-071210-" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" + "-2880736"
    assert verificar_mercadopago(valor) == Estado.VALIDA


def test_mercadopago_mes_impossivel_marca_invalida() -> None:
    # Mês 13 não existe: bloco de data impossível, não é instante real.
    valor = "APP_USR-4934588586838432-137210-" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" + "-2880736"
    assert verificar_mercadopago(valor) == Estado.INVALIDA


def test_mercadopago_hash_truncado_marca_invalida() -> None:
    valor = "APP_USR-4934588586838432-071210-" + "a1b2c3d4e5f6" + "-2880736"
    assert verificar_mercadopago(valor) == Estado.INVALIDA


def test_mercadopago_sem_prefixo_e_nao_aplicavel() -> None:
    assert verificar_mercadopago("nao-e-mercadopago") == Estado.NAO_APLICAVEL


def test_uuid_v4_valido() -> None:
    # Nibble de versão `4`, variante `a` (10xx): UUID v4 bem formado.
    assert verificar_uuid("a1b2c3d4-e5f6-4a7b-a8c9-d0e1f2a3b4c5") == Estado.VALIDA


def test_uuid_nulo_e_valido() -> None:
    assert verificar_uuid("00000000-0000-0000-0000-000000000000") == Estado.VALIDA


def test_uuid_versao_impossivel_marca_invalida() -> None:
    # Nibble de versão `0` (fora de 1-5) com hífens nos lugares certos: tem a
    # forma grosseira de UUID, mas não é um UUID RFC 4122 válido.
    assert verificar_uuid("a1b2c3d4-e5f6-0a7b-a8c9-d0e1f2a3b4c5") == Estado.INVALIDA


def test_uuid_variante_impossivel_marca_invalida() -> None:
    # Variante fora de 8/9/a/b.
    assert verificar_uuid("a1b2c3d4-e5f6-4a7b-18c9-d0e1f2a3b4c5") == Estado.INVALIDA


def test_uuid_sem_forma_e_nao_aplicavel() -> None:
    assert verificar_uuid("isto-nao-e-um-uuid") == Estado.NAO_APLICAVEL


def test_git_sha_valido() -> None:
    assert verificar_git_sha("a" * 40) == Estado.VALIDA


def test_git_sha_truncado_marca_invalida() -> None:
    assert verificar_git_sha("a" * 7) == Estado.INVALIDA


def test_git_sha_nao_hex_e_nao_aplicavel() -> None:
    assert verificar_git_sha("nao-e-hex-nem-de-longe") == Estado.NAO_APLICAVEL


@given(st.text(max_size=200))
def test_nenhum_verificador_levanta_excecao(valor: str) -> None:
    for verificador in TODOS_OS_VERIFICADORES:
        assert isinstance(verificador(valor), Estado)
