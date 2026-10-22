"""Verificadores estruturais offline por família de credencial.

Cada função aqui responde uma pergunta estreita: o valor tem a FORMA
estruturalmente correta de uma família de credencial — não se o segredo é
*verdadeiro* (exigiria chamar a API do fornecedor; este módulo nunca faz
rede) nem se *parece exemplo de documentação* (esse eixo já existe em
:func:`guardiao.rules.definitions.is_obvious_fake` e é independente deste).
Um valor pode ser estruturalmente VALIDO e ainda ser um exemplo de doc; os
dois eixos compõem, não substituem um ao outro.

Cada verificador devolve um :class:`Estado`, nunca levanta exceção:

- ``VALIDA``: o valor tem a forma FINA e correta da família.
- ``INVALIDA``: o valor tem o marcador GROSSEIRO da família (prefixo,
  número de segmentos) mas quebra a forma fina — o caso canônico é um
  fixture truncado (documentação, log cortado, teste que encurtou o valor
  para caber na página).
- ``NAO_APLICAVEL``: o valor não tem nem o marcador grosseiro; o
  verificador simplesmente não se aplica a ele.

Deliberadamente conservador: cada checagem fina aqui é um fato ESPECIFICADO
em RFC (4122 para UUID, 7519 para JWT) ou já ESTABELECIDO no próprio
código deste repositório (os comprimentos exatos das regras de
``rules/definitions.py``, a estrutura ``APP_USR-<appid>-<MMDDHH>-<hash>-
<userid>`` documentada em ``tests/conftest.py``) — nunca um comportamento
interno de fornecedor inferido sem fonte verificável. Por isso não há, por
exemplo, checagem de alfabeto para AWS AKID: a afirmação pública de que a
AWS restringe esses 16 caracteres a um subconjunto não tem confirmação
neste repositório, e um falso-positivo nessa checagem rebaixaria um achado
real — melhor não ter a checagem do que ter uma errada.

``INVALIDA`` aqui nunca é motivo para SUPRIMIR um achado — isso é decisão
de quem consome este módulo; aqui só existe o sinal "a forma não fecha".
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from enum import Enum


class Estado(Enum):
    """Resultado de um verificador estrutural."""

    VALIDA = "valida"
    INVALIDA = "invalida"
    NAO_APLICAVEL = "nao_aplicavel"


# --------------------------------------------------------------------------- #
# JWT — RFC 7519: header.payload.signature, header e payload são objetos JSON
# em base64url. A regra `jwt` de `rules/definitions.py` só exige que cada
# segmento COMECE com `eyJ` e tenha 10+ chars — não decodifica nada. Aqui a
# forma fina decodifica os dois primeiros segmentos de verdade: um fixture
# truncado (header ou payload cortado no meio) ainda casa o regex grosseiro,
# mas quebra o decode.
# --------------------------------------------------------------------------- #
_JWT_GROSSEIRO = re.compile(r"^([^.]+)\.([^.]+)\.([^.]*)$")


def _decodifica_base64url_json(segmento: str) -> object | None:
    padded = segmento + "=" * (-len(segmento) % 4)
    try:
        bruto = base64.urlsafe_b64decode(padded)
        resultado: object = json.loads(bruto)
    except (binascii.Error, ValueError):
        return None
    return resultado


def verificar_jwt(valor: str) -> Estado:
    """JWT: header e payload precisam decodificar para objeto JSON de verdade."""
    m = _JWT_GROSSEIRO.match(valor)
    if m is None:
        return Estado.NAO_APLICAVEL
    header, payload, _assinatura = m.groups()
    for segmento in (header, payload):
        if not isinstance(_decodifica_base64url_json(segmento), dict):
            return Estado.INVALIDA
    return Estado.VALIDA


# --------------------------------------------------------------------------- #
# AWS Access Key ID — mesmo prefixo que a regra `aws-access-key-id` de
# `rules/definitions.py`. O marcador grosseiro é o prefixo conhecido; a forma
# fina é o corpo com EXATAMENTE 16 caracteres (o mesmo comprimento que a
# regra de produção já exige — um corpo mais curto é tentativa truncada).
# --------------------------------------------------------------------------- #
_AWS_PREFIXOS = ("AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA")
_AWS_GROSSEIRO = re.compile(r"^(?:" + "|".join(_AWS_PREFIXOS) + r")([A-Z0-9]*)$")


def verificar_aws_akid(valor: str) -> Estado:
    """AWS Access Key ID: prefixo conhecido + corpo de exatamente 16 caracteres."""
    m = _AWS_GROSSEIRO.match(valor)
    if m is None:
        return Estado.NAO_APLICAVEL
    return Estado.VALIDA if len(m.group(1)) == 16 else Estado.INVALIDA


# --------------------------------------------------------------------------- #
# SendGrid API Key — `SG.<22 chars>.<43 chars>`, mesmos comprimentos exatos
# da regra `sendgrid-api-key`.
# --------------------------------------------------------------------------- #
_SENDGRID_GROSSEIRO = re.compile(r"^SG\.([0-9A-Za-z_-]*)\.([0-9A-Za-z_-]*)$")


def verificar_sendgrid(valor: str) -> Estado:
    """SendGrid API Key: `SG.` + segmento de 22 chars + `.` + segmento de 43 chars."""
    m = _SENDGRID_GROSSEIRO.match(valor)
    if m is None:
        return Estado.NAO_APLICAVEL
    id_parte, segredo_parte = m.groups()
    valido = len(id_parte) == 22 and len(segredo_parte) == 43
    return Estado.VALIDA if valido else Estado.INVALIDA


# --------------------------------------------------------------------------- #
# Slack token — `xox[baprs]-...`. Um token clássico (bot/user) sempre tem o
# id do workspace e o id do ator antes do segredo em si:
# `xoxb-<workspace-id>-<actor-id>-<segredo>` — pelo menos 3 partes separadas
# por `-` no corpo. Um blob único sem essa separação é a forma grosseira
# (prefixo certo) mas não a forma fina de um token real.
# --------------------------------------------------------------------------- #
_SLACK_GROSSEIRO = re.compile(r"^xox[baprs]-(.+)$")


def verificar_slack(valor: str) -> Estado:
    """Slack token: corpo com pelo menos 3 partes (workspace-id, actor-id, segredo)."""
    m = _SLACK_GROSSEIRO.match(valor)
    if m is None:
        return Estado.NAO_APLICAVEL
    partes_preenchidas = [p for p in m.group(1).split("-") if p]
    return Estado.VALIDA if len(partes_preenchidas) >= 3 else Estado.INVALIDA


# --------------------------------------------------------------------------- #
# Stripe Secret Key — `(sk|rk)_live_` + corpo. A regra `stripe-secret-key` já
# exige 24..99 chars; o piso de 24 é a forma fina aqui.
# --------------------------------------------------------------------------- #
_STRIPE_GROSSEIRO = re.compile(r"^(?:sk|rk)_live_([0-9a-zA-Z]*)$")


def verificar_stripe(valor: str) -> Estado:
    """Stripe Secret Key: prefixo `sk_live_`/`rk_live_` + corpo de 24+ caracteres."""
    m = _STRIPE_GROSSEIRO.match(valor)
    if m is None:
        return Estado.NAO_APLICAVEL
    return Estado.VALIDA if len(m.group(1)) >= 24 else Estado.INVALIDA


# --------------------------------------------------------------------------- #
# Mercado Pago Access Token — `APP_USR-<appid>-<MMDDHH>-<hash 32 hex>-<userid>`,
# a mesma estrutura documentada no comentário de `MERCADOPAGO_TOKEN` em
# `tests/conftest.py`. O bloco de 6 dígitos é mês+dia+hora: um bloco cujo mês,
# dia ou hora é impossível (ex.: mês 13) não descreve nenhum instante real —
# é fixture/placeholder, não token de produção.
# --------------------------------------------------------------------------- #
_MERCADOPAGO_GROSSEIRO = re.compile(r"^APP_USR-(\d+)-(\d*)-([0-9a-f]*)-(\d+)$")


def verificar_mercadopago(valor: str) -> Estado:
    """Mercado Pago Access Token: bloco de data MMDDHH real + hash de 32 hex."""
    m = _MERCADOPAGO_GROSSEIRO.match(valor)
    if m is None:
        return Estado.NAO_APLICAVEL
    _app_id, data, hexa, _user_id = m.groups()
    if len(data) != 6 or len(hexa) != 32:
        return Estado.INVALIDA
    mes, dia, hora = int(data[0:2]), int(data[2:4]), int(data[4:6])
    if 1 <= mes <= 12 and 1 <= dia <= 31 and 0 <= hora <= 23:
        return Estado.VALIDA
    return Estado.INVALIDA


# --------------------------------------------------------------------------- #
# UUID — RFC 4122. O marcador grosseiro é a forma 8-4-4-4-12 em hex; a forma
# fina confere o nibble de versão (§4.1.3: 1-5) e os bits de variante
# (§4.1.1: `10xx`, ou seja primeiro hex do 4º grupo em 8/9/a/b) — uma cadeia
# só coincidentemente separada por hífens nessas posições não é um UUID
# RFC 4122 de verdade. O UUID nulo (§4.1.7) é caso especial: é forma
# reservada, não lixo.
# --------------------------------------------------------------------------- #
_UUID_GROSSEIRO = re.compile(
    r"^([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$"
)
_UUID_NULO = "00000000-0000-0000-0000-000000000000"


def verificar_uuid(valor: str) -> Estado:
    """UUID: nibble de versão (1-5) e bits de variante (RFC 4122) coerentes."""
    m = _UUID_GROSSEIRO.match(valor)
    if m is None:
        return Estado.NAO_APLICAVEL
    if valor.lower() == _UUID_NULO:
        return Estado.VALIDA
    versao = m.group(3)[0].lower()
    variante = m.group(4)[0].lower()
    if versao in "12345" and variante in "89ab":
        return Estado.VALIDA
    return Estado.INVALIDA


# --------------------------------------------------------------------------- #
# SHA de commit (git-sha) — `_GIT_SHA` de `rules/definitions.py`: 40 hex
# (SHA-1 de commit, ou action pinada por SHA). O marcador grosseiro é
# "só hex, entre 4 (mínimo de abreviação do git) e 40 chars"; a forma fina
# exige o comprimento cheio de 40 — um SHA abreviado ou cortado no meio não
# é o que essa família de regra procura.
# --------------------------------------------------------------------------- #
_GIT_SHA_GROSSEIRO = re.compile(r"^[0-9a-fA-F]+$")


def verificar_git_sha(valor: str) -> Estado:
    """SHA de commit: só hex e comprimento cheio de 40 caracteres (SHA-1)."""
    if _GIT_SHA_GROSSEIRO.match(valor) is None or not (4 <= len(valor) <= 40):
        return Estado.NAO_APLICAVEL
    return Estado.VALIDA if len(valor) == 40 else Estado.INVALIDA
