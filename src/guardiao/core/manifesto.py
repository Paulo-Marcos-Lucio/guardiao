"""Manifesto de hash do corpus: compartilhar segredos de teste sem publicá-los.

Um laboratório/parceiro que quer contribuir um corpus de segredos reais
(vazados, rotacionados) para validar regras do Guardião não pode mandar o
corpus em claro — isso seria publicar justamente o que o `guardiao` existe
para impedir. A saída é um *manifesto*: por segredo, um sal aleatório de 32
bytes (:data:`SALT_BYTES`) e o HMAC-SHA256 do segredo com esse sal. O sal é
por-segredo (não um sal único para o corpus inteiro) para que o manifesto não
vire um dicionário invertível por força bruta a partir de um sal conhecido, e
para que dois segredos iguais no corpus não produzam o mesmo HMAC entre si
(o que já revelaria uma repetição). Nenhum fragmento do segredo — nem os
caracteres de ponta que :mod:`guardiao.core.redaction` mantém no console —
entra no manifesto: só sal, HMAC e o comprimento.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
from dataclasses import dataclass
from os import urandom
from pathlib import Path

MANIFESTO_VERSION = 1
SALT_BYTES = 32


@dataclass(frozen=True)
class EntradaManifesto:
    salt: str
    hmac: str
    comprimento: int


def hash_segredo(segredo: str, salt: bytes | None = None) -> EntradaManifesto:
    """HMAC-SHA256 de `segredo` com um sal aleatório de :data:`SALT_BYTES` bytes.

    `salt` só existe como parâmetro para tornar a função determinística em teste;
    a CLI nunca o passa, e cada chamada sem ele gera um sal novo via :func:`os.urandom`.
    """
    sal = salt if salt is not None else urandom(SALT_BYTES)
    assinatura = hmac_mod.new(sal, segredo.encode("utf-8"), hashlib.sha256).hexdigest()
    return EntradaManifesto(salt=sal.hex(), hmac=assinatura, comprimento=len(segredo))


def build_manifesto_document(segredos: list[str]) -> dict[str, object]:
    entradas = [hash_segredo(s) for s in segredos]
    comprimentos = sorted({e.comprimento for e in entradas})
    return {
        "version": MANIFESTO_VERSION,
        "tool": "guardiao",
        "comando": "hash-corpus",
        "nota": (
            "Cada segredo recebe um sal aleatório de 32 bytes e um HMAC-SHA256 próprio "
            "deste sal. Este arquivo não contém o segredo nem fragmento dele — só sal, "
            "HMAC e comprimento."
        ),
        "total": len(entradas),
        "comprimentos": comprimentos,
        "itens": [{"salt": e.salt, "hmac": e.hmac, "comprimento": e.comprimento} for e in entradas],
    }


def hash_corpus(entrada: Path, saida: Path) -> int:
    """Lê um segredo por linha de `entrada`, grava o manifesto em `saida`.

    Devolve a quantidade de segredos processados (linhas não vazias).
    """
    segredos = [
        linha for linha in Path(entrada).read_text(encoding="utf-8").splitlines() if linha.strip()
    ]
    documento = build_manifesto_document(segredos)
    Path(saida).write_text(
        json.dumps(documento, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return len(segredos)
