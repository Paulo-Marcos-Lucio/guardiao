"""Modelos de domínio do Guardião.

O objeto :class:`Finding` guarda o segredo cru em ``secret`` apenas para permitir
mascarar a linha de contexto. Esse campo **nunca** é serializado nem impresso —
os renderizadores usam exclusivamente ``redacted``, e a *fingerprint* publicada é
derivada do valor **ocultado**, não do segredo (ver :attr:`Finding.fingerprint`).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """Severidade de um achado, ancorada nas faixas usuais do CVSS."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Location:
    """Onde um segredo foi encontrado."""

    path: str
    line: int
    column: int = 1
    commit: str | None = None

    def as_str(self) -> str:
        base = f"{self.path}:{self.line}"
        return f"{base}@{self.commit}" if self.commit else base


@dataclass(frozen=True)
class Finding:
    """Um segredo potencial encontrado por uma regra."""

    rule_id: str
    title: str
    severity: Severity
    location: Location
    secret: str
    redacted: str
    line_preview: str
    entropy: float | None = None
    cwe: str | None = None
    owasp: str | None = None
    category: str = "secret"
    recommendation: str = ""
    #: Quantos blobs distintos do histórico Git carregavam ESTE mesmo achado
    #: (mesma regra, arquivo e valor ocultado). 1 num scan de árvore; >1 quando o
    #: `--git-history` encontra o segredo repetido em vários commits — reportado como
    #: UM achado para não multiplicar o mesmo vazamento por dezenas de linhas.
    occurrences: int = 1
    #: Último commit (na ordem de varredura) em que o achado reincidiu; `None` fora
    #: do histórico ou quando aparece uma vez só. O primeiro fica em ``location.commit``.
    commit_last: str | None = None

    @property
    def fingerprint(self) -> str:
        """Identidade estável de um achado — publicável em SARIF, JSON e baseline.

        Derivada de ``(regra, arquivo, valor ocultado)``. **Não** inclui o segredo
        cru: um hash truncado do segredo é um compromisso quebrável — para uma senha
        humana como ``Brasil@2024``, um dicionário a recupera em dezenas de
        tentativas, e a fingerprint viaja no SARIF que o CI publica no Code Scanning.
        Como só entra aqui dado que **já** aparece no relatório, força bruta não
        acrescenta informação nenhuma ao atacante.

        Também **não** inclui a linha: mover o código não pode fechar o alerta no
        GitHub e abrir outro idêntico.

        Custo aceito: dois segredos curtos com a mesma inicial, na mesma regra e no
        mesmo arquivo, colidem — para o baseline isso é próximo do comportamento
        desejado ("a dívida deste arquivo está aceita"), mas rotacionar um segredo
        curto pode não gerar achado novo. Rode ``--update-baseline`` ao rotacionar.
        """
        digest = hashlib.sha256()
        digest.update(self.rule_id.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(self.location.path.replace("\\", "/").encode("utf-8"))
        digest.update(b"\x00")
        digest.update(self.redacted.encode("utf-8"))
        return digest.hexdigest()[:16]
