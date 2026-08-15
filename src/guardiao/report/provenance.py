"""Proveniência do laudo (PROV-01): amarra o JSON/SARIF ao código e às regras.

Defeito de origem: o relatório era um documento solto — não dava para provar com
qual versão do Guardião nem com qual conjunto de regras ele foi gerado, nem
detectar adulteração posterior. Três campos resolvem isso:

- ``commit`` — o SHA do código que rodou (env ``GUARDIAO_COMMIT`` → ``git
  rev-parse HEAD`` → ``None``). Em pacote instalado sem git, cai em ``None`` sem
  quebrar.
- ``ruleset_hash`` — sha256 do catálogo de regras. Muda quando qualquer regra
  muda; dois laudos com o mesmo hash foram medidos com o mesmo conjunto de
  regras.
- ``artifact_sha256`` — sha256 do próprio documento (sem o campo), canônico. O
  cliente recomputa e detecta adulteração.

Molde: ``chaveiro/src/chaveiro/report/provenance.py`` (mesma suíte, mesmo
contrato ``suite-appsec/1``).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from typing import Any

from guardiao.rules.definitions import OWASP_EDITION
from guardiao.rules.registry import all_rules


def _git_head() -> str | None:
    """SHA do HEAD via git, ou ``None`` se não houver repositório/git disponível."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = proc.stdout.strip()
    return sha if proc.returncode == 0 and sha else None


def commit() -> str | None:
    """Identidade do código: variável de ambiente tem prioridade sobre o git.

    ``GUARDIAO_COMMIT`` existe para o caso do pacote instalado (sem .git) ou de
    CI que já conhece o SHA e não quer pagar um subprocesso por laudo.
    """
    env = os.environ.get("GUARDIAO_COMMIT", "").strip()
    if env:
        return env
    return _git_head()


def ruleset_hash() -> str:
    """sha256 estável do catálogo de regras (id, severidade, OWASP/CWE, texto)."""
    itens = [
        [
            rule.id,
            rule.severity.value,
            rule.owasp or "",
            rule.cwe or "",
            rule.title,
            rule.recommendation,
        ]
        for rule in sorted(all_rules(), key=lambda r: r.id)
    ]
    blob = json.dumps(
        {"owasp_edition": OWASP_EDITION, "rules": itens},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def artifact_sha256(document: dict[str, Any]) -> str:
    """sha256 canônico do documento **excluindo** o próprio campo de hash.

    Serialização determinística (chaves ordenadas, sem espaços) para que o
    cliente recompute o mesmo valor a partir do JSON recebido.
    """
    sem_campo = {k: v for k, v in document.items() if k != "artifact_sha256"}
    return canonical_sha256(sem_campo)


def canonical_sha256(obj: Any) -> str:
    """sha256 da serialização canônica — usado quando o campo de hash já está em
    ``None`` DENTRO do objeto (caso do SARIF, onde ele mora em ``properties`` e
    não no nível raiz, então não há o que excluir por cima)."""
    blob = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
