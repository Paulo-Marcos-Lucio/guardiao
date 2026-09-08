"""Proveniência do laudo (PROV-01): amarra o JSON/SARIF ao código e às regras.

Defeito de origem: o relatório era um documento solto — não dava para provar com
qual versão do Guardião nem com qual conjunto de regras ele foi gerado, nem
detectar adulteração posterior. Três campos resolvem isso:

- ``commit`` — o SHA do código AUDITADO (env ``GUARDIAO_COMMIT`` → ``git
  rev-parse HEAD`` da RAIZ VARRIDA → ``None``). É o commit do repositório-alvo,
  **não** o do CWD do processo: rodar da pasta da própria ferramenta varrendo
  ``../outro-repo`` carimbava o HEAD da ferramenta — silenciosamente errado, e é
  justamente a proveniência que existe para desmentir. Em pacote instalado sem
  git, cai em ``None`` sem quebrar.
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
import re
import subprocess
from pathlib import Path
from typing import Any

from guardiao.rules.definitions import OWASP_EDITION
from guardiao.rules.registry import all_rules

#: Um SHA-1 de commit tem exatamente 40 dígitos hex minúsculos. O filtro vale tanto para
#: a saída do git quanto para o override do ambiente: um valor malformado (typo, variável
#: errada herdada do CI) não pode contaminar a proveniência — é o "parece informação" que
#: o docstring do módulo diz ser pior que o silêncio.
_SHA_COMPLETO = re.compile(r"^[0-9a-f]{40}$")


def _git_head(root: Path | str | None = None) -> str | None:
    """SHA do HEAD do repositório que CONTÉM ``root``, ou ``None`` se não houver.

    ``root`` é o caminho AUDITADO — o ``cwd`` do subprocesso é ele (ou a pasta que o
    contém, quando é arquivo), nunca o diretório de trabalho do processo Guardião. Sem
    isso o commit vinha do git de onde a ferramenta foi iniciada, não do código-alvo.
    """
    diretorio = Path(root) if root is not None else Path.cwd()
    try:
        if diretorio.is_file():
            diretorio = diretorio.parent
    except OSError:  # pragma: no cover - fs edge
        pass
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(diretorio),
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    sha = proc.stdout.strip().lower()
    return sha if _SHA_COMPLETO.match(sha) else None


def commit(root: Path | str | None = None) -> str | None:
    """Identidade do código AUDITADO: ``GUARDIAO_COMMIT`` → git da raiz ``root`` → ``None``.

    ``root`` é a raiz varrida (``ScanResult.root``): o commit tem de ser o do repositório
    que contém o código-alvo, não o do CWD do processo. ``GUARDIAO_COMMIT`` tem prioridade
    (pacote instalado sem ``.git``, ou CI que já conhece o SHA) e passa pelo MESMO filtro
    de 40-hex que a saída do git — um override malformado cai para o git em vez de vazar.
    """
    env = os.environ.get("GUARDIAO_COMMIT", "").strip().lower()
    if env and _SHA_COMPLETO.match(env):
        return env
    return _git_head(root)


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
