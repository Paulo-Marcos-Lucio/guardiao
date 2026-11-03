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
- ``ruleset_hash`` — sha256 do catálogo de regras (nativo + externas carregadas
  por ``--gitleaks-config``/``--rules-file``, quando houver). Muda quando
  qualquer regra muda, nativa ou externa; dois laudos com o mesmo hash foram
  medidos com o mesmo conjunto de regras.
- ``artifact_sha256`` — sha256 do próprio documento (sem o campo), canônico. O
  cliente recomputa e detecta adulteração.

Dívida fechada (G-05, §0.4): antes desta versão o hash só via o catálogo NATIVO
— um laudo gerado com ``--rules-file``/``--gitleaks-config`` carimbava o mesmo
``ruleset_hash`` de uma varredura sem nenhuma regra externa, mentindo sobre o
que de fato julgou o código. ``ruleset_hash`` agora aceita o texto bruto de
cada arquivo externo carregado (``externas``) e o inclui no material hasheado.

Receita de verificação (idêntica nas ferramentas da suíte, para o cliente conferir
os quatro laudos com UM procedimento só):

- ``ruleset_hash`` = ``sha256:`` + sha256 do catálogo canônico (chaves ordenadas,
  separadores compactos), com a versão do schema do catálogo (``guardiao-ruleset/2``)
  embutida no material hasheado — mudar o schema muda o hash.
- ``artifact_sha256`` = sha256 da serialização canônica do documento com o próprio
  campo em ``None``/ausente (``sort_keys=True, separators=(',',':'), ensure_ascii=False``).
- ``commit_scope`` no envelope diz o SENTIDO do ``commit``: para o Guardião é
  ``"target"`` — o commit é o do repositório AUDITADO, não o da ferramenta.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from guardiao.rules.definitions import OWASP_EDITION
from guardiao.rules.registry import all_rules

#: Um SHA-1 de commit tem exatamente 40 dígitos hex minúsculos. O filtro vale tanto para
#: a saída do git quanto para o override do ambiente: um valor malformado (typo, variável
#: errada herdada do CI) não pode contaminar a proveniência — é o "parece informação" que
#: o docstring do módulo diz ser pior que o silêncio.
_SHA_COMPLETO = re.compile(r"^[0-9a-f]{40}$")

#: Versão do schema do CATÁLOGO de regras, embutida no material que gera o ``ruleset_hash``.
#: Mudar a forma do catálogo (colunas hasheadas, semântica de um campo) obriga a subir isto,
#: e o hash muda junto — dois laudos com o mesmo ``ruleset_hash`` foram medidos com o mesmo
#: catálogo E o mesmo schema. Padrão da suíte: ``<tool>-ruleset/<n>``.
#: /2 (G-05, §0.4): o material hasheado passou a incluir ``externas`` — o texto bruto das
#: regras carregadas por ``--gitleaks-config``/``--rules-file``. Um hash calculado antes
#: desta versão não é comparável a um calculado depois, mesmo com o catálogo nativo igual.
RULESET_SCHEMA = "guardiao-ruleset/2"

#: Sentido do campo ``commit`` no envelope. No Guardião o commit é o do repositório
#: **auditado** (o alvo da varredura), não o da ferramenta — daí ``"target"``. O
#: discriminador existe porque outras ferramentas da suíte carimbam o commit da própria
#: ferramenta (``"tool"``): mesmo nome de campo, sentidos opostos sem isto.
COMMIT_SCOPE = "target"


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


def ruleset_hash(externas: Sequence[str] = ()) -> str:
    """``sha256:<hex>`` estável do catálogo de regras (id, severidade, OWASP/CWE, texto).

    O prefixo ``sha256:`` é auto-descritivo (o cliente sabe qual algoritmo recomputar sem
    adivinhar pelo comprimento) e uniforme na suíte. A versão do schema do catálogo
    (``RULESET_SCHEMA``) entra no material hasheado: reformar o catálogo muda o hash.

    ``externas`` é o texto BRUTO de cada arquivo de regra carregado por
    ``--gitleaks-config``/``--rules-file`` (G-05, §0.4) — não o ``Rule`` compilado.
    Hashear o texto, não o resultado da compilação, significa que até uma mudança
    cosmética no arquivo de origem (reordenar regras, um comentário) já move o hash:
    o laudo prova com QUAL arquivo ele foi gerado, não só com qual comportamento. A
    ordem dos arquivos na linha de comando não importa — a lista é ordenada antes de
    entrar no material hasheado.
    """
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
        {
            "schema": RULESET_SCHEMA,
            "owasp_edition": OWASP_EDITION,
            "rules": itens,
            "externas": sorted(externas),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


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
