"""Leitor de config `gitleaks.toml` — migração sem reescrever regra por regra.

Um time que já tem um `gitleaks.toml` afinado (regras próprias, allowlist de
caminhos de teste, de segredos sintéticos) não deveria ter que recomeçar do
zero para trocar de scanner. `--gitleaks-config arquivo.toml` carrega ESSE
arquivo — sem tradução manual — e as regras entram na varredura como
qualquer outra (mesmo motor que ``rules/external.py`` usa para o formato
nativo do Guardião).

## O que é suportado

`[[rules]]`:

- ``id`` (obrigatório), ``regex`` (obrigatório) — Python `re`, não RE2: a
  maioria das regex de gitleaks compila sem alteração, mas sintaxe
  específica de RE2 pode falhar (vira erro de carregamento, igual a uma
  regex malformada).
- ``description`` — vira o título (default: o próprio ``id``, o gitleaks
  não exige o campo).
- ``secretGroup`` — grupo da regex que contém o segredo (default 0, igual
  ao gitleaks).
- ``entropy`` — piso de entropia Shannon do valor casado.
- ``keywords`` — a linha só é testada contra a regex se contiver alguma
  (pré-filtro; mesmo mecanismo que as regras internas usam).
- ``path`` — regex contra o CAMINHO do arquivo (não glob): só dispara para
  arquivo cujo caminho a regex casar em algum ponto.
- ``tags`` — lido e ignorado (não afeta detecção nem no gitleaks upstream).
- ``allowlist`` (tabela aninhada, ``[rules.allowlist]``) — ver abaixo.

Allowlist (``[allowlist]`` global, tabela única, e ``[rules.allowlist]`` por
regra, mesma forma):

- ``paths`` — regex de caminho; casando, suprime achados dessa allowlist
  nesse arquivo.
- ``regexes`` — regex contra o **valor do segredo casado**; casando,
  suprime o achado.
- ``stopwords`` — substring (case-insensitive) do valor casado; casando,
  suprime o achado.

O allowlist só se aplica às regras carregadas DESTE arquivo — não às regras
internas do Guardião. Migrar um `gitleaks.toml` não deveria mudar o
comportamento do que o Guardião já detectava por conta própria.

## O que NÃO é suportado (e gera aviso explícito, não erro)

Nada disto trava o carregamento — o arquivo é aceito, essas partes são
ignoradas e o motivo entra em ``GitleaksConfig.avisos`` (que o CLI despeja em
``ScanResult.avisos_de_cobertura`` — o mesmo canal usado para "isto aqui o
Guardião não conseguiu ver", porque é exatamente isso: uma parte do
`gitleaks.toml` que o operador escreveu e que NÃO foi aplicada):

- Chave desconhecida em `[[rules]]`, `[allowlist]`/`[rules.allowlist]` ou no
  nível raiz do arquivo (ex.: `regexTarget`, `[extend]`, `commits` de
  allowlist).
- `[[allowlists]]` (array de tabelas — schema do gitleaks ≥ 8.18, múltiplos
  allowlists nomeados). Só a tabela singular `[allowlist]` é lida.
- `condition = "AND"` num allowlist (o gitleaks aceita AND/OR; aqui só OR —
  o default do gitleaks — é aplicado). Nesse caso a allowlist inteira é
  IGNORADA, não aplicada com semântica errada: o viés é relatar demais, não
  suprimir um achado real por engano.

Isto não é "suporte parcial ao gitleaks" fingindo ser completo: é um
subconjunto documentado, com aviso explícito para tudo que fica de fora —
exatamente o contrato que o item pede.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Mesmo raciocínio de `rules/external.py`: `sys.version_info` (não
# `try/except`) para que o mypy — `python_version = "3.10"` fixo no
# pyproject — resolva o mesmo ramo (`tomli`) em toda a matriz de CI.
if sys.version_info >= (3, 11):  # pragma: no cover - ramo depende do interpretador
    import tomllib
else:  # pragma: no cover - ramo depende do interpretador
    import tomli as tomllib

from guardiao.core.models import Finding, Severity
from guardiao.rules.base import Rule, compile_rule

#: Gitleaks não distingue severidade entre regras — todo achado é "achado".
#: Migrado para cá, cada regra vira HIGH: é a suposição conservadora para um
#: scanner de segredo (a alternativa, MEDIUM, subestima o que o operador
#: definiu deliberadamente como um padrão de credencial a vigiar).
_SEVERIDADE_PADRAO = Severity.HIGH

_CAMPOS_REGRA_SUPORTADOS = frozenset(
    {
        "id",
        "description",
        "regex",
        "secretGroup",
        "entropy",
        "keywords",
        "path",
        "tags",
        "allowlist",
    }
)
_CAMPOS_ALLOWLIST_SUPORTADOS = frozenset({"description", "paths", "regexes", "stopwords"})
_CAMPOS_RAIZ_SUPORTADOS = frozenset({"title", "rules", "allowlist"})


class GitleaksConfigError(RuntimeError):
    """Falha ao carregar um `gitleaks.toml` — campo obrigatório ausente ou inválido."""


@dataclass(frozen=True)
class _Allowlist:
    """Uma tabela `[allowlist]`/`[rules.allowlist]` já compilada."""

    paths: tuple[re.Pattern[str], ...] = ()
    regexes: tuple[re.Pattern[str], ...] = ()
    stopwords: tuple[str, ...] = ()  # já em minúsculas

    def suprime(self, path: str, secret: str) -> bool:
        if any(p.search(path) for p in self.paths):
            return True
        if any(r.search(secret) for r in self.regexes):
            return True
        baixo = secret.lower()
        return any(sw in baixo for sw in self.stopwords)

    @property
    def vazia(self) -> bool:
        return not (self.paths or self.regexes or self.stopwords)


_ALLOWLIST_VAZIA = _Allowlist()


@dataclass
class GitleaksConfig:
    """Resultado de carregar um `gitleaks.toml`: regras + allowlists compiladas.

    ``allowlist_global``, ``allowlist_por_regra`` e ``path_por_regra`` são
    detalhe de implementação de :meth:`filtra` — a API pensada para uso
    externo (CLI, testes) é ``rules``, ``avisos`` e ``filtra()``.
    """

    rules: list[Rule]
    avisos: list[str] = field(default_factory=list)
    allowlist_global: _Allowlist = field(default_factory=lambda: _ALLOWLIST_VAZIA)
    allowlist_por_regra: dict[str, _Allowlist] = field(default_factory=dict)
    path_por_regra: dict[str, re.Pattern[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._ids = {r.id for r in self.rules}

    def filtra(self, findings: list[Finding]) -> tuple[list[Finding], int]:
        """Aplica o `path` de cada regra e as allowlists (global + por regra).

        Só toca achados cujo ``rule_id`` veio DESTE arquivo — uma regra
        interna do Guardião não é afetada por um allowlist de migração.
        Devolve ``(mantidos, suprimidos)``, no mesmo formato de
        :func:`guardiao.core.baseline.apply_baseline`.
        """
        mantidos: list[Finding] = []
        suprimidos = 0
        for achado in findings:
            if achado.rule_id not in self._ids:
                mantidos.append(achado)
                continue
            filtro_path = self.path_por_regra.get(achado.rule_id)
            if filtro_path is not None and filtro_path.search(achado.location.path) is None:
                suprimidos += 1
                continue
            if not self.allowlist_global.vazia and self.allowlist_global.suprime(
                achado.location.path, achado.secret
            ):
                suprimidos += 1
                continue
            allow_regra = self.allowlist_por_regra.get(achado.rule_id)
            if allow_regra is not None and allow_regra.suprime(achado.location.path, achado.secret):
                suprimidos += 1
                continue
            mantidos.append(achado)
        return mantidos, suprimidos


def load_gitleaks_config(path: Path) -> GitleaksConfig:
    """Lê `path` como `gitleaks.toml` e devolve regras + allowlists compiladas.

    Campo obrigatório ausente ou regex/allowlist inválida aborta com
    :class:`GitleaksConfigError`. Construção reconhecida mas não
    implementada (ver docstring do módulo) não aborta — vai para
    ``avisos``.
    """
    bruto = _ler_toml(path)
    avisos: list[str] = []

    for chave in bruto:
        if chave not in _CAMPOS_RAIZ_SUPORTADOS:
            # Cobre, entre outros, `[extend]` (herança de config externa) e
            # `[[allowlists]]` (schema gitleaks >= 8.18, múltiplos allowlists
            # nomeados) — só a tabela singular `[allowlist]` é lida.
            avisos.append(f"{path}: campo de nível raiz '{chave}' não suportado — ignorado.")

    entradas_regra = bruto.get("rules", [])
    if not isinstance(entradas_regra, list):
        raise GitleaksConfigError(
            f"{path}: 'rules' precisa ser uma lista de tabelas ([[rules]]), "
            f"achei {type(entradas_regra).__name__}"
        )
    if not entradas_regra:
        raise GitleaksConfigError(f"{path}: nenhuma tabela [[rules]] encontrada")

    regras: list[Rule] = []
    ids_vistos: set[str] = set()
    path_por_regra: dict[str, re.Pattern[str]] = {}
    allowlist_por_regra: dict[str, _Allowlist] = {}
    for indice, entrada in enumerate(entradas_regra):
        onde = f"{path} [[rules]] #{indice + 1}"
        if not isinstance(entrada, dict):
            raise GitleaksConfigError(f"{onde}: cada entrada precisa ser uma tabela")

        for chave in entrada:
            if chave not in _CAMPOS_REGRA_SUPORTADOS:
                avisos.append(f"{onde}: campo '{chave}' não suportado nesta regra — ignorado.")

        if "id" not in entrada or "regex" not in entrada:
            faltando = [c for c in ("id", "regex") if c not in entrada]
            raise GitleaksConfigError(
                f"{onde}: campo(s) obrigatório(s) ausente(s): {', '.join(faltando)}"
            )

        id_ = entrada["id"]
        regex_bruta = entrada["regex"]
        if not isinstance(id_, str) or not id_:
            raise GitleaksConfigError(f"{onde}: 'id' precisa ser uma string não-vazia")
        if not isinstance(regex_bruta, str) or not regex_bruta:
            raise GitleaksConfigError(f"{onde}: 'regex' precisa ser uma string não-vazia")
        if id_ in ids_vistos:
            raise GitleaksConfigError(f"{path}: id de regra duplicado: {id_!r}")
        ids_vistos.add(id_)

        try:
            re.compile(regex_bruta)
        except re.error as exc:
            raise GitleaksConfigError(f"{onde}: regex inválida em 'regex': {exc}") from exc

        secret_group = entrada.get("secretGroup", 0)
        if not isinstance(secret_group, int) or isinstance(secret_group, bool):
            raise GitleaksConfigError(f"{onde}: 'secretGroup' precisa ser um inteiro")

        entropy = entrada.get("entropy")
        if entropy is not None and not isinstance(entropy, int | float):
            raise GitleaksConfigError(f"{onde}: 'entropy' precisa ser numérico")

        keywords = entrada.get("keywords", [])
        if not isinstance(keywords, list) or not all(isinstance(k, str) for k in keywords):
            raise GitleaksConfigError(f"{onde}: 'keywords' precisa ser uma lista de strings")

        titulo = entrada.get("description", id_)
        if not isinstance(titulo, str) or not titulo:
            raise GitleaksConfigError(f"{onde}: 'description' precisa ser uma string não-vazia")

        caminho_regra = entrada.get("path")
        if caminho_regra is not None:
            if not isinstance(caminho_regra, str) or not caminho_regra:
                raise GitleaksConfigError(f"{onde}: 'path' precisa ser uma string não-vazia")
            try:
                path_por_regra[id_] = re.compile(caminho_regra)
            except re.error as exc:
                raise GitleaksConfigError(f"{onde}: regex inválida em 'path': {exc}") from exc

        allowlist_bruta = entrada.get("allowlist")
        if allowlist_bruta is not None:
            allow, avisos_allow = _construir_allowlist(f"{onde} allowlist", allowlist_bruta)
            avisos.extend(avisos_allow)
            if allow is not None:
                allowlist_por_regra[id_] = allow

        regras.append(
            compile_rule(
                id=id_,
                title=titulo,
                severity=_SEVERIDADE_PADRAO,
                pattern=regex_bruta,
                secret_group=secret_group,
                min_entropy=float(entropy) if entropy is not None else None,
                keywords=tuple(keywords),
            )
        )

    allowlist_global = _ALLOWLIST_VAZIA
    allowlist_bruta_global = bruto.get("allowlist")
    if allowlist_bruta_global is not None:
        allow, avisos_allow = _construir_allowlist(f"{path} allowlist", allowlist_bruta_global)
        avisos.extend(avisos_allow)
        if allow is not None:
            allowlist_global = allow

    return GitleaksConfig(
        rules=regras,
        avisos=avisos,
        allowlist_global=allowlist_global,
        allowlist_por_regra=allowlist_por_regra,
        path_por_regra=path_por_regra,
    )


def _construir_allowlist(onde: str, bruta: object) -> tuple[_Allowlist | None, list[str]]:
    """Compila uma tabela de allowlist. `None` = reconhecida mas descartada (ex.: `condition=AND`)."""
    avisos: list[str] = []
    if not isinstance(bruta, dict):
        avisos.append(f"{onde}: precisa ser uma tabela — ignorada.")
        return None, avisos

    condicao = bruta.get("condition")
    if condicao is not None and str(condicao).upper() != "OR":
        avisos.append(
            f"{onde}: condition={condicao!r} não suportado (só OR, o default do "
            "gitleaks, é aplicado) — allowlist inteira ignorada para não suprimir "
            "achado real com a semântica errada."
        )
        return None, avisos

    for chave in bruta:
        if chave not in _CAMPOS_ALLOWLIST_SUPORTADOS and chave != "condition":
            avisos.append(f"{onde}: campo '{chave}' não suportado — ignorado.")

    paths_brutos = bruta.get("paths", [])
    regexes_brutas = bruta.get("regexes", [])
    stopwords_brutas = bruta.get("stopwords", [])
    for nome, valor in (
        ("paths", paths_brutos),
        ("regexes", regexes_brutas),
        ("stopwords", stopwords_brutas),
    ):
        if not isinstance(valor, list) or not all(isinstance(v, str) for v in valor):
            avisos.append(f"{onde}: '{nome}' precisa ser uma lista de strings — ignorado.")
            return None, avisos

    try:
        paths = tuple(re.compile(p) for p in paths_brutos)
        regexes = tuple(re.compile(r) for r in regexes_brutas)
    except re.error as exc:
        avisos.append(f"{onde}: regex inválida em paths/regexes ({exc}) — allowlist ignorada.")
        return None, avisos

    stopwords = tuple(sw.lower() for sw in stopwords_brutas)
    return _Allowlist(paths=paths, regexes=regexes, stopwords=stopwords), avisos


def _ler_toml(path: Path) -> dict[str, object]:
    try:
        with Path(path).open("rb") as arquivo:
            return tomllib.load(arquivo)
    except FileNotFoundError as exc:
        raise GitleaksConfigError(f"{path}: arquivo não encontrado") from exc
    except tomllib.TOMLDecodeError as exc:
        raise GitleaksConfigError(f"{path}: TOML inválido — {exc}") from exc
