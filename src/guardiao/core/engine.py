"""Motor de varredura: junta fontes + regras e produz achados."""

from __future__ import annotations

import functools
import re
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field, replace
from fnmatch import fnmatch
from pathlib import Path, PurePath

from guardiao.core.config import Config
from guardiao.core.entropy import shannon_entropy
from guardiao.core.models import Finding, Location, Severity
from guardiao.core.redaction import redact, redact_spans
from guardiao.rules.base import Rule
from guardiao.rules.definitions import (
    HASH_CONTEXT,
    PUBLIC_KEY_CONTEXT,
    is_probable_hash_or_id,
    linha_tem_hash_cripto,
    looks_like_placeholder,
    looks_like_secret_token,
    tem_letra_nao_ascii,
)
from guardiao.rules.registry import all_rules
from guardiao.sources.files import iter_files, read_text
from guardiao.sources.githistory import iter_history_blobs

_ALLOW_MARKERS = ("guardiao:allow", "guardiao: allow", "pragma: allowlist secret")

#: Regras de ENTROPIA cujo ruído domina um bundle minificado (hash de chunk, nome de
#: variável minificado): puladas só em arquivo minificado de linha única — as regras de
#: FORMATO (ghp_/AKIA/sk_live) e a genérica por keyword continuam valendo (FP-08).
_RUIDO_EM_MINIFICADO = frozenset({"high-entropy-string", "secret-in-path"})
_EXT_MINIFICAVEL = frozenset({".js", ".mjs", ".cjs", ".css"})


def _e_minificado(path: str, text: str) -> bool:
    """Arquivo .js/.css minificado? Poucas linhas + longo, ou alguma linha muito longa —
    a assinatura de um bundle (hash de chunk, variáveis minificadas) cujo ruído de
    entropia é falso positivo (FP-08)."""
    if PurePath(path).suffix.lower() not in _EXT_MINIFICAVEL:
        return False
    corpo = text.strip()
    linhas = corpo.split("\n")
    if len(linhas) <= 3 and len(corpo) > 500:
        return True
    return max((len(linha) for linha in linhas), default=0) > 400


#: Regras HEURISTICAS rebaixadas (nao skip) em arquivos de teste; regras de FORMATO imunes.
_DEMOTABLE_IN_TESTS: frozenset[str] = frozenset({"generic-assignment", "high-entropy-string"})


def _one_notch_down(sev: Severity) -> Severity:
    """Severidade um degrau abaixo (MEDIUM→LOW); INFO é o piso."""
    alvo = max(Severity.INFO.rank, sev.rank - 1)
    return next(s for s in Severity if s.rank == alvo)


#: Motivos pelos quais conteúdo deixa de ser analisado. Sempre reportados (mesmo
#: zerados) — "não olhei" e "olhei e está limpo" precisam ser distinguíveis.
#: ``diretorio`` conta ÁRVORES inteiras puladas (exclude_dirs/venv), não arquivos:
#: é o motivo que mais esconde conteúdo e o último a ganhar contador.
MOTIVOS_DE_PULO: tuple[str, ...] = (
    "diretorio",
    "tamanho",
    "ruido",
    "binario",
    "linha_longa",
    "fora-da-raiz",
)

#: Uma unidade de varredura: (caminho, conteúdo, commit de origem ou None).
Unit = tuple[str, str, "str | None"]


#: Delimitadores de bloco PEM (certificado, chave, CRL, requisição).
_PEM_ABRE_RE = re.compile(r"^-{5}BEGIN [A-Z0-9 ]+-{5}\s*$")
_PEM_FECHA_RE = re.compile(r"^-{5}END [A-Z0-9 ]+-{5}\s*$")

#: Linha inteira de base64 contíguo, fora de bloco delimitado (blob solto, objeto Git).
_CORPO_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")

#: Junção de dois literais de string por `+` (`"AKIA" + "…"`, `'a' + 'b'`): a evasão
#: trivial de quebrar um segredo em pedaços para escapar da regex. Removê-la reconstrói
#: o valor contíguo. Só casa literal-com-literal (aspa antes E depois do `+`), nunca
#: `"x" + var` — que juntaria texto não-secreto.
_CONCAT_LITERAIS_RE = re.compile(r"""["']\s*\+\s*["']""")

#: Alfabeto base64/base64url (sem o `/`, tratado à parte como possível delimitador).
_B64URL_SEM_BARRA = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+=_-")

#: Alfabeto base64 padrão INCLUINDO `/` — para medir o comprimento de um blob contíguo.
_B64_COM_BARRA = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

#: A partir de que comprimento uma corrida contígua de base64-com-barra é um BLOB (payload
#: codificado: DKIM `p=…`, chave pública, dado binário) e não um caminho `/a/token/b`.
_MIN_BLOB_BASE64 = 64


def _e_letra_nao_ascii(c: str) -> bool:
    return ord(c) > 127 and c.isalpha()


def _barra_interna_base64(raw_line: str, start: int) -> bool:
    """A `/` em ``raw_line[start-1]`` é interna a um base64 entre aspas, não um path?

    Varre à esquerda sobre o segmento base64url anterior à `/`. Se a fronteira desse
    segmento for uma **aspa** (`"`/`'`), o `/` está dentro de um valor citado
    (``opaque="FQhe/qaU…"``) — não é delimitador de caminho. Se for `/`, espaço ou o
    início da linha, é um path de verdade (``/_internal/<seg>/…``, o cenário do F-007),
    e a checagem devolve ``False`` para não cegar o achado legítimo.
    """
    i = start - 2
    vistos = 0
    while i >= 0 and raw_line[i] in _B64URL_SEM_BARRA:
        i -= 1
        vistos += 1
    if vistos == 0 or i < 0:
        return False  # `/` logo após não-base64, ou segmento cola no início: path limpo
    return raw_line[i] in "\"'"


def _barra_interna_de_blob(raw_line: str, start: int) -> bool:
    """A `/` em ``raw_line[start-1]`` é interna a um BLOB base64 (não delimitador de path)?

    Dois casos: (1) o segmento anterior é fechado por aspas (`opaque="FQhe/qaU…"`); (2) a
    corrida contígua de base64-com-barra em volta da `/` é longa (≥ :data:`_MIN_BLOB_BASE64`)
    — DKIM `p=…`, chave pública sem prefixo reconhecido, dado binário. Um caminho real
    (`/_internal/<token>/intel`) tem o `_` fora do alfabeto base64 e não forma corrida longa.
    """
    if _barra_interna_base64(raw_line, start):
        return True
    barra = start - 1
    esq = barra
    while esq >= 0 and raw_line[esq] in _B64_COM_BARRA:
        esq -= 1
    dir_ = barra
    n = len(raw_line)
    while dir_ < n and raw_line[dir_] in _B64_COM_BARRA:
        dir_ += 1
    return (dir_ - esq - 1) >= _MIN_BLOB_BASE64


#: Caminho SINTÉTICO: a unidade não veio de um arquivo com nome (blob órfão do
#: histórico, mensagem de commit/tag). Quem produz a unidade escreve o descritor
#: entre ``<>`` — nome de arquivo real não tem essa forma em nenhum dos dois lados.
_CAMINHO_SINTETICO_RE = re.compile(r"^<[^>]*>$")

#: Linha no formato de arquivo de ambiente: `CHAVE_MAIÚSCULA=valor` sem aspas e sem
#: espaço em volta do `=` — é isso que separa um `.env` de código-fonte (`x = f()`).
_LINHA_DOTENV_RE = re.compile(r"^[ \t]*(?:export[ \t]+)?[A-Z_][A-Z0-9_]*=(?![\s\"'])")


def _parece_dotenv(text: str) -> bool:
    """O conteúdo tem forma de arquivo de ambiente?

    Usado só quando o caminho real é irrecuperável (blob solto). Exige que a MAIORIA
    (≥60%) das linhas úteis case o formato: um arquivo de código com uma linha
    `EXPORT_X=1` perdida no meio não vira `.env`, e um `.env` de uma linha só — que
    existe — continua sendo reconhecido.
    """
    linhas = [
        linha
        for linha in text.split("\n")[:400]  # o suficiente para decidir; não varre 100 MB
        if linha.strip() and not linha.lstrip().startswith("#")
    ]
    if not linhas:
        return False
    casam = sum(1 for linha in linhas if _LINHA_DOTENV_RE.match(linha))
    return casam * 5 >= len(linhas) * 3


def _e_corpo_base64(linha: str) -> bool:
    """A linha é corpo base64 solto, sem estrutura de conteúdo?

    Complementa o rastreamento de bloco PEM para o caso em que só o corpo chega
    (um blob de objeto Git, um trecho colado sem cabeçalho).
    """
    return _CORPO_BASE64_RE.fullmatch(linha.strip()) is not None


@functools.cache
def _keyword_pattern(keywords: tuple[str, ...]) -> re.Pattern[str] | None:
    """Regex que casa qualquer keyword como palavra.

    Cobre três formas de nome que a fronteira ``\\b`` deixa passar ou barra errado:
    ``token`` solto, ``DB_PASSWORD``/``JWT_SECRET`` (``\\b`` não existe entre ``_`` e
    letra) e ``accessToken`` (camelCase). Continua rejeitando ``author``→``auth`` e
    ``monkey``→``key``, porque o ramo camelCase exige maiúscula literal.
    """
    if not keywords:
        return None
    body = "|".join(re.escape(k) for k in keywords)
    return re.compile(
        rf"(?:(?<![A-Za-z0-9])|(?<=[a-z0-9])(?=[A-Z]))(?:{body})(?![A-Za-z0-9])",
        re.IGNORECASE,
    )


_HASH_CONTEXT_RE = re.compile(
    rf"(?:(?<![A-Za-z0-9])|(?<=[a-z0-9])(?=[A-Z]))(?:{'|'.join(HASH_CONTEXT)})(?![A-Za-z0-9])",
    re.IGNORECASE,
)

# Contexto de valor PÚBLICO na linha (chave pública, JWKS, pk_live/site_key): a alta
# entropia ali é publicável por design, não credencial (FP-02).
_PUBKEY_CONTEXT_RE = re.compile("|".join(re.escape(k) for k in PUBLIC_KEY_CONTEXT), re.IGNORECASE)

# Blob base64 PÚBLICO na linha: chave SSH pública (`ssh-rsa AAAA…`), data-URI
# (`data:image/png;base64,…`) ou cabeçalho PEM público/certificado embutido numa string
# (com `\n` literal, então o rastreio de bloco PEM multi-linha não pega). O alfabeto base64
# tem `/`, e `secret-in-path` lia cada barra desses blobs como um segmento de path — um
# `authorized_keys` ou uma fonte-ícone rendia dezenas de "segredos" (FP-01, a classe dos
# ~98,6% de FP no terraform-aws). Só as regras de ENTROPIA são neutralizadas: um `AKIA…`,
# um `ghp_…` ou o cabeçalho de chave PRIVADA continuam pegos por prefixo.
_SSH_PUBKEY_RE = re.compile(
    r"\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/]{40,}"
)
_DATA_URI_B64_RE = re.compile(r"data:[\w.+/-]*;base64,[A-Za-z0-9+/]{20,}", re.IGNORECASE)
_PEM_PUBLICO_INLINE_RE = re.compile(
    r"-{5}BEGIN (?:PUBLIC KEY|CERTIFICATE|RSA PUBLIC KEY|EC PUBLIC KEY|PGP PUBLIC KEY BLOCK|DSA PUBLIC KEY|CERTIFICATE REQUEST)-{5}"
)


def _e_blob_base64_publico(raw_line: str) -> bool:
    """A linha carrega um blob base64 PÚBLICO (chave SSH pública, data-URI, PEM público
    inline)? Nesse caso as barras internas do blob NÃO são delimitadores de path."""
    return bool(
        _SSH_PUBKEY_RE.search(raw_line)
        or _DATA_URI_B64_RE.search(raw_line)
        or _PEM_PUBLICO_INLINE_RE.search(raw_line)
    )


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    units_scanned: int = 0
    duration_s: float = 0.0
    #: Conteúdo NÃO analisado, por motivo (ver :data:`MOTIVOS_DE_PULO`).
    skipped: dict[str, int] = field(default_factory=lambda: dict.fromkeys(MOTIVOS_DE_PULO, 0))
    #: Valores casados por uma regra e descartados como placeholder (auditabilidade
    #: da supressão: sem esse número, o descarte é silencioso).
    placeholders: int = 0
    #: Limites de ALCANCE que a fonte reconhece e declara (ex.: um clone não recebe os
    #: objetos inalcançáveis do repositório de origem). Não é erro e não muda o código
    #: de saída: travar o CI do cliente por um limite conhecido seria pior que declará-lo.
    avisos_de_cobertura: list[str] = field(default_factory=list)

    def counts(self) -> dict[Severity, int]:
        result: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            result[finding.severity] += 1
        return result

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def total_pulado(self) -> int:
        return sum(self.skipped.values())


class Scanner:
    """Aplica as regras habilitadas a qualquer trecho de texto."""

    def __init__(self, config: Config | None = None, rules: list[Rule] | None = None) -> None:
        self.config = config or Config()
        self.rules = [
            rule
            for rule in (rules if rules is not None else all_rules())
            if self.config.rule_enabled(rule.id, rule.category)
        ]

    # -- unidade mínima: um texto ------------------------------------------- #

    def scan_text(
        self,
        path: str,
        text: str,
        *,
        commit: str | None = None,
        contadores: dict[str, int] | None = None,
    ) -> Iterator[Finding]:
        """Produz os achados de um texto. ``contadores`` acumula pulos/descartes."""
        contadores = {} if contadores is None else contadores
        rules = self._rules_for(path, text)
        em_teste = self.config.demote_tests and self.config.is_test_path(path)
        minificado = _e_minificado(path, text)
        dentro_de_pem = False
        for lineno, line in enumerate(text.split("\n"), start=1):
            raw_line = line.removesuffix("\r")  # conta linhas só por \n (igual ao editor/GitHub)
            if _PEM_ABRE_RE.match(raw_line):
                dentro_de_pem = True
            elif _PEM_FECHA_RE.match(raw_line):
                dentro_de_pem = False
            if len(raw_line) > self.config.max_line_length:
                contadores["linha_longa"] = contadores.get("linha_longa", 0) + 1
                continue
            if _is_allowlisted(raw_line):
                continue

            # 1) Coleta todos os matches da linha que sobrevivem aos filtros.
            hits: list[tuple[Rule, int, str, float]] = []
            contexto_de_hash: bool | None = None
            # Corpo de PEM não é conteúdo: é payload codificado. O alfabeto base64
            # inclui `/`, então `secret-in-path` via um "segredo em path" a cada barra —
            # um único `certifi/cacert.pem` (CAs PÚBLICAS) rendia 821 achados, e todo
            # virtualenv tem esse arquivo. Só as regras de ENTROPIA são neutralizadas:
            # as de fornecedor (`AKIA…`, `ghp_…`) e a de chave privada casam por prefixo
            # ou pelo cabeçalho `-----BEGIN…`, que continuam sendo lidos normalmente.
            payload_codificado = (
                dentro_de_pem
                or _e_corpo_base64(raw_line)
                or _e_blob_base64_publico(raw_line)
                or linha_tem_hash_cripto(raw_line)
            )
            for rule in rules:
                if payload_codificado and rule.category == "entropy":
                    continue
                if minificado and rule.id in _RUIDO_EM_MINIFICADO:
                    continue  # bundle .js/.css de 1 linha: hash de chunk/var minificada (FP-08)
                keyword_re = _keyword_pattern(rule.keywords)
                if keyword_re is not None and keyword_re.search(raw_line) is None:
                    continue
                regex = rule.regex
                if regex.search(raw_line) is None:
                    continue  # barato: evita montar o iterador nas linhas que não casam
                group = rule.secret_group
                for match in regex.finditer(raw_line):
                    secret = match.group(group)
                    if secret is None:
                        continue
                    if not rule.composto and looks_like_placeholder(secret):
                        # Regra COMPOSTA (URI/connection string): o filtro por substring
                        # dispara errado no host/nome-do-banco — quem julga é o validator.
                        contadores["placeholder"] = contadores.get("placeholder", 0) + 1
                        continue
                    if rule.validator is not None and not rule.validator(secret):
                        continue
                    entropy = shannon_entropy(secret)
                    if rule.min_entropy is not None and entropy < rule.min_entropy:
                        continue
                    start = match.start(group)
                    if rule.category == "entropy":
                        fim = start + len(secret)
                        if (start > 0 and _e_letra_nao_ascii(raw_line[start - 1])) or (
                            fim < len(raw_line) and _e_letra_nao_ascii(raw_line[fim])
                        ):
                            continue  # colado a letra acentuada: é palavra natural, não token (FP-07)
                        # Aceitação multi-sinal: entropia por-alfabeto OU
                        # impronunciabilidade (blob MAIÚSCULO aleatório que o limiar de
                        # entropia subestima). Segmento de path aleatório entra por aqui.
                        if not looks_like_secret_token(secret) or tem_letra_nao_ascii(secret):
                            continue
                        if is_probable_hash_or_id(secret):
                            continue  # UUID / SHA-1 de commit / pin não são segredos
                        if start > 0 and raw_line[start - 1] == "@":
                            continue  # 'action@sha' / 'image@digest' são pins, não segredos
                        if (
                            start >= 2
                            and raw_line[start - 1] == "/"
                            and _barra_interna_de_blob(raw_line, start)
                        ):
                            # `/` DENTRO de um base64 entre aspas (`opaque="FQhe/qaU…"`) não é
                            # delimitador de path — o token inteiro é um valor, não uma URL.
                            # Distingue-se do path real (`/_internal/<seg>/intel`, o F-007) pela
                            # fronteira à esquerda do segmento anterior: aspas ⇒ valor; `/` ⇒ path.
                            continue
                        if contexto_de_hash is None:
                            contexto_de_hash = (
                                _HASH_CONTEXT_RE.search(raw_line) is not None
                                or _PUBKEY_CONTEXT_RE.search(raw_line) is not None
                            )
                        if contexto_de_hash:
                            continue  # digest ('md5'/'etag') ou chave PÚBLICA (jwks/pk_live): não é credencial
                    hits.append((rule, start, secret, entropy))

            # Evasão por concatenação: `KEY = "AKIA" + "…"`. Reconstrói o valor unido e
            # reporta só o que a JUNÇÃO forma (e que não existia contíguo na linha) — corre
            # ANTES do corte por `hits` vazio, porque é justamente a linha sem achado normal
            # (o segredo foi partido) que a evasão explora.
            if "+" in raw_line and _CONCAT_LITERAIS_RE.search(raw_line):
                juntada = _CONCAT_LITERAIS_RE.sub("", raw_line)
                yield from self._hits_de_concatenacao(
                    rules, path, juntada, raw_line, lineno, commit
                )

            if not hits:
                continue

            # 1b) Dedup por trecho sobreposto: o MESMO segredo casado por várias regras
            #     (ex.: github-token HIGH + high-entropy MEDIUM) vira um achado só — a regra
            #     mais específica/severa. Evita ruído de "achado dobrado" no relatório.
            hits = _dedupe_overlapping(hits)

            # 2) Um preview compartilhado que mascara TODOS os segredos da linha —
            #    impede que um segundo segredo na mesma linha vaze cru.
            spans = [(start, start + len(secret), secret) for (_, start, secret, _) in hits]
            preview = redact_spans(raw_line, spans)

            # 3) Um Finding por match, todos com o mesmo preview seguro.
            for rule, start, secret, entropy in hits:
                severity = rule.severity
                if em_teste and rule.id in _DEMOTABLE_IN_TESTS:
                    # Sinal suave: em teste, o palpite heurístico vale menos — mas
                    # continua REPORTADO (rebaixado), nunca suprimido.
                    severity = _one_notch_down(severity)
                yield Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=severity,
                    location=Location(path=path, line=lineno, column=start + 1, commit=commit),
                    secret=secret,
                    redacted=redact(secret),
                    line_preview=preview,
                    entropy=round(entropy, 2),
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    category=rule.category,
                    recommendation=rule.recommendation,
                )

    def _hits_de_concatenacao(
        self,
        rules: list[Rule],
        path: str,
        linha: str,
        original: str,
        lineno: int,
        commit: str | None,
    ) -> Iterator[Finding]:
        """Achados de FORMATO no valor reconstruído de uma concatenação de literais.

        Só regras de formato/fornecedor (entropia solta em código concatenado é ruído) e
        só o segredo que a junção FORMOU — ``secret in original`` significa que já estava
        contíguo e já foi reportado no passe normal, então é descartado para não duplicar.
        """
        for rule in rules:
            if rule.category == "entropy":
                continue
            keyword_re = _keyword_pattern(rule.keywords)
            if keyword_re is not None and keyword_re.search(linha) is None:
                continue
            for match in rule.regex.finditer(linha):
                secret = match.group(rule.secret_group)
                if secret is None or secret in original:
                    continue
                if not rule.composto and looks_like_placeholder(secret):
                    continue
                if rule.validator is not None and not rule.validator(secret):
                    continue
                entropy = shannon_entropy(secret)
                if rule.min_entropy is not None and entropy < rule.min_entropy:
                    continue
                start = match.start(rule.secret_group)
                preview = redact_spans(linha, [(start, start + len(secret), secret)])
                yield Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    location=Location(path=path, line=lineno, column=start + 1, commit=commit),
                    secret=secret,
                    redacted=redact(secret),
                    line_preview=preview,
                    entropy=round(entropy, 2),
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    category=rule.category,
                    recommendation=rule.recommendation,
                )

    def _rules_for(self, path: str, text: str) -> list[Rule]:
        """Regras válidas para esta unidade (algumas só valem em `.env` e afins).

        Quando a unidade **não tem nome de arquivo** — blob órfão de `--amend`/rebase,
        mensagem de commit —, decidir por `fnmatch` significa descartar a regra: era
        assim que o `.env` amendado, o cenário-assinatura da fonte de histórico,
        voltava "nenhum segredo encontrado". Aí a decisão passa a ser por CONTEÚDO.
        Hoje a única família `only_files` é a do `.env`, então uma heurística basta;
        outra família precisará da sua.
        """
        if not any(rule.only_files for rule in self.rules):
            return self.rules
        if _CAMINHO_SINTETICO_RE.match(path):
            baixo = path.lower()
            if any(m in baixo for m in ("example", "sample", "template", ".dist")):
                return [r for r in self.rules if not r.only_files]  # blob de arquivo de exemplo
            if _parece_dotenv(text):
                return self.rules
            return [r for r in self.rules if not r.only_files]
        if any(m in path.lower() for m in ("example", "sample", "template", ".dist")):
            # Arquivo de EXEMPLO (por nome, em qualquer ponto do caminho ou descritor de
            # histórico): `CHAVE=valor` ali é documentação, não vazamento (FP-05).
            return [r for r in self.rules if not r.only_files]
        nome = PurePath(path).name.lower()
        return [r for r in self.rules if not r.only_files or _nome_casa(nome, r.only_files)]

    # -- pipeline único ----------------------------------------------------- #

    def scan_units(
        self, units: Iterable[Unit], skipped: dict[str, int] | None = None
    ) -> ScanResult:
        """Varre unidades já materializadas. Todo comando desemboca aqui.

        ``skipped`` é usado **por referência**: as fontes são preguiçosas e só
        contabilizam o que pularam enquanto o laço abaixo as consome.
        """
        started = time.perf_counter()
        contadores: dict[str, int] = skipped if skipped is not None else {}
        for motivo in MOTIVOS_DE_PULO:
            contadores.setdefault(motivo, 0)
        findings: list[Finding] = []
        units_scanned = 0
        for path, text, commit in units:
            units_scanned += 1
            findings.extend(self.scan_text(path, text, commit=commit, contadores=contadores))
        findings.sort(key=lambda f: (-f.severity.rank, f.location.path, f.location.line))
        placeholders = contadores.pop("placeholder", 0)
        return ScanResult(
            findings=findings,
            units_scanned=units_scanned,
            duration_s=round(time.perf_counter() - started, 4),
            skipped=contadores,
            placeholders=placeholders,
        )

    # -- varredura de arquivos ---------------------------------------------- #

    def scan_paths(self, paths: Iterable[Path | str]) -> ScanResult:
        skipped: dict[str, int] = dict.fromkeys(MOTIVOS_DE_PULO, 0)
        return self.scan_units(_file_units(paths, self.config, skipped), skipped)

    # -- varredura de histórico Git ----------------------------------------- #

    def scan_git_history(self, repo: Path | str, *, permitir_shallow: bool = False) -> ScanResult:
        skipped: dict[str, int] = dict.fromkeys(MOTIVOS_DE_PULO, 0)
        # `avisos` é preenchido por REFERÊNCIA, como `skipped`: a fonte é preguiçosa e
        # só declara o que descobriu enquanto o pipeline a consome.
        avisos: list[str] = []
        units = (
            (blob.path, blob.text, blob.sha)
            for blob in iter_history_blobs(
                Path(repo),
                max_bytes=self.config.max_file_size,
                skipped=skipped,
                permitir_shallow=permitir_shallow,
                avisos=avisos,
            )
        )
        result = self.scan_units(units, skipped)
        result.avisos_de_cobertura = avisos
        # O MESMO segredo persiste em dezenas de blobs (todo commit que tocou o arquivo
        # o recarrega): 283 linhas brutas eram ~64 vazamentos distintos. Colapsa por
        # fingerprint (regra+arquivo+valor ocultado) em UM achado, contando as recidivas.
        result.findings = _collapse_history(result.findings)
        return result


def _file_units(
    paths: Iterable[Path | str], config: Config, skipped: dict[str, int]
) -> Iterator[Unit]:
    for raw in paths:
        for file_path in iter_files(Path(raw), config, skipped):
            text = read_text(file_path)
            if text is None:
                skipped["binario"] += 1
                continue
            yield (str(file_path), text, None)


def _nome_casa(nome: str, padroes: tuple[str, ...]) -> bool:
    """Padrões :mod:`fnmatch` sobre o nome do arquivo; prefixo ``!`` nega."""
    if not any(fnmatch(nome, p) for p in padroes if not p.startswith("!")):
        return False
    return not any(fnmatch(nome, p[1:]) for p in padroes if p.startswith("!"))


def _dedupe_overlapping(
    hits: list[tuple[Rule, int, str, float]],
) -> list[tuple[Rule, int, str, float]]:
    """Mantém, entre matches que cobrem o mesmo trecho, o de maior severidade — e, no
    empate, a regra específica antes da genérica de entropia.

    ``high-entropy-string`` é o fallback MAIS genérico (casa qualquer cadeia, inclusive
    o path inteiro diluído): perde o empate para qualquer outra regra de entropia, como
    a precisa ``secret-in-path`` — senão o rótulo genérico (e rebaixável em teste)
    soterrava o achado de formato, exatamente o caso do F-007."""
    if len(hits) < 2:
        return hits
    ordered = sorted(
        hits,
        key=lambda h: (
            -h[0].severity.rank,
            h[0].category == "entropy",
            h[0].id == "high-entropy-string",
            # `config-file-secret` é o fallback largo de config (qualquer `chave: valor`):
            # perde o empate para a regra canônica do formato — `dotenv-assignment` num
            # `.env`, um segredo de fornecedor — mantendo o rótulo mais informativo.
            h[0].id == "config-file-secret",
            h[0].id,
        ),
    )
    kept: list[tuple[Rule, int, str, float]] = []
    for hit in ordered:
        _, start, secret, _ = hit
        a1, a2 = start, start + len(secret)
        if any(a1 < ks + len(ksec) and ks < a2 for (_, ks, ksec, _) in kept):
            continue  # sobrepõe um já mantido (mais severo/específico)
        kept.append(hit)
    return kept


def _collapse_history(findings: list[Finding]) -> list[Finding]:
    """Colapsa achados idênticos (mesma fingerprint) vindos de blobs diferentes do
    histórico num único achado, acumulando ``occurrences`` e o último commit visto.

    O primeiro commit permanece em ``location.commit``; o mais recente (na ordem de
    varredura) vai para ``commit_last``. Preserva a ordenação de entrada.
    """
    indice: dict[str, int] = {}
    kept: list[Finding] = []
    for f in findings:
        fp = f.fingerprint
        if fp in indice:
            anterior = kept[indice[fp]]
            kept[indice[fp]] = replace(
                anterior,
                occurrences=anterior.occurrences + 1,
                commit_last=f.location.commit,
            )
        else:
            indice[fp] = len(kept)
            kept.append(f)
    return kept


def _is_allowlisted(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in _ALLOW_MARKERS)
