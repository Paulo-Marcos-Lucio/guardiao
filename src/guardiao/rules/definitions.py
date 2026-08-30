"""Catálogo de regras de detecção de segredos.

Cada regra aponta para uma classe do **OWASP Top 10:2025** e um CWE. A
recomendação assume o pior caso — que o segredo já vazou — e por isso sempre
começa por **rotacionar/revogar**, não apenas remover do histórico.
"""

from __future__ import annotations

import re

from guardiao.core.entropy import MIN_SECRET_LEN, is_high_entropy
from guardiao.core.models import Confidence, EvidenceType, Severity
from guardiao.rules.base import Rule, compile_rule
from guardiao.rules.br import cnpj_valido, cpf_valido

#: Edição do OWASP Top 10 usada em todos os rótulos deste catálogo.
OWASP_EDITION = "2025"

_A01 = "A01:2025 Broken Access Control"
_A02 = "A02:2025 Security Misconfiguration"
_A03 = "A03:2025 Software Supply Chain Failures"
_A04 = "A04:2025 Cryptographic Failures"
_A07 = "A07:2025 Authentication Failures"

_ROTATE = "Revogue/rotacione a credencial AGORA (o histórico Git é público mesmo após remoção), remova do código e injete via variável de ambiente ou cofre de segredos."

# Contexto que precisa estar PRESENTE na linha para a regra genérica de entropia disparar.
# Sem isso, "alta entropia" pega hash de lockfile, SHA de commit, UUID e blob base64 — ruído.
# Regras específicas (AWS, GitHub, Stripe, chave privada...) NÃO dependem deste contexto.
SECRET_CONTEXT: tuple[str, ...] = (
    "secret",
    "token",
    "key",
    "keys",
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "pass",
    # `api` isolado casava DENTRO de `FastAPI` (fronteira camelCase) e ligava a
    # regra de entropia num comentário `SQLAlchemy/Redis/FastAPI` — FP de campo.
    # `apikey`/`api_key`/`api_token` continuam cobertos por `key`/`token`/`apikey`.
    "apikey",
    "access",
    "auth",
    "authorization",
    "authtoken",
    "oauth",
    "credential",
    "cred",
    "bearer",
    "private",
    "encrypt",
    "encryption",
)

# Contexto que, se presente na linha, DESLIGA a regra de entropia.
# Entropia não distingue hash de segredo — os dois são cadeias aleatórias e
# matematicamente idênticas. O único discriminante barato é o contexto: uma linha
# que fala em `md5`, `etag` ou `integrity` está descrevendo um digest, não uma
# credencial. Isso é uma heurística, não uma prova: um segredo numa linha que
# também contenha "checksum" passa despercebido.
HASH_CONTEXT: tuple[str, ...] = (
    "hash",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "checksum",
    "digest",
    "etag",
    "integrity",
    "fingerprint",
    "revision",
    "commit",
    "idempotency",
)

# Contexto de CHAVE PÚBLICA / valor publicável: quando a linha fala de chave pública,
# JWKS, chave publicável de fornecedor (Stripe pk_live/pk_test) ou site-key de reCAPTCHA,
# a cadeia de alta entropia ali é um valor PÚBLICO por design — não uma credencial (FP-02).
PUBLIC_KEY_CONTEXT: tuple[str, ...] = (
    "public_key",
    "publickey",
    "pub_key",
    "pubkey",
    "public-key",
    "publishable",
    "pk_live",
    "pk_test",
    "site_key",
    "sitekey",
    "recaptcha",
    "jwks",
    "authorized_keys",
    "known_hosts",
    "ssh-rsa",
    "ssh-ed25519",
    "ssh-dss",
    "verify_key",
    "verifying_key",
    "x5c",
    "kty",
    "dkim",
)


# Hash de senha em formato crypt(3)/PHC (`$2b$…` bcrypt, `$argon2id$…`, `$6$…` sha512-crypt,
# `pbkdf2_sha256$…` Django, `sha256$…`): é o HASH já derivado, não a senha em claro. Guardião
# detecta segredo/credencial em claro; um hash não é isso (FP-03).
_HASH_CRIPTO_RE = re.compile(
    r"^\$(?:2[aby]?|1|5|6|argon2(?:i|d|id)?|scrypt|apr1|y|pbkdf2[\w-]*|sha\d+|md5)\$"
    r"|^(?:pbkdf2_(?:sha\d+|hmac)|bcrypt|argon2|scrypt|sha1|sha256|sha512)\$",
    re.IGNORECASE,
)


# Mesmo padrão, mas para procurar EM QUALQUER PONTO da linha (um `$2b$12$…` embutido num
# INSERT SQL ou num YAML de seed). O `high-entropy-string` captura o corpo base64 do hash e
# suas barras viram "path" — neutralizar a entropia na linha inteira mata a classe (FP-03).
_HASH_CRIPTO_LINHA_RE = re.compile(
    r"\$(?:2[aby]?|1|5|6|argon2(?:i|d|id)?|scrypt|apr1|y|pbkdf2[\w-]*|sha\d+|md5)\$"
    r"|(?:pbkdf2_(?:sha\d+|hmac)|bcrypt|argon2|scrypt)\$",
    re.IGNORECASE,
)


def e_hash_cripto(value: str) -> bool:
    """O valor é um hash de senha em formato crypt/PHC (não a senha em claro)?"""
    return bool(_HASH_CRIPTO_RE.match(value.strip()))


def linha_tem_hash_cripto(raw_line: str) -> bool:
    """A linha contém um hash crypt/PHC (bcrypt/argon2/sha-crypt)? Então a alta entropia
    ali é o hash, não uma credencial em claro (FP-03)."""
    return bool(_HASH_CRIPTO_LINHA_RE.search(raw_line))


# Palavras-chave que marcam uma atribuição como sensível na regra genérica.
# `pass` e `senha` (PT-BR) entram por último e SÓ casam em fronteira de palavra/`_`
# (`DB_PASS`, `senha =`) — nunca dentro de `compass`/`bypass`. `passphrase` (chave de
# GPG/SSH) é palavra própria, não coberta por `password`.
_CHAVE_SENSIVEL = (
    "password|passwd|pwd|passphrase|secret[_-]?key|secret|token|api[_-]?key|apikey"
    "|access[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key|senha|pass"
)
# Em camelCase, `...Token` e `...Key` são sufixos comuns de lexer/parser/AST
# (`nextLastSignificantToken`, `UnexpectedToken`). Numa medição em 24.943 arquivos reais,
# 48 dos 79 falso-positivos vinham daí, com ZERO verdadeiro-positivo — por isso o ramo
# camelCase não aceita `token` nem `key` isolados.
_CHAVE_SENSIVEL_CAMEL = (
    "password|passwd|secret[_-]?key|client[_-]?secret|api[_-]?key|apikey"
    "|access[_-]?key|auth[_-]?token|private[_-]?key"
)
# Fronteira por caractere alfanumérico (e não `\b`): `\b` não existe entre `_` e letra,
# então `DB_PASSWORD`, `JWT_SECRET` e `DJANGO_SECRET_KEY` não casavam `\bpassword\b`.
_ANCORA_CHAVE = (
    rf"(?:(?<![A-Za-z0-9])(?i:{_CHAVE_SENSIVEL})"
    rf"|(?<=[a-z0-9])(?=[A-Z])(?i:{_CHAVE_SENSIVEL_CAMEL}))(?![A-Za-z0-9])"
)

# Cadeia longa candidata a segredo. `=` sai do corpo e dos lookarounds (senão a regra
# capturava `NOME=VALOR` inteiro como se o nome da variável fizesse parte do segredo);
# fica só como padding base64 no fim. Sem teto de comprimento: o teto real de custo é
# o `max_line_length` do motor, e um segredo LONGO não pode ser menos visível que um curto.
_ENTROPIA_PATTERN = (
    r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{" + str(MIN_SECRET_LEN) + r",}={0,2})(?![A-Za-z0-9+/_-])"
)

# Segmento de path/URL longo o bastante para ser um token: `/…<seg>…/`. Ao contrário
# do `_ENTROPIA_PATTERN`, o `/` NÃO entra na classe — é o delimitador do segmento, para
# não diluir o token. O segmento é aceito/rejeitado depois pelo filtro multi-sinal da
# categoria `entropy` (`looks_like_secret_token`), que separa token aleatório de slug
# legível. A fronteira final aceita `/`, aspas, espaço, query/fragmento ou fim de linha.
_SECRET_IN_PATH_PATTERN = r"/([A-Za-z0-9+_=-]{" + str(MIN_SECRET_LEN) + r",})(?=[/\"'\s?#]|$)"

# `.env` e amigos: ali `CHAVE=valor` sem aspas é o formato normal, e restringir a regra
# a esses arquivos mantém o falso-positivo em zero por construção (em código-fonte,
# `token = alguma_funcao()` é uma das linhas mais comuns que existem).
_ARQUIVOS_DOTENV = (
    ".env",
    ".env.*",
    "*.env",
    ".envrc",
    "!*.example",
    "!*.sample",
    "!*.template",
    "!*.dist",
    "!example.*",
    "!sample.*",
    "!template.*",
    "!*.example.*",
    "!*.sample.*",
    "!*example*",
)
# Valor SEM aspas. `$` saiu da classe de exclusão: um cifrão é caractere comum de
# senha (`Xk9$abc…`) e barrá-lo criava falso-negativo; o template `${VAR}` continua
# excluído pelas chaves `{}` e o ref de shell `$VAR` cru é barrado pelo validator.
# A cauda `(?:[ \t]+#…)?` aceita o comentário inline que dotenv/docker permitem.
_DOTENV_PATTERN = (
    r"^[ \t]*(?:export[ \t]+)?[A-Za-z0-9_]*"
    rf"(?<![A-Za-z0-9])(?i:{_CHAVE_SENSIVEL})(?![A-Za-z0-9])"
    r"[A-Za-z0-9_]*[ \t]*=[ \t]*"
    r"""([^\s"'\n(){}\[\];,<>]{8,80})(?:[ \t]+#[^\n]*)?[ \t]*$"""
)
# Valor ENTRE aspas em `.env` — permite ESPAÇO no valor (passphrase de GPG/SSH, que
# legitimamente tem espaço) e serve os casos que a genérica não pega porque o valor
# tem espaço ou a chave é `passphrase`/`senha`. O `\1` fecha na mesma aspa que abriu.
_DOTENV_QUOTED_PATTERN = (
    r"^[ \t]*(?:export[ \t]+)?[A-Za-z0-9_]*"
    rf"(?<![A-Za-z0-9])(?i:{_CHAVE_SENSIVEL})(?![A-Za-z0-9])"
    r"[A-Za-z0-9_]*[ \t]*=[ \t]*"
    r"""(['"])(.{6,200}?)\1[ \t]*(?:#[^\n]*)?$"""
)

# Arquivos de CONFIGURAÇÃO/CREDENCIAL onde `chave: valor` / `chave=valor` / `<chave>valor`
# SEM aspas é a convenção de credencial (YAML de k8s/compose/Helm, `.properties` do
# Spring, `.cnf`/`.ini`, `settings.xml`/`web.config`, `.npmrc`, `.pypirc`, `netrc`). Fora
# desses formatos — em código-fonte — `password = get_env()` é uma das linhas mais comuns
# que existem, e é por isso que a regra é ESCOPADA por nome de arquivo (como a do `.env`).
_ARQUIVOS_CONFIG = (
    "*.yml",
    "*.yaml",
    "*.properties",
    "*.cnf",
    "*.ini",
    "*.conf",
    "*.config",
    "*.xml",
    "*.npmrc",
    ".npmrc",
    ".pypirc*",
    "netrc",
    ".netrc",
)
# Chave sensível para a regra de config: além do vocabulário comum, os nomes de campo de
# credencial de ferramenta (`_authToken`/`_auth` do npm, `AccountKey` do Azure).
_CHAVE_CONFIG = (
    r"password|passwd|pwd|passphrase|secret[_-]?key|secret|token|api[_-]?key|apikey"
    r"|access[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key|senha|pass"
    r"|_authtoken|_auth|account[_-]?key|accountkey"
)
# Palavra sensível colada a UM delimitador de config (`:` de YAML, `=` de INI/query,
# `>` de XML, ou espaço de netrc) e um valor sem aspas. O delimitador tem de vir LOGO
# após a palavra — `auth.password.error=…` (i18n) não casa, porque entre `password` e
# `=` há `.error`. É esse "adjacente ao delimitador" que separa credencial de string i18n.
_CONFIG_SECRET_PATTERN = (
    r"(?<![A-Za-z0-9])(?i:" + _CHAVE_CONFIG + r")(?![A-Za-z])"
    r"(?:\s*[:=]\s*|\s*>\s*|[ \t]+)"
    r"""([^\s"'<>;,&\n]{6,200})"""
)
# `.pgpass`: linha POSICIONAL `host:porta:db:usuário:senha` — sem palavra-chave, o
# segredo é o 5º campo. Escopada a `.pgpass` (por isso 4 dois-pontos bastam como forma).
_PGPASS_PATTERN = r"^[^:\n]+:[^:\n]*:[^:\n]*:[^:\n]*:([^:\n]{4,})[ \t]*$"


def default_rules() -> list[Rule]:
    return [
        compile_rule(
            "private-key",
            "Chave privada (PEM/OpenSSH)",
            Severity.CRITICAL,
            # Além do PEM canônico de 5 traços, os cabeçalhos reais de outras ferramentas:
            # bloco PGP (`… PRIVATE KEY BLOCK`), formato SSH.com/SSH2 (4 traços e espaços
            # em volta), e o `.ppk` do PuTTY (`PuTTY-User-Key-File-N:`). Todos exigem a
            # palavra PRIVATE — o par PÚBLICO (`PGP PUBLIC KEY BLOCK`) nunca casa.
            r"(?:-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
            r"|-{4,5} ?BEGIN SSH2 (?:ENCRYPTED )?PRIVATE KEY ?-{4,5}"
            r"|PuTTY-User-Key-File-\d+:[ \t]*\S+)",
            cwe="CWE-321",
            owasp=_A04,
            recommendation="Chave privada exposta compromete TLS/mTLS/assinaturas. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "aws-access-key-id",
            "AWS Access Key ID",
            Severity.HIGH,
            r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Chave de acesso AWS. Desative a chave no IAM e gere outra. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "aws-secret-access-key",
            "AWS Secret Access Key",
            Severity.HIGH,
            r"""(?i)aws.{0,24}?(?:secret|sk)[^\n]{0,24}?['"]([0-9a-zA-Z/+]{40})['"]""",
            secret_group=1,
            min_entropy=4.2,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Segredo de acesso AWS. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.MEDIUM,
        ),
        compile_rule(
            "github-token",
            "GitHub token (PAT/OAuth/App)",
            Severity.HIGH,
            r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A07,
            recommendation="Token do GitHub. Revogue em Settings > Developer settings. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "github-pat-fine-grained",
            "GitHub fine-grained PAT",
            Severity.HIGH,
            r"\b(github_pat_[0-9A-Za-z_]{22,255})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A07,
            recommendation="Token fine-grained do GitHub. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "gitlab-pat",
            "GitLab Personal Access Token",
            Severity.HIGH,
            r"\b(glpat-[0-9A-Za-z_-]{20,50})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A07,
            recommendation="Token de acesso pessoal do GitLab (prefixo glpat-). "
            "Revogue em User Settings > Access Tokens. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "npm-token",
            "npm access token",
            Severity.HIGH,
            r"\b(npm_[0-9A-Za-z]{36})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A03,
            recommendation="Token de acesso do npm (prefixo npm_) permite publicar pacotes — "
            "risco de supply chain. Revogue em npmjs.com > Access Tokens. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "google-api-key",
            "Google API Key",
            Severity.HIGH,
            r"\b(AIza[0-9A-Za-z_\-]{35})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Chave de API do Google. Restrinja/rotacione no Cloud Console. "
            + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "slack-token",
            "Slack token",
            Severity.HIGH,
            r"\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Token do Slack. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "slack-webhook",
            "Slack Incoming Webhook",
            Severity.MEDIUM,
            r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]{16,})",
            secret_group=1,
            cwe="CWE-200",
            owasp=_A01,
            recommendation="Webhook do Slack permite postar como o app. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "sendgrid-api-key",
            "SendGrid API Key",
            Severity.HIGH,
            r"\b(SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43})(?![0-9A-Za-z_-])",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Chave de API do SendGrid (prefixo SG.) permite enviar e-mail em seu "
            "domínio — risco de phishing/spoofing. Revogue no painel do SendGrid. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "twilio-api-key",
            "Twilio API Key SID",
            Severity.HIGH,
            r"\b(SK[0-9a-f]{32})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="API Key SID do Twilio (SK + 32 hex) autentica envio de SMS/voz e "
            "gera custo na conta. Revogue no Console do Twilio (Account > API keys & tokens). "
            + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "digitalocean-token",
            "DigitalOcean access token",
            Severity.HIGH,
            r"\b((?:dop|doo|dor)_v1_[0-9a-f]{64})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Token de acesso da DigitalOcean (dop_/doo_/dor_v1_) dá acesso de "
            "API à infraestrutura (droplets, DNS, storage, faturamento). Revogue em API > Tokens. "
            + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "huggingface-token",
            "Hugging Face access token",
            Severity.HIGH,
            r"\b(hf_[A-Za-z0-9]{34,64})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A03,
            recommendation="Token de acesso do Hugging Face (prefixo hf_). Um token de escrita "
            "pode publicar em repositórios de modelos/datasets — risco de supply chain de ML. "
            "Revogue em Settings > Access Tokens. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "mercadopago-access-token",
            "Mercado Pago Access Token",
            Severity.CRITICAL,
            r"\b(APP_USR-\d+-\d{6}-[0-9a-f]{32}-\d+)\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Access token de produção do Mercado Pago (APP_USR-...) dá acesso "
            "de backend à conta de pagamentos. Revogue e gere outro no painel de credenciais "
            "(Suas integrações). " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "stripe-secret-key",
            "Stripe Secret Key",
            Severity.CRITICAL,
            r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Chave secreta de produção da Stripe. Roll da chave no dashboard. "
            + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "shopify-token",
            "Shopify access token / shared secret",
            Severity.HIGH,
            r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Credencial da Shopify (shpat_/shpca_/shppa_ = access token; "
            "shpss_ = shared secret) dá acesso à Admin API da loja — pedidos, clientes e "
            "dados sensíveis. Desinstale/reinstale o app na loja ou gire o segredo no "
            "Partner Dashboard. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "doppler-token",
            "Doppler personal token",
            Severity.CRITICAL,
            r"\b(dp\.pt\.[A-Za-z0-9]{43})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Token pessoal do Doppler (dp.pt.) é chave-mestra de um gestor de "
            "segredos: dá acesso a TODOS os segredos das configs a que o usuário tem acesso. "
            "Revogue em Dashboard > Tokens e trate os segredos expostos como comprometidos. "
            + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "linear-api-key",
            "Linear API key",
            Severity.HIGH,
            r"\b(lin_api_[A-Za-z0-9]{40})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A07,
            recommendation="Chave de API pessoal do Linear (lin_api_) autentica na API do "
            "workspace — issues, projetos e roadmap. Revogue em Settings > Security & access "
            "> API. " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "jwt",
            "JSON Web Token (JWT)",
            Severity.MEDIUM,
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
            secret_group=1,
            cwe="CWE-522",
            owasp=_A07,
            recommendation="JWT no código. Se for de sessão/serviço, invalide-o. "
            "Confirme se não carrega dados sensíveis no payload (é apenas base64, não é cifrado).",
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.MEDIUM,
        ),
        compile_rule(
            "db-connection-uri",
            "URI de banco com credenciais",
            Severity.HIGH,
            # O usuário pode ser VAZIO: a forma canônica do Redis (e do AMQP com vhost
            # padrão) omite o usuário — `redis://` seguido de `:senha@host` — e é assim
            # que o redis-cli, o Sidekiq e o REDIS_URL do Heroku a escrevem.
            # `(?:\+[a-z0-9]+)?` aceita o sufixo +driver do SQLAlchemy/DBAPI
            # (`postgresql+psycopg://`, `mysql+pymysql://`) — a forma que TODO backend
            # FastAPI/SQLAlchemy usa; sem isso a senha embutida passava batida.
            # `(?:jdbc:)?` cobre o prefixo do driver Java (`jdbc:postgresql://`,
            # `jdbc:mariadb://…`); os esquemas `mariadb`/`mssql`/`sqlserver`/`smtp` são
            # tão comuns quanto os já listados e têm o MESMO formato `user:senha@host`.
            r"\b((?:jdbc:)?(?:postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss"
            r"|amqp|amqps|mssql|sqlserver|smtp|smtps)"
            r"(?:\+[a-z0-9]+)?://"
            r"[^:@\s/]*:[^@\s/]+@[^\s'\"<>]+)",
            secret_group=1,
            composto=True,
            validator=_uri_conexao_e_vazamento,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="String de conexão com usuário e senha embutidos. " + _ROTATE,
            evidence_type=EvidenceType.CONNECTION_STRING,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "basic-auth-url",
            "Credencial em URL (Basic Auth)",
            Severity.MEDIUM,
            r"\b(https?://[^:@\s/]*:[^@\s/]{3,}@[^\s'\"]+)",
            secret_group=1,
            validator=_basic_auth_url_e_vazamento,
            cwe="CWE-522",
            owasp=_A07,
            recommendation="Usuário:senha embutidos na URL vazam em logs e histórico. " + _ROTATE,
            evidence_type=EvidenceType.CONNECTION_STRING,
            confidence=Confidence.MEDIUM,
        ),
        compile_rule(
            "generic-assignment",
            "Segredo genérico atribuído a chave sensível",
            Severity.MEDIUM,
            _ANCORA_CHAVE + r"""["' ]?\s*[:=]\s*["']([^"'\n]{8,})["']""",
            secret_group=1,
            validator=looks_like_secret_value,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Valor de aparência secreta atribuído a uma chave sensível. " + _ROTATE,
            evidence_type=EvidenceType.GENERIC_SECRET,
            confidence=Confidence.MEDIUM,
        ),
        # Segredo de alta entropia embutido num SEGMENTO de path/URL (`/_internal/<32c>/…`).
        # A regra genérica de entropia diluía o token no `/` e o keyword-gate cegava a
        # linha sem palavra de contexto — este era o buraco do F-007. Aqui o path É o
        # contexto: cada segmento entre barras é pontuado por conta própria (categoria
        # `entropy` herda os filtros de aleatoriedade, hash/UUID e pin `@sha`).
        compile_rule(
            "secret-in-path",
            "Segredo de alta entropia embutido em path/URL",
            # MEDIUM (não HIGH) de propósito: é uma heurística de entropia, igual à
            # `high-entropy-string`. Assim uma regra de FORNECEDOR específica que cubra
            # a mesma URL (ex.: `slack-webhook`) vence o desempate do dedup e mantém o
            # rótulo mais informativo.
            Severity.MEDIUM,
            _SECRET_IN_PATH_PATTERN,
            secret_group=1,
            category="entropy",
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Token aleatório embutido num caminho/URL (vaza em logs, "
            "referrer e histórico do navegador). " + _ROTATE,
            evidence_type=EvidenceType.GENERIC_SECRET,
            confidence=Confidence.LOW,
        ),
        compile_rule(
            "dotenv-assignment",
            "Segredo em arquivo .env (valor sem aspas)",
            Severity.HIGH,
            _DOTENV_PATTERN,
            secret_group=1,
            validator=_dotenv_valor_real,
            only_files=_ARQUIVOS_DOTENV,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Credencial em texto claro num arquivo de ambiente versionado. "
            "Tire o arquivo do controle de versão (.gitignore). " + _ROTATE,
            evidence_type=EvidenceType.CREDENTIAL,
            confidence=Confidence.MEDIUM,
        ),
        compile_rule(
            "dotenv-quoted",
            "Segredo em arquivo .env (valor entre aspas)",
            Severity.HIGH,
            _DOTENV_QUOTED_PATTERN,
            secret_group=2,
            validator=_env_quoted_e_segredo,
            only_files=_ARQUIVOS_DOTENV,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Credencial (inclusive passphrase com espaço) em texto claro num "
            "arquivo de ambiente versionado. Tire o arquivo do controle de versão. " + _ROTATE,
        ),
        compile_rule(
            "config-file-secret",
            "Segredo em arquivo de configuração (valor sem aspas)",
            Severity.HIGH,
            _CONFIG_SECRET_PATTERN,
            secret_group=1,
            validator=_config_valor_real,
            only_files=_ARQUIVOS_CONFIG,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Credencial em texto claro num arquivo de configuração versionado "
            "(YAML/INI/properties/XML/npmrc/netrc). Mova para um cofre de segredos. " + _ROTATE,
        ),
        compile_rule(
            "pgpass-credential",
            "Senha em arquivo .pgpass",
            Severity.HIGH,
            _PGPASS_PATTERN,
            secret_group=1,
            validator=looks_like_secret_value,
            only_files=(".pgpass",),
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Senha em texto claro no 5º campo de um .pgpass versionado. " + _ROTATE,
        ),
        compile_rule(
            "high-entropy-string",
            "String de alta entropia (possível segredo)",
            Severity.MEDIUM,
            _ENTROPIA_PATTERN,
            secret_group=1,
            category="entropy",
            keywords=SECRET_CONTEXT,  # só dispara perto de palavra de contexto de segredo
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Cadeia longa e aleatória com cara de segredo. Confirme se não é "
            "credencial/chave; se for, " + _ROTATE,
            evidence_type=EvidenceType.GENERIC_SECRET,
            confidence=Confidence.LOW,
        ),
        compile_rule(
            "cpf",
            "CPF (dado pessoal — LGPD)",
            Severity.LOW,
            r"\b(\d{3}\.\d{3}\.\d{3}-\d{2})\b",
            secret_group=1,
            category="pii",
            validator=lambda valor: cpf_valido(valor) and valor not in CPF_DE_TUTORIAL,
            cwe="CWE-359",
            owasp="A04:2025 / LGPD art. 46",
            recommendation="CPF em texto claro é dado pessoal (LGPD). Remova de logs/código, "
            "minimize e proteja o tratamento; considere anonimização/pseudonimização.",
            evidence_type=EvidenceType.PERSONAL_DATA,
            confidence=Confidence.HIGH,
        ),
        compile_rule(
            "cnpj",
            "CNPJ (dado — LGPD)",
            Severity.INFO,
            r"\b(\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2})\b",
            secret_group=1,
            category="pii",
            validator=cnpj_valido,
            cwe="CWE-359",
            owasp="A04:2025 / LGPD",
            recommendation="CNPJ em texto claro. Avalie se precisa estar versionado no repositório.",
            evidence_type=EvidenceType.PERSONAL_DATA,
            confidence=Confidence.HIGH,
        ),
    ]


# CPFs que passam no módulo 11 mas aparecem em todo tutorial/fixture brasileiro.
CPF_DE_TUTORIAL: frozenset[str] = frozenset({"123.456.789-09", "111.444.777-35"})

# Valores obviamente de exemplo/placeholder que não devem gerar achado.
# NÃO inclua sequências que possam cair por acaso dentro de um segredo real
# (`abcdefgh`, `1234567890`): elas suprimiam em silêncio senhas humanas legítimas
# como `Cliente1234567890`. Valor de exemplo por INTEIRO é tratado por
# `_WEAK_EXAMPLE_VALUES` e `_REPEATED`, que não têm esse efeito colateral.
PLACEHOLDER_SUBSTRINGS: tuple[str, ...] = (
    "example",
    "exemplo",
    "change-me",
    "placeholder",
    "your_",
    "your-",
    "yourkey",
    "yourtoken",
    "dummy",
    "sample",
    "redacted",
    "test-key",
    "test_key",
    "notreal",
    "xxxxxxxx",
    "foobar",
    "0000000000000000",
    "fakekey",
    "fake-",
    "fake_",
    "mock",
    "stub",
    "change_me",
    "changeme",
    "change-this",
    "please",
    "substitute",
    "replace_",
    "replace-",
    "set_this",
    "set-this",
    "setthis",
    "insert_your",
    "provide_your",
    "enter_your",
    "todo",
    "change_this",
    "change this",
    "substitu",
    "troque",
    "insira",
    "coloque",
    "preencha",
    "seu_token",
    "sua_senha",
    "real-token",
    "real_token",
)

# Exemplos canônicos da documentação de fornecedores.
KNOWN_FAKE_SECRETS: frozenset[str] = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        # Chave de TESTE canônica da documentação do Stripe (aparece em quase todo exemplo).
        "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "pk_test_" + "TYooMQauvdEDq54NiTphI7jx",
        # JWT canônico do jwt.io (HS256, John Doe) — exemplo de documentação onipresente.
        # Como o `high-entropy-string` quebra o JWT nos `.`, cada segmento entra à parte.
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4g"
        "RG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    }
)

_REPEATED = re.compile(r"^(.)\1{7,}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_GIT_SHA = re.compile(r"^[0-9a-fA-F]{40}$")  # SHA-1 de commit / action pinada
# Interpolação de template (`${VAR}`, `{{ var }}`, `{NOME_DA_VAR}`) — é a receita do
# segredo, não o segredo.
_TEMPLATE = re.compile(r"\$\{|\{\{|\{[A-Z][A-Z0-9_]{2,}\}|<[A-Za-z][A-Za-z0-9_-]*>")

# Credencial embutida em URL de EXEMPLO/teste (docs, fixtures de parser) — não é vazamento real.
_URL_CRED = re.compile(
    r"^[a-z][a-z0-9+.\-]*://(?P<user>[^:@/\s]*):(?P<pw>[^@/\s]+)@(?P<host>[^/:\s]+)",
    re.IGNORECASE,
)
_EXAMPLE_HOST = re.compile(
    r"^(?:localhost"
    r"|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|\[::1\]"
    r"|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|example\.(?:com|org|net)"
    r"|.+\.(?:example|test|local|localhost|invalid))$",
    re.IGNORECASE,
)
_PLACEHOLDER_USERS = frozenset({"", "user", "username", "test", "foo", "bar", "me"})
_PLACEHOLDER_PWS = frozenset(
    {"pass", "password", "passwd", "secret", "changeme", "test", "foo", "bar", "123456"}
)


# Senhas/segredos fracos ou de exemplo canônicos — valor completo, não vazam nada real.
_WEAK_EXAMPLE_VALUES: frozenset[str] = frozenset(
    {
        "password",
        "password123",
        "passw0rd",
        "p@ssw0rd",
        "mypassword",
        "secret",
        "secret123",
        "supersecret",
        "topsecret",
        "test",
        "test123",
        "admin",
        "admin123",
        "changeme",
        "letmein",
        "hunter2",
        "qwerty",
        "123456",
        "12345678",
        "1234567890",
    }
)


def _is_example_url_cred(secret: str) -> bool:
    match = _URL_CRED.match(secret)
    if match is None:
        return False
    user, pw = match.group("user").lower(), match.group("pw").lower()
    if "{" in user or "{" in pw or "%25" in user or "%25" in pw:
        return True  # template de formato ({ENCODED_USER}) ou fixture de parser de URL
    if _EXAMPLE_HOST.match(match.group("host").lower()):
        # localhost / IP privado / example.* NÃO é passe-livre por si só: uma senha
        # de ALTA ENTROPIA contra um banco de dev é uma credencial real committada
        # (bancos de dev vazam). Só é exemplo se a senha TAMBÉM parecer placeholder.
        return not _pw_looks_real(pw)
    user_ph = user in _PLACEHOLDER_USERS or set(user) <= {"x"}
    pw_ph = (
        pw in _PLACEHOLDER_PWS
        or set(pw) <= {"x"}
        or any(w in pw for w in ("changeme", "example", "pass", "secret"))
    )
    return user_ph and pw_ph  # user E senha placeholder (não suprime vazamento real)


def is_obvious_fake(secret: str) -> bool:
    """Descarte que vale para **todas** as regras: valor de exemplo por inteiro.

    Só casa o valor COMPLETO (ou a estrutura completa, no caso de URL/template), então
    nunca engole um segredo real por coincidência de substring.
    """
    if secret in KNOWN_FAKE_SECRETS:
        return True
    if secret.lower() in _WEAK_EXAMPLE_VALUES:
        return True
    if _REPEATED.match(secret):
        return True
    if _TEMPLATE.search(secret):
        return True
    return _is_example_url_cred(secret)


def looks_like_placeholder(secret: str) -> bool:
    """Heurística barata para descartar valores de exemplo/documentação."""
    if is_obvious_fake(secret):
        return True
    lowered = secret.lower()
    return any(sub in lowered for sub in PLACEHOLDER_SUBSTRINGS)


def is_probable_hash_or_id(token: str) -> bool:
    """UUID ou SHA-1 de 40 hex (commit/pin de action) — estrutura de hash, não de segredo.

    Deliberadamente **não** cobre 32 hex (MD5) nem 64 hex (SHA-256): esses são
    exatamente os comprimentos de `openssl rand -hex 16/32`, ou seja, de segredos
    reais. Hash desses tamanhos é filtrado por :data:`HASH_CONTEXT`, pelo contexto
    da linha — não pela forma do token.
    """
    return bool(_UUID.match(token) or _GIT_SHA.match(token))


# --------------------------------------------------------------------------- #
# Aparência de segredo: pontuação MULTI-SINAL (não um limiar rígido único)
# --------------------------------------------------------------------------- #
# A entropia de Shannon por-alfabeto (`is_high_entropy`) subestima cadeias de UMA
# única classe (ex.: 32 letras MAIÚSCULAS aleatórias): o alfabeto teórico é 36, mas
# só 26 símbolos aparecem, e o token cai abaixo do limiar mesmo sendo aleatório. O
# discriminante barato que sobra é a IMPRONUNCIABILIDADE: uma sequência aleatória de
# letras acumula corridas longas de consoantes que palavras/identificadores legíveis
# (`get_user_by_email`, `AbstractFactoryBean`) não têm. É um SINAL adicional, somado
# à entropia — nunca um filtro que substitui os outros.

_CONSOANTES = re.compile(r"[bcdfghjklmnpqrstvwxyz]+", re.IGNORECASE)
#: hex de 32+ (`openssl rand -hex 16/32`, md5, sha256) — formato de segredo conhecido.
_HEX_SECRET = re.compile(r"^[0-9a-fA-F]{32,}$")

#: Fronteira de segmento de identificador: `_`, `-`, `.` ou transição camelCase.
_SEP_IDENTIFICADOR = re.compile(r"[_\-.]+|(?<=[a-z0-9])(?=[A-Z])")
_VOGAL = re.compile(r"[aeiouyAEIOUY]")
#: Sequência de URL-encoding (`%5D`, `%F0`): sinal de dado de URL/fixture, não de segredo.
_URL_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")


def _parece_identificador_de_codigo(token: str) -> bool:
    """Token com estrutura de identificador de código (snake_case/kebab/camelCase de
    palavras legíveis) — NUNCA é um segredo aleatório.

    Esta é a CAUSA-RAIZ da classe de falso-positivo em que `cert_encrypted_private_key_file`
    virava achado: a heurística de impronunciabilidade (:func:`_max_consonant_run`) dispara
    em palavras reais (``encrypted`` tem a corrida ``ncrypt`` = 6 consoantes), e a de entropia
    subestima o token. O discriminante é a ESTRUTURA: um segredo de base64/hex não se decompõe
    em sub-palavras pronunciáveis; um identificador, sim.

    Critério (conservador, para não cegar segredo real): 2+ segmentos, quase todos só-letras,
    com vogal e curtos (≤12), cobrindo ≥70% dos caracteres do token. Um blob aleatório com `_`/`-`
    tem segmentos com dígitos (``xK7mP9``) que não contam como palavra → não é bloqueado.
    """
    segmentos = [s for s in _SEP_IDENTIFICADOR.split(token) if s]
    if len(segmentos) < 2:
        return False
    palavras = [s for s in segmentos if s.isalpha() and 2 <= len(s) <= 12 and _VOGAL.search(s)]
    if len(palavras) < 2 or len(palavras) < len(segmentos) - 1:
        return False
    cobertura = sum(len(p) for p in palavras)
    return cobertura * 10 >= len(token) * 7


def _predominantemente_url_encoded(value: str) -> bool:
    """O valor é majoritariamente sequências ``%XX`` (dado de URL/fixture de parser)?

    Fecha a classe do ``"password": "%F0%9F%92%A9"`` da suíte de conformidade WHATWG:
    um emoji URL-encoded não é uma credencial. Exige que as sequências ``%XX`` cubram a
    maior parte do valor — uma senha real com um único ``%`` não é afetada.
    """
    encoded = "".join(m.group() for m in _URL_ENCODED.finditer(value))
    return len(encoded) * 10 >= len(value) * 6


def _max_consonant_run(token: str) -> int:
    """Maior corrida de consoantes (só LETRAS; vogais, dígitos e símbolos quebram)."""
    return max((len(m.group()) for m in _CONSOANTES.finditer(token)), default=0)


def _num_char_classes(value: str) -> int:
    """Quantas das 4 classes (minúscula/maiúscula/dígito/símbolo) o valor mistura."""
    return sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )


def _proporcao_vogais(token: str) -> float:
    vogais = sum(1 for c in token.lower() if c in "aeiou")
    return vogais / len(token) if token else 0.0


def tem_letra_nao_ascii(s: str) -> bool:
    """Tem letra acentuada/não-ASCII? Um segredo base64/hex é ASCII puro; uma palavra
    natural (alemão `Zugriffsschlüssel`) não — e é isso que o corpo do token denuncia (FP-07)."""
    return any(ord(c) > 127 and c.isalpha() for c in s)


def looks_like_secret_token(token: str, *, min_length: int = MIN_SECRET_LEN) -> bool:
    """Um token isolado (segmento de path, cadeia solta) parece gerado aleatoriamente?

    Multi-sinal: entropia alta por-alfabeto **OU** impronunciabilidade (corrida longa
    de consoantes) numa cadeia longa. UUID/SHA-1 são estrutura de hash, não segredo.
    """
    if len(token) < min_length:
        return False
    if is_probable_hash_or_id(token):
        return False
    if _parece_identificador_de_codigo(token):
        return False  # identificador de código (`cert_encrypted_private_key_file`) não é segredo
    if is_high_entropy(token):
        return True
    if _max_consonant_run(token) < 6:
        return False
    # Corrida de consoantes aceita blob impronunciável (ex.: base64 MAIÚSCULO), MAS uma
    # palavra natural composta (alemão `...schluessel`, com `ue`) também dispara. O
    # discriminante: palavra é toda alfabética e tem vogais suficientes; segredo real
    # quase sempre traz dígitos/símbolos (FP-07).
    return not (token.isalpha() and _proporcao_vogais(token) >= 0.22)


#: Partes de uma URL Basic-Auth, tolerante a host vazio/absurdo (o que os fixtures de
#: parser de URL produzem: `http://user:pass@/`, `http://&a:foo@d:2/`).
_BASIC_AUTH_PARTS = re.compile(
    r"^https?://(?P<user>[^:@/\s]*):(?P<pw>[^@/\s]+)@(?P<host>[^/\s?#'\"]*)",
    re.IGNORECASE,
)


def _basic_auth_url_e_vazamento(url: str) -> bool:
    """A URL Basic-Auth carrega credencial REAL, ou é fixture de parser de URL?

    CAUSA-RAIZ da classe: a suíte de conformidade WHATWG (`tests/models/whatwg.json`) usa
    URLs sintaticamente válidas mas absurdas — host vazio (`@/`), host de 1 caractere
    (`@d:2/`), senha de teste URL-encoded. A regex de `basic-auth-url` casava todas. O
    discriminante de classe é o HOST: um vazamento real tem host com forma de domínio/
    hostname (≥4 caracteres); um fixture de parser tem host degenerado. Sob host degenerado,
    só é vazamento se a senha for de ALTA ENTROPIA (uma senha real embutida contra um host
    curto interno continua pega); caso contrário, é dado de teste.
    """
    m = _BASIC_AUTH_PARTS.match(url)
    if m is None:  # não bate o parser fino: mantém o veredito da regex principal
        return True
    if _is_example_url_cred(url):
        return False  # já coberto (example.com, user:pass, template) — não duplica
    pw = m.group("pw")
    hostname = m.group("host").split(":")[0]
    if len(hostname) < 4:
        # host degenerado (vazio, 1-3 chars: fixture de parser): só vaza se a senha for
        # de alta entropia (uma senha real contra host interno curto continua pega).
        return is_high_entropy(pw, min_length=12)
    # host com forma de domínio: ainda exige que a SENHA pareça real. `a%20secret`
    # (a-space-secret, URL-encoded) contra `müller.de` é exemplo de parser de URL, não
    # vazamento. `_pw_looks_real` reprova senha URL-encoded/placeholder e aprova segredo real.
    return _pw_looks_real(pw)


def _pw_looks_real(pw: str) -> bool:
    """Senha embutida em URL parece um segredo REAL (não `pass`/`changeme`/`postgres`)?

    Usado para decidir se uma URL contra host local/privado ainda é vazamento.
    """
    if pw in _PLACEHOLDER_PWS or set(pw) <= {"x"}:
        return False
    if any(w in pw for w in ("changeme", "example", "pass", "secret")):
        return False
    return (
        is_high_entropy(pw, min_length=12)
        or _num_char_classes(pw) >= 3
        or _max_consonant_run(pw) >= 6
    )


# Palavras que aparecem em VALORES de teste/fixture mas nunca dentro de um segredo real
# aleatório. Usadas só pela `generic-assignment`, e só abaixo do gate de alta entropia.
_TEST_VALUE_MARKERS: tuple[str, ...] = (
    "teste",
    "senha",
    "segredo",
    "test",
    "fixture",
    "example",
    "exemplo",
    "dummy",
    "sample",
    "changeme",
    "placeholder",
    "fake",
    "mock",
)


def looks_like_secret_value(value: str) -> bool:
    """O VALOR atribuído a uma chave sensível parece um segredo? (piso da genérica)

    A `generic-assignment` casava qualquer literal de 8+ chars, afogando o relatório
    em `mynewpassword`/`wrong password`/nome de bind-var do psql. Este piso multi-sinal
    exige que o valor PAREÇA segredo, sem cair no extremo oposto (derrubar senha humana
    curta legítima como `Brasil@2024` ou `Cliente1234567890`):

    * valor com espaço em branco → nunca é um token (mata `wrong password`);
    * entropia alta OU formato hex conhecido → aceita chaves/hashes;
    * 3+ classes de caracteres → aceita senhas humanas mistas (`S3cr3tP4ss…`);
    * uma classe só, mas longa e impronunciável → aceita blob MAIÚSCULO aleatório;
    * caso contrário (identificador legível `monitoring_password`) → rejeita.
    """
    if any(c.isspace() for c in value):
        return False
    if e_hash_cripto(value):
        return False  # hash de senha (bcrypt/argon2/sha-crypt) é derivado, não a senha (FP-03)
    if _predominantemente_url_encoded(value):
        return False  # `%F0%9F%92%A9` (emoji URL-encoded de fixture) não é credencial
    if is_high_entropy(value) or _HEX_SECRET.match(value):
        return True
    # Marcador de TESTE/placeholder no VALOR (palavra que um segredo real não carrega):
    # `senha-teste-1`, `nova-senha-teste-9`, `Test@2026!` passavam pelo ramo "3 classes"
    # apesar de baixa entropia. Só suprime AQUI, abaixo do gate de alta entropia — um
    # segredo real (`openssl rand`) já retornou True acima e nunca chega neste ponto,
    # então isto reduz FP sem criar FN. Marcadores curtos ('test') são seguros porque
    # (a) só agem sob baixa entropia e (b) só afetam a `generic-assignment`.
    low = value.lower()
    if looks_like_placeholder(value) or any(m in low for m in _TEST_VALUE_MARKERS):
        return False
    if _num_char_classes(value) >= 3:
        return True
    return len(value) >= MIN_SECRET_LEN and _max_consonant_run(value) >= 6


# --------------------------------------------------------------------------- #
# Validadores das regras de URI/config/credencial (real vs. exemplo)
# --------------------------------------------------------------------------- #
def _uri_conexao_e_vazamento(uri: str) -> bool:
    """A URI de conexão carrega credencial REAL, ou é exemplo/template?

    A regra é ``composto=True``: o motor NÃO roda o filtro de placeholder por substring
    (que barrava errado `db.prod.internal/sample_reports` por conter ``sample``). Aqui a
    decisão é ESTRUTURAL — ``is_obvious_fake`` parseia a URL (``user:senha@host``) e só
    reprova quando usuário E senha são placeholder (`foo:bar`), o host é de exemplo
    (`localhost`/IP privado/`example.com`) com senha fraca, ou o valor é template
    (`${VAR}`). Uma senha real contra `db.prod.internal` passa e é reportada."""
    return not is_obvious_fake(uri)


def _dotenv_valor_real(value: str) -> bool:
    """Valor SEM aspas de `.env` é segredo, ou template/ref de shell?

    Com o `$` de volta na classe do valor (senha com cifrão), reintroduz-se o risco do
    template — este validador o barra: `${VAR}` e `$VAR` cru são a receita do segredo,
    não o segredo. Qualquer outra coisa (`Xk9$abc…`) passa."""
    if is_obvious_fake(value):
        return False
    return re.fullmatch(r"\$\{?[A-Za-z_][\w]*\}?", value) is None


def _env_quoted_e_segredo(value: str) -> bool:
    """Valor ENTRE aspas de `.env` (pode ter espaço) parece segredo?

    Aceita passphrase de várias palavras desde que ALGUM token pareça aleatório
    (alta entropia, hex, ou 3+ classes de caractere). Reprova placeholder/template e
    frases-instrução (`please generate a random string`)."""
    if is_obvious_fake(value) or looks_like_placeholder(value):
        return False
    return any(
        len(tok) >= 8
        and (is_high_entropy(tok) or _HEX_SECRET.match(tok) or _num_char_classes(tok) >= 3)
        for tok in value.split()
    )


def _config_valor_real(value: str) -> bool:
    """Valor SEM aspas de arquivo de configuração parece segredo?

    Reusa o piso multi-sinal da genérica (`looks_like_secret_value`: reprova hash de
    senha bcrypt/argon2, valor com espaço, identificador legível) e barra a mais os
    refs de template/YAML-tag (`${VAR}`, `!Ref`, `$VAR`) que só aparecem em config."""
    if value[:1] in "$!":
        return False
    if is_obvious_fake(value) or looks_like_placeholder(value):
        return False
    return looks_like_secret_value(value)
