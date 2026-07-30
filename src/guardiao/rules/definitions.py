"""Catálogo de regras de detecção de segredos.

Cada regra aponta para uma classe do **OWASP Top 10:2025** e um CWE. A
recomendação assume o pior caso — que o segredo já vazou — e por isso sempre
começa por **rotacionar/revogar**, não apenas remover do histórico.
"""

from __future__ import annotations

import re

from guardiao.core.entropy import MIN_SECRET_LEN, is_high_entropy, shannon_entropy
from guardiao.core.models import Severity
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

# Palavras-chave que marcam uma atribuição como sensível na regra genérica.
_CHAVE_SENSIVEL = (
    "password|passwd|pwd|secret[_-]?key|secret|token|api[_-]?key|apikey"
    "|access[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key"
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
_SECRET_IN_PATH_PATTERN = (
    r"/([A-Za-z0-9+_=-]{" + str(MIN_SECRET_LEN) + r",})(?=[/\"'\s?#]|$)"
)

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
)
_DOTENV_PATTERN = (
    r"^[ \t]*(?:export[ \t]+)?[A-Za-z0-9_]*"
    rf"(?<![A-Za-z0-9])(?i:{_CHAVE_SENSIVEL})(?![A-Za-z0-9])"
    r"[A-Za-z0-9_]*[ \t]*=[ \t]*"
    r"""([^\s"'\n(){}\[\]$;,<>]{8,80})[ \t]*$"""
)


def default_rules() -> list[Rule]:
    return [
        compile_rule(
            "private-key",
            "Chave privada (PEM/OpenSSH)",
            Severity.CRITICAL,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
            cwe="CWE-321",
            owasp=_A04,
            recommendation="Chave privada exposta compromete TLS/mTLS/assinaturas. " + _ROTATE,
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
            r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)"
            r"(?:\+[a-z0-9]+)?://"
            r"[^:@\s/]*:[^@\s/]+@[^\s'\"]+)",
            secret_group=1,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="String de conexão com usuário e senha embutidos. " + _ROTATE,
        ),
        compile_rule(
            "basic-auth-url",
            "Credencial em URL (Basic Auth)",
            Severity.MEDIUM,
            r"\b(https?://[^:@\s/]*:[^@\s/]{3,}@[^\s'\"]+)",
            secret_group=1,
            cwe="CWE-522",
            owasp=_A07,
            recommendation="Usuário:senha embutidos na URL vazam em logs e histórico. " + _ROTATE,
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
        ),
        compile_rule(
            "dotenv-assignment",
            "Segredo em arquivo .env (valor sem aspas)",
            Severity.HIGH,
            _DOTENV_PATTERN,
            secret_group=1,
            only_files=_ARQUIVOS_DOTENV,
            cwe="CWE-798",
            owasp=_A02,
            recommendation="Credencial em texto claro num arquivo de ambiente versionado. "
            "Tire o arquivo do controle de versão (.gitignore). " + _ROTATE,
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
)

# Exemplos canônicos da documentação de fornecedores.
KNOWN_FAKE_SECRETS: frozenset[str] = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
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


def looks_like_secret_token(token: str, *, min_length: int = MIN_SECRET_LEN) -> bool:
    """Um token isolado (segmento de path, cadeia solta) parece gerado aleatoriamente?

    Multi-sinal: entropia alta por-alfabeto **OU** impronunciabilidade (corrida longa
    de consoantes) numa cadeia longa. UUID/SHA-1 são estrutura de hash, não segredo.
    """
    if len(token) < min_length:
        return False
    if is_probable_hash_or_id(token):
        return False
    if is_high_entropy(token):
        return True
    return _max_consonant_run(token) >= 6


def _pw_looks_real(pw: str) -> bool:
    """Senha embutida em URL parece um segredo REAL (não `pass`/`changeme`/`postgres`)?

    Usado para decidir se uma URL contra host local/privado ainda é vazamento.
    """
    if pw in _PLACEHOLDER_PWS or set(pw) <= {"x"}:
        return False
    if any(w in pw for w in ("changeme", "example", "pass", "secret")):
        return False
    return is_high_entropy(pw, min_length=12) or _num_char_classes(pw) >= 3 or _max_consonant_run(
        pw
    ) >= 6


# Palavras que aparecem em VALORES de teste/fixture mas nunca dentro de um segredo real
# aleatório. Usadas só pela `generic-assignment`, e só abaixo do gate de alta entropia.
_TEST_VALUE_MARKERS: tuple[str, ...] = (
    "teste", "senha", "segredo", "test", "fixture", "example", "exemplo",
    "dummy", "sample", "changeme", "placeholder", "fake", "mock",
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
