"""Catálogo de regras de detecção de segredos.

Cada regra aponta para uma classe do OWASP Top 10 e um CWE. A recomendação
assume o pior caso — que o segredo já vazou — e por isso sempre começa por
**rotacionar/revogar**, não apenas remover do histórico.
"""

from __future__ import annotations

import re

from guardiao.core.models import Severity
from guardiao.rules.base import Rule, compile_rule

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
    "api",
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


def default_rules() -> list[Rule]:
    return [
        compile_rule(
            "private-key",
            "Chave privada (PEM/OpenSSH)",
            Severity.CRITICAL,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
            cwe="CWE-321",
            owasp="A02:2021 Cryptographic Failures",
            recommendation="Chave privada exposta compromete TLS/mTLS/assinaturas. " + _ROTATE,
        ),
        compile_rule(
            "aws-access-key-id",
            "AWS Access Key ID",
            Severity.HIGH,
            r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp="A05:2021 Security Misconfiguration",
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
            owasp="A05:2021 Security Misconfiguration",
            recommendation="Segredo de acesso AWS. " + _ROTATE,
        ),
        compile_rule(
            "github-token",
            "GitHub token (PAT/OAuth/App)",
            Severity.HIGH,
            r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp="A07:2021 Identification and Authentication Failures",
            recommendation="Token do GitHub. Revogue em Settings > Developer settings. " + _ROTATE,
        ),
        compile_rule(
            "github-pat-fine-grained",
            "GitHub fine-grained PAT",
            Severity.HIGH,
            r"\b(github_pat_[0-9A-Za-z_]{22,255})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp="A07:2021 Identification and Authentication Failures",
            recommendation="Token fine-grained do GitHub. " + _ROTATE,
        ),
        compile_rule(
            "gitlab-pat",
            "GitLab Personal Access Token",
            Severity.HIGH,
            r"\b(glpat-[0-9A-Za-z_-]{20,50})\b",
            secret_group=1,
            cwe="CWE-798",
            owasp="A07:2021 Identification and Authentication Failures",
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
            owasp="A08:2021 Software and Data Integrity Failures",
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
            owasp="A05:2021 Security Misconfiguration",
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
            owasp="A05:2021 Security Misconfiguration",
            recommendation="Token do Slack. " + _ROTATE,
        ),
        compile_rule(
            "slack-webhook",
            "Slack Incoming Webhook",
            Severity.MEDIUM,
            r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]{16,})",
            secret_group=1,
            cwe="CWE-200",
            owasp="A01:2021 Broken Access Control",
            recommendation="Webhook do Slack permite postar como o app. " + _ROTATE,
        ),
        compile_rule(
            "sendgrid-api-key",
            "SendGrid API Key",
            Severity.HIGH,
            r"\b(SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43})(?![0-9A-Za-z_-])",
            secret_group=1,
            cwe="CWE-798",
            owasp="A05:2021 Security Misconfiguration",
            recommendation="Chave de API do SendGrid (prefixo SG.) permite enviar e-mail em seu "
            "domínio — risco de phishing/spoofing. Revogue no painel do SendGrid. " + _ROTATE,
        ),
        compile_rule(
            "mercadopago-access-token",
            "Mercado Pago Access Token",
            Severity.CRITICAL,
            r"\b(APP_USR-\d+-\d{6}-[0-9a-f]{32}-\d+)\b",
            secret_group=1,
            cwe="CWE-798",
            owasp="A05:2021 Security Misconfiguration",
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
            owasp="A05:2021 Security Misconfiguration",
            recommendation="Chave secreta de produção da Stripe. Roll da chave no dashboard. "
            + _ROTATE,
        ),
        compile_rule(
            "jwt",
            "JSON Web Token (JWT)",
            Severity.MEDIUM,
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
            secret_group=1,
            cwe="CWE-522",
            owasp="A07:2021 Identification and Authentication Failures",
            recommendation="JWT no código. Se for de sessão/serviço, invalide-o. "
            "Confirme se não carrega dados sensíveis no payload (é apenas base64, não é cifrado).",
        ),
        compile_rule(
            "db-connection-uri",
            "URI de banco com credenciais",
            Severity.HIGH,
            r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://"
            r"[^:@\s/]+:[^@\s/]{1,}@[^\s'\"]+)",
            secret_group=1,
            cwe="CWE-798",
            owasp="A05:2021 Security Misconfiguration",
            recommendation="String de conexão com usuário e senha embutidos. " + _ROTATE,
        ),
        compile_rule(
            "basic-auth-url",
            "Credencial em URL (Basic Auth)",
            Severity.MEDIUM,
            r"\b(https?://[^:@\s/]+:[^@\s/]{3,}@[^\s'\"]+)",
            secret_group=1,
            cwe="CWE-522",
            owasp="A07:2021 Identification and Authentication Failures",
            recommendation="Usuário:senha embutidos na URL vazam em logs e histórico. " + _ROTATE,
        ),
        compile_rule(
            "generic-assignment",
            "Segredo genérico atribuído a chave sensível",
            Severity.MEDIUM,
            r"""(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|"""
            r"""access[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key)\b"""
            r"""["' ]?\s*[:=]\s*["']([^"'\n]{8,80})["']""",
            secret_group=1,
            min_entropy=3.2,
            cwe="CWE-798",
            owasp="A05:2021 Security Misconfiguration",
            recommendation="Valor de alta entropia atribuído a uma chave sensível. " + _ROTATE,
        ),
        compile_rule(
            "high-entropy-string",
            "String de alta entropia (possível segredo)",
            Severity.MEDIUM,
            r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/=_-]{24,120})(?![A-Za-z0-9+/=_-])",
            secret_group=1,
            category="entropy",
            keywords=SECRET_CONTEXT,  # só dispara perto de palavra de contexto de segredo
            cwe="CWE-798",
            owasp="A05:2021 Security Misconfiguration",
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
            cwe="CWE-359",
            owasp="A02:2021 / LGPD art. 46",
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
            cwe="CWE-359",
            owasp="A02:2021 / LGPD",
            recommendation="CNPJ em texto claro. Avalie se precisa estar versionado no repositório.",
        ),
    ]


# Valores obviamente de exemplo/placeholder que não devem gerar achado.
PLACEHOLDER_SUBSTRINGS: tuple[str, ...] = (
    "example",
    "exemplo",
    "changeme",
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
    "1234567890",
    "abcdefgh",
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

# Credencial embutida em URL de EXEMPLO/teste (docs, fixtures de parser) — não é vazamento real.
_URL_CRED = re.compile(
    r"^[a-z][a-z0-9+.\-]*://(?P<user>[^:@/\s]+):(?P<pw>[^@/\s]+)@(?P<host>[^/:\s]+)",
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
_PLACEHOLDER_USERS = frozenset({"user", "username", "test", "foo", "bar", "me"})
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
        return True  # localhost / IP privado / example.* / *.test|.local|.invalid
    user_ph = user in _PLACEHOLDER_USERS or set(user) <= {"x"}
    pw_ph = (
        pw in _PLACEHOLDER_PWS
        or set(pw) <= {"x"}
        or any(w in pw for w in ("changeme", "example", "pass", "secret"))
    )
    return user_ph and pw_ph  # user E senha placeholder (não suprime vazamento real)


def looks_like_placeholder(secret: str) -> bool:
    """Heurística barata para descartar valores de exemplo/documentação."""
    if secret in KNOWN_FAKE_SECRETS:
        return True
    lowered = secret.lower()
    if lowered in _WEAK_EXAMPLE_VALUES:
        return True
    if any(sub in lowered for sub in PLACEHOLDER_SUBSTRINGS):
        return True
    if _REPEATED.match(secret):
        return True
    return _is_example_url_cred(secret)


def is_probable_hash_or_id(token: str) -> bool:
    """UUID ou SHA-1 de 40 hex (commit/pin de action) — estrutura de hash, não de segredo."""
    return bool(_UUID.match(token) or _GIT_SHA.match(token))
