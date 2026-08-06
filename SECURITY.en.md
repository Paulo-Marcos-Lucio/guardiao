<p align="center"><a href="SECURITY.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/guardiao/main/assets/btn-lang-pt.svg" alt="Ler este documento em Português" width="300"/></a></p>

# Security Policy

## Responsible disclosure

Found a vulnerability in Guardião? Report it **privately**:

- Email: **contatopml26@gmail.com** (subject starting with `[security]`)

Please allow a reasonable amount of time for a fix before disclosing it publicly.

## Scope and principle

Guardião is a **defensive** tool. It is designed to **never** expose the raw secret in
reports (console, JSON, SARIF, or baseline) — only a redacted value. A bug that leaks
a secret into a report is treated as a **security failure** of this tool, not a style issue.

**How much** of the redacted value is shown depends on where it's headed: console and
JSON show 4 characters from each end; the **baseline** (meant to be committed) and the
**SARIF** (which gets uploaded to Code Scanning) show only **2** — 4+4 would reveal 8
characters of any secret with 13+ characters, enough to reconstruct a human password with
a dictionary attack.

The *fingerprint* published in SARIF, JSON, and baseline is derived from
`(rule, file, redacted value)` — **not** from the raw secret. A truncated hash of the
secret might look safe, but for a human password (`Brasil@2024`) a dictionary reverses
it in a few dozen attempts — and these three channels are precisely the ones that leave
your computer.

## Responsible use and legal framing (Brazil)

Use Guardião only on repositories you **own** or for which you have **formal
authorization** to analyze. Even though the tool is passive (it only reads local files
and Git objects), access to the repository itself must be legitimate.

In Brazil, accessing someone else's computer system or device without authorization is a
crime defined under **art. 154-A of the Penal Code (Código Penal)** — unauthorized access
to a computing device, as worded by Law 14.155/2021. The handling of personal data found —
CPF, CNPJ (Brazilian individual/company tax IDs), and credentials that identify people —
is governed by **LGPD (Brazil's data-protection law, GDPR-equivalent; Law 13.709/2018)**,
whose **art. 46** requires technical protection measures. A scan report **is** sensitive
data: keep it with the same care you would give the secret it points to.

Every secret found should be considered compromised — the correct response is to
**rotate/revoke** it, not just remove it from history.
