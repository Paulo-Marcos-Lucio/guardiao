# Changelog

Todos os lançamentos notáveis deste projeto são documentados aqui.
O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e
[Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [0.1.0] — 2026-07-21

### Adicionado

- Motor de varredura por linha com 16 regras (chaves privadas, AWS, GitHub,
  Google, Slack, Stripe, JWT, URIs de banco, atribuições genéricas de alta
  entropia e PII/LGPD).
- Detecção por **entropia de Shannon** com limiares por alfabeto.
- Redução de falso-positivo: filtro de placeholder, allowlist inline
  (`# guardiao:allow`) e **baseline** para o CI falhar só em segredos novos.
- Varredura do **histórico Git** completo (`git rev-list --all`).
- Renderizadores **console**, **JSON** e **SARIF 2.1.0** — nenhum expõe o segredo cru.
- CLI `guardiao` com `scan`, `rules` e `pre-commit`.
- Suíte de testes (41 casos), tipos estritos (mypy) e CI multi-versão.
