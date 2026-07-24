# Changelog

Todos os lançamentos notáveis deste projeto são documentados aqui.
O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e
[Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado

- Três novos detectores de provedores com formato público e documentado:
  **Shopify** (`shpat_`/`shpca_`/`shppa_` = access token e `shpss_` = shared secret,
  prefixo + 32 hex; acesso à Admin API da loja), **Doppler** personal token
  (`dp.pt.` + 43 base62 — chave-mestra de um gestor de segredos, severidade crítica) e
  **Linear** API key (`lin_api_` + 40 base62). Cada regra ancora no prefixo fixo do
  fornecedor (baixo falso-positivo) e tem teste positivo (token sintético realista) e
  negativo (uso benigno do prefixo, ex.: `shpat_`/`dp.pt.`/`lin_api_` sem o corpo do token).
- Três novos detectores de provedores com formato público e documentado:
  **Twilio** API Key SID (`SK` + 32 hex, 34 chars — REST API Key Resource),
  **DigitalOcean** access token (`dop_`/`doo_`/`dor_v1_` + 64 hex) e
  **Hugging Face** access token (`hf_`, risco de supply chain de ML). Cada regra
  ancora no prefixo fixo do fornecedor (baixo falso-positivo) e tem teste positivo
  (token sintético realista) e negativo (uso benigno do prefixo, ex.: `SKU-`, `hf_model_config`).
- Quatro novos detectores de provedores, todos com formato público e documentado:
  **Mercado Pago** access token (`APP_USR-<appid>-<data>-<hash>-<userid>`, crítico —
  atende ao item de roadmap de gateways de pagamento BR), **GitLab** PAT (`glpat-`),
  **npm** token (`npm_`, risco de supply chain) e **SendGrid** API key (`SG.`).
- O detector do Mercado Pago distingue o **access token** (segredo de backend) da
  **public key** de frontend: exige que o primeiro segmento seja numérico, evitando
  falso-positivo na chave pública. Cada regra tem teste positivo (token realista) e
  negativo (entrada benigna / chave pública).

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
