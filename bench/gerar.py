"""Gera os fixtures cujo segredo tem formato que o GitHub Secret Scanning bloqueia.

Existe por um motivo prático e instrutivo: um corpus de segredos **não pode versionar
segredos em formato de produção** — o push protection do GitHub recusa, e com razão.
Estes casos ficam como molde em `bench/moldes/*.tpl` e são materializados em
`bench/positivos/` na hora de rodar a bateria.

Por que os moldes NÃO ficam dentro de `bench/positivos/` (como ficavam antes do
`GRD-04`): `guardiao scan bench` varre a árvore inteira, sem respeitar `.gitignore` —
não é o papel de um scanner de segredos ignorar o que o Git ignora. Um molde como
`TWILIO_API_KEY = "SK{32:hex}"` sentado ao lado do fixture materializado tem chave
sensível (`TOKEN`/`KEY`) e valor entre aspas com 8+ caracteres — a `generic-assignment`
disparava nele mesmo sem nenhum segredo real, contando como falso-positivo "em linha
errada" contra `positivos/`. Separar o molde do corpus fecha essa classe: o que
`guardiao` varre em `positivos/`/`negativos/` é só o que o `manifest.json` rotula.

Uso:
    python bench/gerar.py        # antes de `guardiao scan bench`
"""

import os
import secrets
import string

BASE = os.path.dirname(os.path.abspath(__file__))
MOLDES = os.path.join(BASE, "moldes")
POSITIVOS = os.path.join(BASE, "positivos")

# Alfabetos por sufixo de molde. `{N}` (sem sufixo) continua alfanumérico — é o que
# `stripe.js.tpl` já usava antes deste dicionário existir. `hex`/`dig` foram
# acrescentados pelo `GRD-04` porque alguns provedores (Twilio, DigitalOcean, Shopify,
# Mercado Pago) exigem um segmento só-hex ou só-dígito: preencher esse segmento com
# letra fora de `a-f` ou `A-Z` quebra a regex do próprio Guardião, e o fixture nunca
# dispara o achado que deveria.
_ALFABETOS = {
    "": string.ascii_letters + string.digits,
    "hex": "0123456789abcdef",
    "dig": string.digits,
}


def preenche(molde: str) -> str:
    """Substitui cada `{N}` ou `{N:alfabeto}` por N caracteres aleatórios.

    `alfabeto` é uma chave de :data:`_ALFABETOS` (`hex`, `dig`); omitido, usa o
    alfanumérico padrão.
    """
    saida, i = [], 0
    while i < len(molde):
        if molde[i] == "{":
            fim = molde.index("}", i)
            n, _, chave = molde[i + 1 : fim].partition(":")
            alfabeto = _ALFABETOS[chave]
            saida.append("".join(secrets.choice(alfabeto) for _ in range(int(n))))
            i = fim + 1
        else:
            saida.append(molde[i])
            i += 1
    return "".join(saida)


def main() -> None:
    gerados = 0
    for nome in sorted(os.listdir(MOLDES)):
        if not nome.endswith(".tpl"):
            continue
        origem = os.path.join(MOLDES, nome)
        destino = os.path.join(POSITIVOS, nome[: -len(".tpl")])
        with open(origem, encoding="utf-8") as fh:
            conteudo = preenche(fh.read())
        with open(destino, "w", encoding="utf-8") as fh:
            fh.write(conteudo)
        gerados += 1
        print(f"  gerado: {os.path.relpath(destino, BASE)}")
    print(f"{gerados} fixture(s) materializado(s).")


if __name__ == "__main__":
    main()
