"""Gera os fixtures cujo segredo tem formato que o GitHub Secret Scanning bloqueia.

Existe por um motivo prático e instrutivo: um corpus de segredos **não pode versionar
segredos em formato de produção** — o push protection do GitHub recusa, e com razão.
Estes casos ficam como `.tpl` e são materializados na hora de rodar a bateria.

Uso:
    python bench/gerar.py        # antes de `guardiao scan bench`
"""

import os
import secrets
import string

BASE = os.path.dirname(os.path.abspath(__file__))
ALFABETO = string.ascii_letters + string.digits


def preenche(molde: str) -> str:
    """Substitui cada `{N}` por N caracteres aleatórios do alfabeto do provedor."""
    saida, i = [], 0
    while i < len(molde):
        if molde[i] == "{":
            fim = molde.index("}", i)
            saida.append("".join(secrets.choice(ALFABETO) for _ in range(int(molde[i + 1 : fim]))))
            i = fim + 1
        else:
            saida.append(molde[i])
            i += 1
    return "".join(saida)


def materializa(base: str) -> list[str]:
    """Materializa todo `.tpl` sob `base`; devolve os caminhos gerados, relativos a `base`.

    Parametrizado (em vez de usar `BASE` direto) para que o teste de invariante do
    benchmark (`tests/test_bench_avaliar.py`) rode a mesma lógica sobre uma cópia
    temporária do corpus, sem escrever segredo sintético dentro do repositório.
    """
    gerados = []
    for raiz, _, arquivos in os.walk(base):
        for nome in arquivos:
            if not nome.endswith(".tpl"):
                continue
            origem = os.path.join(raiz, nome)
            destino = origem[: -len(".tpl")]
            with open(origem, encoding="utf-8") as fh:
                conteudo = preenche(fh.read())
            with open(destino, "w", encoding="utf-8") as fh:
                fh.write(conteudo)
            gerados.append(os.path.relpath(destino, base))
    return gerados


def main() -> None:
    gerados = materializa(BASE)
    for caminho in gerados:
        print(f"  gerado: {caminho}")
    print(f"{len(gerados)} fixture(s) materializado(s).")


if __name__ == "__main__":
    main()
