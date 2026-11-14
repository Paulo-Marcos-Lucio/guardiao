"""Invariante de classe: toda recomendação do catálogo traz o comando de conferência de purga.

Contrapartida pública do G12 (a reescrita de histórico assistida em si é
item de trilha privada, risco alto). O README já dizia "achar é metade;
`git filter-repo` e a rotação são trabalho separado" — mas não dizia COMO o
usuário confirma, no próprio clone, que a reescrita funcionou. "Reescrevi o
histórico" e "confirmei que sumiu" são afirmações diferentes, e só a segunda
fecha o problema.

Um teste por regra provaria isso só para as regras que alguém lembrou de
testar — exatamente o defeito que `test_catalogo.py` já achou uma vez (uma
regra inteira sem linha na tabela do README). Este teste varre `all_rules()`
inteiro: qualquer regra nova que entrar no catálogo sem o comando de
conferência quebra o CI, não só as 34 de hoje.
"""

from __future__ import annotations

from guardiao.rules.registry import all_rules


def test_toda_recomendacao_do_catalogo_traz_o_comando_de_conferencia_de_purga() -> None:
    sem_comando = [
        rule.id
        for rule in all_rules()
        if "git log" not in rule.recommendation or "-S'" not in rule.recommendation
    ]
    assert not sem_comando, (
        f"regra(s) do catálogo sem o comando git de conferência de purga: {sem_comando}"
    )


def test_comando_de_purga_busca_pelo_conteudo_em_todos_os_refs() -> None:
    """`-S` é pickaxe (busca por CONTEÚDO, não por mensagem) e `--all` cobre todo ref —
    sem os dois a conferência podia voltar vazia só porque olhou o branch errado."""
    for rule in all_rules():
        assert "--all" in rule.recommendation, rule.id
        assert "-S'<trecho do valor>'" in rule.recommendation, rule.id
