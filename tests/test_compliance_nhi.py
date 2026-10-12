"""Invariantes do item G-14pub: NHI2/NHI7 no `owasp` das regras de segredo, bloco
`compliance` (nhi/cwe/lgpd) no relatório JSON, e a frase de cobertura GERADA — nunca
digitada à mão, para não divergir se o catálogo mudar.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from guardiao.core.engine import Scanner
from guardiao.report.json_report import to_document
from guardiao.rules.registry import all_rules

_TODAS_IDS = [r.id for r in all_rules()]


def _documento(rules: list) -> dict:
    resultado = Scanner(rules=rules).scan_units([("a.py", "x = 1\n", None)])
    return to_document(resultado)


# ---- 1) o catálogo: toda regra de segredo mapeia NHI2+NHI7; PII nunca mapeia ---- #


def test_toda_regra_de_segredo_mapeia_nhi2_e_nhi7() -> None:
    """INVARIANTE: toda regra cuja categoria não é `pii` detecta credencial hardcoded —
    por definição NHI2 (Secret Leakage, o vazamento em si) e NHI7 (Long-Lived Secrets,
    a classe do que foi vazado). Regra nova no catálogo que esqueça o rótulo quebra
    este teste, não um exemplo isolado — é a classe, não o caso.
    """
    sem_nhi = [
        r.id
        for r in all_rules()
        if r.category != "pii"
        and ("NHI2:2025" not in (r.owasp or "") or "NHI7:2025" not in (r.owasp or ""))
    ]
    assert sem_nhi == [], f"regra(s) de segredo sem NHI2/NHI7 no owasp: {sem_nhi}"


def test_regra_de_pii_nunca_recebe_rotulo_nhi() -> None:
    """Contraprova: dado pessoal (cpf/cnpj) não é credencial de identidade não-humana —
    mapeia LGPD, não NHI. Trava a classe oposta, para o pós-processamento não vazar
    para onde não devia se alguém remover o filtro `category == "pii"`.
    """
    com_nhi = [r.id for r in all_rules() if r.category == "pii" and "NHI" in (r.owasp or "")]
    assert com_nhi == [], f"regra de PII com rótulo NHI indevido: {com_nhi}"


# ---- 2) o relatório: compliance.lgpd é sempre None; nunca ausente ---- #


def test_compliance_lgpd_e_sempre_none_explicito() -> None:
    """O build open-source não mapeia LGPD automaticamente (isso é o laudo do
    Guardião-Pro, com revisão humana — item G-14 privado). A chave existe e é `None`
    explícito, nunca ausente: um consumidor de máquina não pode confundir "este build
    não faz isso" com "campo esquecido".
    """
    documento = _documento(all_rules())
    compliance = documento["summary"]["compliance"]
    assert "lgpd" in compliance
    assert compliance["lgpd"] is None


# ---- 3) a frase de cobertura é GERADA a partir do que rodou, não hardcoded ---- #


def test_frase_de_cobertura_reflete_o_catalogo_completo() -> None:
    documento = _documento(all_rules())
    compliance = documento["summary"]["compliance"]
    assert compliance["nhi"]["categories"] == ["NHI2", "NHI7"]
    assert compliance["nhi"]["categories_total"] == 10
    assert compliance["coverage_line"] == (
        "Guardião cobre 2 das 10 categorias do OWASP Non-Human Identity (NHI) "
        "Top 10:2025: NHI2, NHI7."
    )


def test_frase_de_cobertura_fica_vazia_sem_regra_nhi_ativa() -> None:
    """Rodar só a regra de CPF (PII, sem NHI) não pode herdar a frase do catálogo
    inteiro — provaria que o texto é fixo, não calculado a partir da seleção real.
    """
    apenas_cpf = [r for r in all_rules() if r.id == "cpf"]
    documento = _documento(apenas_cpf)
    compliance = documento["summary"]["compliance"]
    assert compliance["nhi"]["categories"] == []
    assert "Nenhuma regra ativa" in compliance["coverage_line"]
    assert compliance["cwe"] == ["CWE-359"]  # a cobertura de CWE é a da SELEÇÃO, não do catálogo


# ---- 4) property-based: para qualquer seleção de regras (--only/--skip), a cobertura
#         NHI relatada é exatamente a união dos códigos das regras daquela seleção ---- #


def _codigos_nhi(owasp: str | None) -> set[str]:
    if not owasp:
        return set()
    return {codigo for codigo in ("NHI2", "NHI7") if f"{codigo}:2025" in owasp}


@settings(max_examples=60)
@given(
    selecionados=st.lists(
        st.sampled_from(_TODAS_IDS), min_size=0, max_size=len(_TODAS_IDS), unique=True
    )
)
def test_categorias_nhi_batem_com_a_uniao_da_selecao_ativa(selecionados: list[str]) -> None:
    ativas = [r for r in all_rules() if r.id in selecionados]
    esperado = sorted({c for r in ativas for c in _codigos_nhi(r.owasp)})

    documento = _documento(ativas)
    compliance = documento["summary"]["compliance"]

    assert compliance["nhi"]["categories"] == esperado
    # A frase nunca mente sobre a contagem: o número que ela anuncia bate com o
    # tamanho da lista que ela mesma lista.
    if esperado:
        assert compliance["coverage_line"].startswith(f"Guardião cobre {len(esperado)} das 10")
    else:
        assert "Nenhuma regra ativa" in compliance["coverage_line"]
