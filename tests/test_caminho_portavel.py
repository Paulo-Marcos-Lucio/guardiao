"""Invariante: o caminho do achado é PORTÁTIL — relativo à raiz da varredura, em POSIX.

Achado da auditoria (2026-09-07, Onda 1.3): o caminho do achado era a string crua do
arquivo varrido, NÃO normalizada à raiz. Consequências da mesma causa: (1) o baseline
não casava entre máquinas (o mesmo achado tinha fingerprint diferente por CWD/máquina);
(2) o caminho local do auditor (``C:\\Users\\...``) vazava no entregável; (3) o SARIF
saía com ``artifactLocation.uri`` ABSOLUTA.

Estes testes fixam a CLASSE: varrer o MESMO arquivo a partir de duas raízes absolutas
diferentes tem de produzir ``location.path``, fingerprint e ``uri`` do SARIF IDÊNTICOS e
relativos. Se alguém voltar a emitir o caminho cru (``str(file_path)``), o par
raiz-A/raiz-B diverge e todos estes testes ficam vermelhos.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from guardiao.core.engine import Scanner, _ancora_de_relativizacao, _caminho_portavel
from guardiao.report.sarif import to_sarif
from tests.conftest import AWS_KEY_ID


def _plantar_projeto(raiz: Path) -> Path:
    """Planta o MESMO conteúdo (mesmo caminho relativo) sob ``raiz`` e devolve a raiz."""
    src = raiz / "src"
    src.mkdir(parents=True)
    (src / "config.py").write_text(f'AWS_ACCESS_KEY_ID = "{AWS_KEY_ID}"\n', encoding="utf-8")
    return raiz


def test_mesmo_arquivo_em_duas_raizes_gera_caminho_identico(tmp_path: Path) -> None:
    """location.path é o MESMO a partir de duas raízes absolutas diferentes."""
    raiz_a = _plantar_projeto(tmp_path / "maquina-a")
    raiz_b = _plantar_projeto(tmp_path / "outro" / "lugar" / "maquina-b")
    assert raiz_a.is_absolute() and raiz_b.is_absolute()
    assert str(raiz_a) != str(raiz_b)

    achados_a = Scanner().scan_paths([raiz_a]).findings
    achados_b = Scanner().scan_paths([raiz_b]).findings
    assert achados_a and achados_b

    caminhos_a = {f.location.path for f in achados_a}
    caminhos_b = {f.location.path for f in achados_b}
    assert caminhos_a == caminhos_b == {"src/config.py"}


def test_fingerprint_de_baseline_identica_entre_raizes(tmp_path: Path) -> None:
    """A chave de baseline (fingerprint = regra+caminho+valor ocultado) não pode
    depender da máquina: dois auditores com o repo em pastas diferentes têm de gerar
    o MESMO baseline, senão ele nunca casa e o CI nunca suprime a dívida aceita."""
    raiz_a = _plantar_projeto(tmp_path / "a")
    raiz_b = _plantar_projeto(tmp_path / "b-mais-fundo" / "ainda-mais")

    fp_a = {f.fingerprint for f in Scanner().scan_paths([raiz_a]).findings}
    fp_b = {f.fingerprint for f in Scanner().scan_paths([raiz_b]).findings}
    assert fp_a and fp_a == fp_b


def test_sarif_uri_e_relativa_sem_drive(tmp_path: Path) -> None:
    """O SARIF sobe para o Code Scanning: a uri não pode carregar drive nem caminho
    absoluto do auditor, e tem de ser a MESMA entre raízes."""
    raiz_a = _plantar_projeto(tmp_path / "a")
    raiz_b = _plantar_projeto(tmp_path / "sub" / "b")

    def _uris(raiz: Path) -> set[str]:
        doc = json.loads(to_sarif(Scanner().scan_paths([raiz])))
        uris: set[str] = set()
        for res in doc["runs"][0]["results"]:
            uris.add(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
        return uris

    uris_a = _uris(raiz_a)
    uris_b = _uris(raiz_b)
    assert uris_a == uris_b == {"src/config.py"}
    for uri in uris_a:
        assert "\\" not in uri  # POSIX, nunca separador do Windows
        assert not uri.startswith("/")  # não é absoluto POSIX
        assert not os.path.isabs(uri)
        # sem "C:" nem qualquer letra de drive no começo
        assert not (len(uri) >= 2 and uri[1] == ":")
        assert "C:" not in uri and str(tmp_path) not in uri


def test_alvo_arquivo_isolado_vira_nome_base(tmp_path: Path) -> None:
    """Varrer UM arquivo (não uma pasta) rende só o nome dele — âncora = pasta-mãe."""
    alvo = _plantar_projeto(tmp_path / "proj") / "src" / "config.py"
    achados = Scanner().scan_paths([alvo]).findings
    assert achados
    assert {f.location.path for f in achados} == {"config.py"}


def test_caminho_nunca_absoluto_em_varredura_de_diretorio(tmp_path: Path) -> None:
    """Nenhum achado de uma varredura de diretório carrega caminho absoluto/Windows."""
    _plantar_projeto(tmp_path / "proj")
    for f in Scanner().scan_paths([tmp_path / "proj"]).findings:
        p = f.location.path
        assert not os.path.isabs(p)
        assert "\\" not in p
        assert not (len(p) >= 2 and p[1] == ":")


def test_fallback_fora_da_ancora_nao_vaza_absoluto() -> None:
    """Caso patológico: arquivo lexicamente incomparável à âncora (ramo irmão).

    O ``relative_to`` falha e o resolve também não casa — o fallback tem de devolver
    só o NOME do arquivo, jamais o caminho absoluto (fail-closed)."""
    if os.name == "nt":
        arquivo = Path(r"C:\Users\auditor\segredos\prod\config.py")
        ancora = Path(r"D:\projeto\repo")
    else:
        arquivo = Path("/home/auditor/segredos/prod/config.py")
        ancora = Path("/srv/projeto/repo")
    resultado = _caminho_portavel(arquivo, ancora)
    assert resultado == "config.py"
    assert not os.path.isabs(resultado)
    assert "auditor" not in resultado  # o caminho do auditor não vazou


def test_ancora_de_diretorio_e_ela_mesma(tmp_path: Path) -> None:
    proj = _plantar_projeto(tmp_path / "proj")
    assert _ancora_de_relativizacao(proj) == proj
    arquivo = proj / "src" / "config.py"
    assert _ancora_de_relativizacao(arquivo) == arquivo.parent


@pytest.mark.parametrize("alvo_rel", ["proj", "proj/src"])
def test_estabilidade_por_subarvore(tmp_path: Path, alvo_rel: str) -> None:
    """Varrer uma subárvore relativiza à subárvore pedida — sempre POSIX, sempre relativo."""
    _plantar_projeto(tmp_path / "proj")
    alvo = tmp_path / Path(alvo_rel)
    for f in Scanner().scan_paths([alvo]).findings:
        assert not os.path.isabs(f.location.path)
        assert "\\" not in f.location.path
