"""Testes do importador de Gitleaks/TruffleHog — contrapartida pública do G11.

Fixa o contrato do documento ``suite-appsec/1`` para um relatório IMPORTADO:
todo achado carrega ``adjudication: null`` (nunca passou pela triagem do
próprio Guardião) e o ``summary`` declara, em prosa, a cobertura de
adjudicação heurística — em vez de deixar a lacuna implícita.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardiao.report import importar

# Segredos sintéticos, fatiados para não casar com o secret-scanning do GitHub
# ao ficarem versionados — mesma convenção de tests/conftest.py.
SEGREDO_GITLEAKS = "ghp_" + "Rk8xY2mN4pQ7wLvB3cD5fG6hJ9kMnP2qAtZ7u"
SEGREDO_TRUFFLEHOG = "AKIA" + "Z7Q2LMN4XYWV8RPD"


def _gravar(tmp_path: Path, nome: str, conteudo: str) -> Path:
    caminho = tmp_path / nome
    caminho.write_text(conteudo, encoding="utf-8")
    return caminho


def test_importa_gitleaks_com_adjudication_null_e_sem_segredo_cru(tmp_path: Path) -> None:
    relatorio = [
        {
            "Description": "GitHub Personal Access Token",
            "StartLine": 12,
            "EndLine": 12,
            "StartColumn": 5,
            "EndColumn": 50,
            "Match": SEGREDO_GITLEAKS,
            "Secret": SEGREDO_GITLEAKS,
            "File": "config.py",
            "Commit": "a1b2c3d4",
            "Entropy": 4.7,
            "RuleID": "github-pat",
            "Fingerprint": "config.py:github-pat:12",
        }
    ]
    caminho = _gravar(tmp_path, "gitleaks.json", json.dumps(relatorio))
    doc = importar.documento("gitleaks", caminho)

    assert doc["schema"] == importar.SCHEMA
    assert doc["fonte"] == "gitleaks"
    assert doc["summary"]["total"] == 1
    assert doc["summary"]["adjudicacao_heuristica"]["cobertura"] == "0/1"
    assert "adjudicação heurística" in doc["summary"]["adjudicacao_heuristica"]["nota"]

    (achado,) = doc["findings"]
    assert achado["adjudication"] is None
    assert achado["id"] == "github-pat"
    assert achado["path"] == "config.py"
    assert achado["line"] == 12
    assert achado["commit"] == "a1b2c3d4"

    # O segredo cru do relatório de origem (`Secret`/`Match`) nunca sobrevive ao
    # import — só a versão ocultada, mesma receita publicada do resto da suíte.
    bruto_json = json.dumps(doc)
    assert SEGREDO_GITLEAKS not in bruto_json
    assert achado["redacted"] is not None and achado["redacted"] != SEGREDO_GITLEAKS


def test_importa_gitleaks_relatorio_vazio_e_lista_vazia(tmp_path: Path) -> None:
    caminho = _gravar(tmp_path, "limpo.json", "[]")
    doc = importar.documento("gitleaks", caminho)
    assert doc["findings"] == []
    assert doc["summary"]["total"] == 0
    assert doc["summary"]["adjudicacao_heuristica"]["cobertura"] == "0/0"


def test_importa_trufflehog_jsonl_com_adjudication_null_e_sem_segredo_cru(
    tmp_path: Path,
) -> None:
    linha_git = json.dumps(
        {
            "SourceMetadata": {
                "Data": {"Git": {"file": "app.py", "line": 7, "commit": "deadbeef"}}
            },
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": SEGREDO_TRUFFLEHOG,
        }
    )
    linha_filesystem = json.dumps(
        {
            "SourceMetadata": {"Data": {"Filesystem": {"file": "notas.txt", "line": 1}}},
            "DetectorName": "Generic",
            "Verified": False,
            "Raw": "nao-e-bem-um-segredo",
        }
    )
    caminho = _gravar(tmp_path, "trufflehog.jsonl", f"{linha_git}\n\n{linha_filesystem}\n")
    doc = importar.documento("trufflehog", caminho)

    assert doc["summary"]["total"] == 2
    for achado in doc["findings"]:
        assert achado["adjudication"] is None

    por_id = {a["id"]: a for a in doc["findings"]}
    assert por_id["AWS"]["path"] == "app.py"
    assert por_id["AWS"]["commit"] == "deadbeef"
    assert por_id["AWS"]["verified"] is True
    assert por_id["Generic"]["path"] == "notas.txt"
    assert por_id["Generic"]["verified"] is False

    assert SEGREDO_TRUFFLEHOG not in json.dumps(doc)


def test_importar_rejeita_fonte_desconhecida(tmp_path: Path) -> None:
    caminho = _gravar(tmp_path, "x.json", "[]")
    with pytest.raises(ValueError):
        importar.documento("semgrep", caminho)


def test_importar_gitleaks_rejeita_formato_que_nao_e_array(tmp_path: Path) -> None:
    caminho = _gravar(tmp_path, "errado.json", json.dumps({"nao": "e array"}))
    with pytest.raises(ValueError):
        importar.importar_gitleaks(caminho)


def test_importar_trufflehog_rejeita_linha_jsonl_invalida(tmp_path: Path) -> None:
    caminho = _gravar(tmp_path, "quebrado.jsonl", "{isto nao e json}\n")
    with pytest.raises(ValueError):
        importar.importar_trufflehog(caminho)


def test_importar_trufflehog_fonte_desconhecida_declara_localizacao_ausente(
    tmp_path: Path,
) -> None:
    """Fonte do trufflehog sem `file`/`line` reconhecidos: ``None`` declarado,
    não adivinhado — ver docstring de `_metadados_trufflehog`."""
    linha = json.dumps(
        {
            "SourceMetadata": {"Data": {"S3": {"bucket": "x"}}},
            "DetectorName": "Generic",
            "Verified": False,
            "Raw": "x",
        }
    )
    caminho = _gravar(tmp_path, "s3.jsonl", linha)
    (achado,) = importar.importar_trufflehog(caminho)
    assert achado["path"] is None
    assert achado["line"] is None


def test_importar_trufflehog_sem_data_reconhecivel_fica_so_com_adjudication_null(
    tmp_path: Path,
) -> None:
    """`SourceMetadata.Data` sem nenhum valor em formato de dicionário (ou
    ausente): o achado ainda existe, só sem localização — nunca um `KeyError`."""
    linha = json.dumps({"DetectorName": "Generic", "Verified": False, "Raw": "x"})
    caminho = _gravar(tmp_path, "sem_metadados.jsonl", linha)
    (achado,) = importar.importar_trufflehog(caminho)
    assert achado["adjudication"] is None
    assert achado["path"] is None


def test_importar_gitleaks_sem_secret_nao_gera_redacted(tmp_path: Path) -> None:
    """Achado sem o campo `Secret` (relatório truncado/parcial): `redacted` fica
    `None` — declarado, não inventado a partir de nada."""
    relatorio = [{"RuleID": "generic-api-key", "File": "a.py", "StartLine": 1}]
    caminho = _gravar(tmp_path, "sem_secret.json", json.dumps(relatorio))
    (achado,) = importar.importar_gitleaks(caminho)
    assert achado["redacted"] is None
    assert achado["adjudication"] is None


def test_to_json_e_serializavel(tmp_path: Path) -> None:
    caminho = _gravar(tmp_path, "gitleaks.json", "[]")
    texto = importar.to_json("gitleaks", caminho)
    assert json.loads(texto)["schema"] == importar.SCHEMA
