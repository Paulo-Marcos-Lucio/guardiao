"""Higiene de material publicado (Classe H): o e-mail de contato é o público.

O contato de clientes da suíte é ``contatopml26@gmail.com``. O e-mail pessoal
NUNCA pode aparecer em arquivo versionado — é a classe de vazamento que a auditoria
cruzada pegou no Pro de outra ferramenta. Aqui a invariante fecha a porta antes de
qualquer push: se o pessoal reaparecer num README, num badge ou no código, o CI
reprova. Ataca a classe (varre a árvore inteira), não um arquivo escolhido a dedo.
"""

from __future__ import annotations

from pathlib import Path

# Montado em pedaços para o próprio guard não casar a si mesmo na varredura.
_PESSOAL = "pmlsp23" + "@gmail.com"
_PUBLICO = "contatopml26@gmail.com"
_RAIZ = Path(__file__).resolve().parent.parent
_EXTS = {".md", ".py", ".toml", ".svg", ".yml", ".yaml", ".json", ".txt", ".cfg"}
_IGNORAR = {".git", ".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__"}


def _arquivos_de_texto() -> list[Path]:
    saida: list[Path] = []
    for caminho in _RAIZ.rglob("*"):
        if any(parte in _IGNORAR for parte in caminho.parts):
            continue
        if caminho.is_file() and caminho.suffix.lower() in _EXTS:
            saida.append(caminho)
    return saida


def test_email_pessoal_nunca_em_arquivo_versionado() -> None:
    ofensores = [
        str(c.relative_to(_RAIZ))
        for c in _arquivos_de_texto()
        if _PESSOAL in c.read_text(encoding="utf-8", errors="ignore")
    ]
    assert not ofensores, f"e-mail pessoal vazou em: {ofensores}; use {_PUBLICO}"
