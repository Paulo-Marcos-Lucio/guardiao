"""Corpus de referência do detector BR (regras `cpf`/`cnpj`) — rotulado.

Existe para medir, com número e não com lembrança, o que a conferência do
dígito verificador (DV) compra. `avaliar.py` roda cada caso duas vezes:

1. **com DV** — contra o motor real (a regra valida o módulo 11 via
   ``cpf_valido``/``cnpj_valido``);
2. **sem DV** — contra a MESMA regex, mas sem chamar o validador — o que a
   regra faria se checasse só o formato.

A diferença de precisão entre as duas é o número que esta bateria publica.

Os negativos cobrem duas classes distintas:

- número no FORMATO de CPF/CNPJ (inclusive alfanumérico) com DV que não
  confere — é o caso que a regex sozinha aceitaria e o validador rejeita;
- ruído realista de texto (telefone, ID/protocolo, timestamp) que não tem
  esse formato — mede falso-positivo fora da forma do documento.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Caso:
    texto: str
    eh_pii: bool
    tipo: str


CASOS: tuple[Caso, ...] = (
    # --- positivos: CPF/CNPJ com DV correto (módulo 11) -------------------- #
    Caso("cliente: 529.982.247-25", True, "cpf"),
    Caso("titular do contrato: 390.533.447-05", True, "cpf"),
    Caso("responsável pela compra: 874.216.350-17", True, "cpf"),
    Caso("fornecedor: 11.222.333/0001-81", True, "cnpj-numerico"),
    Caso("matriz do grupo: 11.444.777/0001-61", True, "cnpj-numerico"),
    # CNPJ alfanumérico (formato vigente desde 31/07/2026, IN RFB 2.229/2024):
    Caso("inscrição nova: 12.ABC.345/01DE-35", True, "cnpj-alfanumerico"),
    Caso("filial recém-aberta: AB.123.CD4/5E67-10", True, "cnpj-alfanumerico"),
    # --- negativos: formato de documento, DV que não confere --------------- #
    Caso("numero do pedido: 000.000.000-00", False, "cpf-dv-invalido"),
    Caso("codigo do produto: 123.456.789-10", False, "cpf-dv-invalido"),
    Caso("referência interna: 102.938.475-00", False, "cpf-dv-invalido"),
    Caso("nota fiscal: 12.345.678/0001-00", False, "cnpj-dv-invalido"),
    Caso("convênio: 98.765.432/0001-00", False, "cnpj-dv-invalido"),
    Caso("sku do lote: AB.CDE.FGH/IJKL-99", False, "cnpj-dv-invalido"),
    Caso("inscrição recusada: 12.ABC.345/01DE-00", False, "cnpj-dv-invalido"),
    # --- negativos: telefone (não tem a forma de CPF/CNPJ) ------------------ #
    Caso("contato: (11) 98765-4321", False, "telefone"),
    Caso("suporte: 0800 727 2772", False, "telefone"),
    Caso("whatsapp: +55 11 91234-5678", False, "telefone"),
    Caso("fixo da filial: (21) 2222-3333", False, "telefone"),
    # --- negativos: ID/protocolo (formato de código, não de documento) ----- #
    Caso("protocolo de atendimento: ORD-2026-00458912", False, "id"),
    Caso("rastreio dos correios: BR123456789XX", False, "id"),
    Caso("uuid da requisição: 550e8400-e29b-41d4-a716-446655440000", False, "id"),
    Caso("ticket interno: #A1B2-C3D4", False, "id"),
    # --- negativos: timestamp (formato de data/hora, não de documento) ----- #
    Caso("entrada em vigor: 2026-07-31T14:05:00Z", False, "timestamp"),
    Caso("gerado em 13/10/2026 09:41:02", False, "timestamp"),
    Caso("epoch do evento: 1760349662", False, "timestamp"),
)
