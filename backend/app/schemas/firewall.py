"""Schemas del estado del firewall: FirewallStatus, ApplyResponse, ChainDrift.

Bloque A5. Son el contrato de los tres endpoints de `/firewall`, y lo que
alimenta las dos piezas de la UI que hacen visible el diseño: el badge de estado
y el banner de drift.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.firewall.spec import Chain

__all__ = [
    "ApplyResponse",
    "ChainApply",
    "ChainDrift",
    "FirewallStatus",
]


class ChainApply(BaseModel):
    """Lo que se ha hecho —o se haria— con una cadena."""

    chain: Chain
    applied: int = Field(description="Reglas de usuario que quedan en la cadena.")
    #: Los comandos, ya listos para leer o para pegar en un terminal. Se
    #: entregan como texto y no como lista de listas porque el valor de un
    #: preview esta en poder LEERLO antes de ejecutarlo: es la mitigacion nº2
    #: del problema del auto-bloqueo. `shlex.join` no pierde informacion, asi
    #: que sigue siendo el argv exacto, solo que legible.
    commands: list[str]


class ApplyResponse(BaseModel):
    """Respuesta de `POST /firewall/apply` y de `GET /firewall/preview`.

    Es la misma forma para los dos a proposito: el preview no es un modo
    escondido ni un endpoint aparte que pueda divergir, es la misma
    reconciliacion con `dry_run=True`. Si el preview y el apply pudieran dar
    listas distintas, el preview no serviria para lo unico que existe.
    """

    dry_run: bool
    chains: list[ChainApply]
    applied_at: datetime | None = Field(
        default=None, description="Nulo en un preview: no se ha ejecutado nada."
    )


class ChainDrift(BaseModel):
    """Diferencia entre lo que dice la base de datos y lo que hay en la cadena.

    `missing` y `pending` son las dos mitades de "esta en la DB y no en
    iptables", y separarlas importa: una regla recien creada todavia no se ha
    aplicado y eso es normal; una regla que se creia aplicada y no esta significa
    que alguien toco el firewall por fuera. Solo lo segundo es drift.
    """

    chain: Chain
    has_drift: bool
    managed: int = Field(description="Reglas gestionadas leidas de la cadena.")
    missing: list[str] = Field(
        default_factory=list,
        description="Uuids de reglas que se creian aplicadas y no estan en la cadena.",
    )
    pending: list[str] = Field(
        default_factory=list,
        description="Uuids de reglas aun sin aplicar. No son drift.",
    )
    #: La linea original de `iptables -S`, no una interpretacion. Es lo que hay
    #: que enseñar cuando toca explicar por que una cadena no cuadra.
    unexpected: list[str] = Field(
        default_factory=list,
        description="Lineas presentes en la cadena que no salen de la base de datos.",
    )
    out_of_order: bool = Field(
        default=False,
        description="Estan todas las reglas, pero en otro orden. En iptables el orden es la semantica.",
    )


class FirewallStatus(BaseModel):
    """Respuesta de `GET /firewall/status`: la foto que pinta el dashboard."""

    backend: str = Field(description="'fake' o 'iptables'.")
    scaffold_ok: bool = Field(description="Existen las cadenas gestionadas FWDASH_*.")
    has_drift: bool
    chains: list[ChainDrift]
    rules_total: int
    rules_pending: int
    last_applied_at: datetime | None = None
