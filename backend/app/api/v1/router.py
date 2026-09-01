"""Agregador de los routers de la v1.

Bloque A1."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import health

__all__ = ["api_router"]

api_router = APIRouter()

api_router.include_router(health.router)

# Se van añadiendo aqui, y en ningun otro sitio:
#   A4: from app.api.v1 import auth      -> api_router.include_router(auth.router)
#   A5: from app.api.v1 import rules, firewall
#   Fase 2: logs
#   Fase 3: stats
