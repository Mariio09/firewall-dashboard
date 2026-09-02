"""Agregador de los routers de la v1.

Bloque A1."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import auth, firewall, health, rules

__all__ = ["api_router"]

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(rules.router)
api_router.include_router(firewall.router)

# Se van añadiendo aqui, y en ningun otro sitio:
#   Fase 2: logs
#   Fase 3: stats
