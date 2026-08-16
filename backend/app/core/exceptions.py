"""Jerarquia de excepciones de dominio.

Bloque A1. Los servicios lanzan estas, NUNCA `HTTPException`: eso los ataria a
FastAPI y romperia los tests unitarios. La traduccion a HTTP ocurre en
`app/api/errors.py`. Ver docs/ARCHITECTURE.md §5.2."""
