"""Logica de negocio. Orquesta `models/` y `firewall/`.

REGLA: ningun modulo de este paquete importa `fastapi`. Si lo hace, los tests
unitarios dejan de poder ejercitarlo sin levantar la app."""
