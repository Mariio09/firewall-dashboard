# ADR-0009: PyJWT en vez de python-jose

- **Fecha:** 2026-09-01
- **Estado:** Aceptado

## Contexto

El scaffolding de A0 fijó `python-jose[cryptography]` como librería de JWT sin discutirlo:
es la que aparece en el tutorial clásico de FastAPI. A4 es el primer paso que la usa de
verdad, y por tanto el momento de mirarla.

`python-jose` lleva años sin mantenimiento activo y arrastra vulnerabilidades conocidas de
confusión de algoritmo y de coste de descompresión al decodificar tokens. Las dependencias
de desarrollo de este proyecto ya incluyen `pip-audit`: el resultado de dejarla sería una
herramienta de seguridad defensiva cuya propia auditoría de dependencias señala su librería
de autenticación.

## Opciones consideradas

### A — Mantener `python-jose` y silenciar el aviso
**Ventajas:** cero cambios; nada que reinstalar.
**Inconvenientes:** añadir una excepción a `pip-audit` para que deje de avisar es
exactamente el antipatrón que este proyecto pretende saber detectar.

### B — Cambiar a `PyJWT`
**Ventajas:** mantenida, es la que usa hoy la documentación de FastAPI, API más pequeña
(`encode` / `decode`) y tipada. El cambio es una línea del `pyproject.toml`, porque todo el
uso de JWT está confinado en `core/security.py`.
**Inconvenientes:** hay que volver a sincronizar el entorno.

### C — Firmar los tokens a mano con `hmac` y `hashlib`
**Ventajas:** ninguna dependencia.
**Inconvenientes:** cripto propia. Son treinta líneas hasta el primer error de
implementación que nadie ve.

## Decisión

**Opción B.** `pyjwt>=2.9` sustituye a `python-jose[cryptography]`.

Que el cambio cueste una línea no es casualidad: es la ventaja de haber metido toda la
cripto en un único módulo sin dependencias del ORM ni de FastAPI.

## Consecuencias

**Positivas:** `pip-audit` queda limpio. `jwt.decode` se llama siempre con
`algorithms=[settings.jwt_algorithm]` explícito, que es la mitigación estándar del ataque de
confusión de algoritmo; hay un test que construye a mano un token con `alg: none` —sin pasar
por la librería, para que siga probando el ataque aunque PyJWT cambie— y comprueba que se
rechaza. Además se exigen los claims `exp`, `iat`, `sub` y `type` al decodificar: un JWT sin
`exp` es una llave que no caduca nunca.

**Negativas:** hace falta `uv sync` en el host y `python-jose` desaparece del lockfile. PyJWT
avisa con `InsecureKeyLengthWarning` si la clave HMAC baja de 32 bytes, lo que aparece en los
tests que firman con claves cortas a propósito; la clave real la genera A1 con 64 caracteres
hexadecimales.

**Qué invalidaría esta decisión:** pasar a firmar con claves asimétricas (RS256/EdDSA) para
que un tercero pueda validar tokens sin conocer el secreto. PyJWT también lo hace, así que
ni siquiera eso.
