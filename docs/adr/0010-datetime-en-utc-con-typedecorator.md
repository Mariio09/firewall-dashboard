# ADR-0010: Normalizar los datetime en el tipo de columna, no en los schemas

- **Fecha:** 2026-09-02
- **Estado:** Aceptado

## Contexto

El recorrido manual de A4 destapó que `/auth/me` devuelve
`"2026-09-01T22:08:13.179259"`, **sin `Z` ni offset**. La columna se declara
`DateTime(timezone=True)` y `utcnow()` escribe con `tzinfo`, pero **SQLite no
almacena la zona**: SQLAlchemy devuelve un datetime ingenuo y Pydantic lo
serializa tal cual. En JavaScript, `new Date("2026-09-01T22:08:13")` se
interpreta como hora **local** — en Madrid, dos horas de desfase.

Es un bug silencioso: no rompe nada, solo desplaza las fechas. La convención de
que todos los `datetime` de la base de datos son UTC existía precisamente para
evitar esto y no lo evitó, porque era una convención sin nada que la hiciera
cumplir.

A5 multiplica los campos de fecha (`applied_at`, `expires_at`, y los `ts` de la
fase 2), así que es el último momento barato para arreglarlo.

## Opciones consideradas

### A — `field_serializer` por schema

Un serializador en `UserRead`, otro en `RuleRead`, otro en cada schema nuevo.
Cinco líneas hoy. Hay que acordarse en cada modelo que se añada, y el día que se
olvide el síntoma vuelve a ser una gráfica desplazada dos horas.

### B — `TypeDecorator` en `db/base.py`

Un tipo de columna, `UtcDateTime`, que repone `tzinfo=UTC` al leer y normaliza a
UTC al escribir. Toca las ocho columnas de fecha de los cinco modelos, de una
vez, y vale también para los modelos que todavía no existen.

### C — Guardar texto ISO

Resuelve la zona y rompe todo lo demás: comparaciones, `ORDER BY`, `func.max`.

## Decisión

Opción B. El arreglo va en el tipo de columna, que es el único sitio por el que
pasan todas las fechas del proyecto.

Al **escribir** se rechaza un datetime ingenuo en vez de suponerle UTC. Suponer
es lo que produjo el problema: un naive puede venir de `datetime.now()` —hora
local del servidor— o de un ISO sin offset, y no hay forma de distinguirlos. Que
falle en el acto convierte un desfase invisible en un error localizable.

Para que esa dureza no le llegue al cliente como un 500, la entrada del usuario
se valida antes: `expires_at` es `AwareDatetime` en los schemas, así que una
fecha sin offset es un 422 con explicación.

## Consecuencias

**Positivas:** la convención "todo UTC en la base de datos" deja de ser una
convención y pasa a ser un invariante que el código impone. No hace falta
migración: `UtcDateTime` genera el mismo `DATETIME` que `DateTime(timezone=True)`,
así que el esquema no cambia. En un motor que sí guarda la zona (PostgreSQL) el
tipo sigue valiendo: se limita a asegurar que lo que vuelve es UTC.

**Negativas:** cualquier `datetime` ingenuo que llegue a un modelo ahora explota.
Es deliberado, y es la mitad del valor de la decisión, pero significa que un
descuido en un servicio se manifiesta como un 500 y no como un valor raro.

**Qué invalidaría esta decisión:** nada previsible. Si algún día hiciera falta
guardar la zona original de un evento —no el instante, la zona— haría falta una
columna aparte, no cambiar este tipo.
