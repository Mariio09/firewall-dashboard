# ADR-0006: Comparar reglas por estructura, nunca por texto

- **Fecha:** 2026-09-01
- **Estado:** Aceptado

## Contexto

La expedición de reconocimiento a la VM (paso A2) destapó que **iptables reescribe cada
regla al guardarla**. La línea que devuelve `iptables -S` no es la que se le pasó, ni
siquiera reordenada: es otra. Comparando el `argv` enviado con la salida capturada en
`tests/fixtures/iptables_output/cargado/save.txt`, sobre `iptables v1.8.11 (nf_tables)`:

| Enviado | Devuelto |
|---|---|
| `-p tcp --dport 22` | `-p tcp -m tcp --dport 22` |
| `--icmp-type echo-request` | `-m icmp --icmp-type 8` |
| `-d 8.8.8.8` | `-d 8.8.8.8/32` |
| `-j LOG --log-level 4` | `-j LOG` |
| `-j REJECT` | `-j REJECT --reject-with icmp-port-unreachable` |
| `-m comment` en medio | `-m comment` siempre justo antes del `-j` |

Hasta ese momento el diseño daba por hecho que la detección de drift consistía en
comparar `iptables -S FWDASH_INPUT` con lo que dice la base de datos. Con la
normalización de por medio, esa comparación da divergencia **siempre**, incluso justo
después de aplicar. Sin decidir esto, el detector de drift gritaría en falso el 100 % de
las veces, y el ruido lo haría inútil.

## Opciones consideradas

### A — Comparar cadenas de texto
Emitir el `argv`, leerlo de vuelta y comparar strings.
**Ventajas:** trivial de implementar.
**Inconvenientes:** es exactamente lo que la normalización rompe.

### B — Canonizar el `argv` del renderer
Hacer que el renderer emita ya la forma que iptables devolvería: `-m tcp` explícito,
tipos ICMP numéricos, CIDR siempre, `--reject-with` explícito.
**Ventajas:** reduce el problema sin cambiar el modelo de comparación.
**Inconvenientes:** obliga a replicar dentro del renderer las reglas de reescritura de
iptables, que no están documentadas y cambian entre versiones. Es acoplarse a un detalle
no contractual: el día que `nf_tables` cambie una reescritura, el drift vuelve a mentir.

### C — Comparar estructuras
El parser devuelve `RuleSpec`; la base de datos produce `RuleSpec`; el drift es una
comparación entre conjuntos de `RuleSpec`.
**Ventajas:** inmune a cualquier reescritura de formato.
**Inconvenientes:** el parser deja de ser un lector de texto y pasa a ser la mitad de un
round-trip; tiene que entender los módulos de match que el renderer emite.

## Decisión

**Opción C.** El drift se calcula comparando `list[RuleSpec]` contra `list[RuleSpec]`.
`RuleSpec` es el único formato en el que dos reglas se comparan.

Para que eso funcione, `RuleSpec` se construye **canónica**: cada campo pasa por su
validador en `__post_init__` y se guarda normalizado — IPs siempre en CIDR, puertos como
cadena normalizada (`"22"`, `"30000:30010"`). Dos formas de escribir la misma regla son
el mismo objeto, con el mismo hash, así que el drift se calcula con operaciones de
conjuntos.

La identidad de la regla (`rule_uuid`) queda **fuera** de la comparación (`compare=False`):
no es parte de la semántica de la regla, y además el parser solo recupera 8 caracteres
del uuid desde el comentario. Incluirla haría que ninguna regla leída coincidiera jamás
con la de la base de datos, que es el mismo fallo por otra puerta.

## Consecuencias

**Positivas:** la detección de drift es inmune al formato. Aparece un test de contrato
nuevo y muy valioso, que solo puede correr dentro de la VM: *renderizar una spec,
aplicarla con iptables real, leerla de vuelta y comprobar que sale la misma spec*.

**Negativas:** el parser tiene que entender los módulos que el renderer emite
(`conntrack`, `multiport`, `comment`, `limit`, `icmp`) y decidir, línea a línea, si lo
que lee es representable. Las fixtures de A2 cubren los cinco. Y se cierra la puerta a
"aplicar solo lo que cambió": para saber qué cambió hay que parsear igual, y si ya has
parseado, reconstruir la cadena entera sale más barato que diferenciarla — lo que
refuerza el ADR-0002 en vez de contradecirlo.

**Qué invalidaría esta decisión:** que el proyecto pasara a usar `iptables-restore` con
un ruleset completo y atómico y aceptara no leer nunca el estado real. Mientras haya
detección de drift, la comparación tiene que ser estructural.
