# ADR-0007: `NativeRule` lleva la spec parseada, no solo el texto

- **Fecha:** 2026-09-01
- **Estado:** Aceptado

## Contexto

El ADR-0006 decidió que el drift se calcula comparando `RuleSpec` contra `RuleSpec`.
Pero el contrato del backend declara `read_ruleset(chain) -> list[NativeRule]`, y
`NativeRule` era solo `raw`, `chain` y `counters`. Con eso no se puede comparar nada: la
decisión estaba tomada y no era implementable.

Había que cerrar el hueco al escribir el parser (paso A3), porque la forma del parser
depende de quién consume su salida.

## Opciones consideradas

### A — Que `read_ruleset` devuelva `list[RuleSpec]`
`NativeRule` desaparece.
**Ventajas:** un tipo menos y un contrato más directo.
**Inconvenientes:** se pierde la línea original, y no hay dónde poner lo que **no** se
puede expresar como spec: las reglas guardián, las de cierre de cadena y las ajenas.
Habría que descartarlas — justo lo que no se puede hacer cuando lo que se busca es
precisamente divergencia.

### B — Aplazarlo a la detección de drift
**Ventajas:** menos decisiones ahora.
**Inconvenientes:** el parser quedaría diseñado sin su consumidor, y el test de contrato
que cierra el ADR-0006 no se podría ni escribir.

### C — Enriquecer `NativeRule`
Que cada regla leída lleve la spec equivalente cuando la hay, y el motivo cuando no.

## Decisión

**Opción C.** `NativeRule` pasa a ser `raw`, `chain`, `target`, `comment`, `rule_uuid`,
`log_prefix`, `counters`, `spec: RuleSpec | None` y `unsupported: tuple[str, ...]`.

El parser rellena `spec` cuando la regla cae dentro del subconjunto que la aplicación
sabe expresar. Cuando no cae, `spec` es `None` y `unsupported` dice por qué.

Hay tres razones distintas para que no haya spec, y las tres importan:

1. **Reglas guardián**, que el renderer emite pero no salen de la base de datos. Se
   reconocen por su etiqueta (`fwdash:guardian:*`), no por heurísticas sobre el texto.
2. **Reglas de cierre de cadena** y saltos a otras cadenas (`-j FWDASH_INPUT`).
3. **Reglas ajenas o más expresivas que el modelo**: `multiport`, `limit`, negaciones,
   tipos ICMP. Que aparezcan dentro de una cadena gestionada **es** drift, y por eso se
   conservan en vez de descartarse en silencio.

## Consecuencias

**Positivas:** el detector de drift puede distinguir "esto no coincide" de "esto no sé
leerlo", que son dos incidencias distintas y ameritan mensajes distintos. `raw` se
conserva siempre, así que la UI y el log pueden enseñar la línea real al explicar una
divergencia: un drift que dice "hay algo que no reconozco" sin enseñar qué es inútil.

**Negativas:** el parser tiene que decidir, línea a línea, si lo que lee es traducible, y
eso son más casos que leer texto. Dos de ellos son puro conocimiento de iptables y no se
habrían adivinado sin las fixtures: que `-j REJECT` vuelve con un `--reject-with
icmp-port-unreachable` que nadie pidió (tratarlo como un match más convertiría cada
REJECT aplicado en drift permanente), y que una regla con log son dos líneas con la misma
etiqueta que hay que volver a juntar al leerlas.

**Qué invalidaría esta decisión:** que el modelo de reglas creciera hasta expresar todo
lo que expresa iptables. Entonces `spec` nunca sería `None` por falta de expresividad y
el campo `unsupported` se quedaría solo con los guardianes — momento de volver a mirar
si `NativeRule` sigue mereciendo existir.
