# ADR-0004: Backend de firewall intercambiable (`fake` / `iptables`)

- **Fecha:** 2026-08-16
- **Estado:** Aceptado

## Contexto

El desarrollo ocurre en macOS (Apple Silicon), pero `iptables` solo existe en
Linux. Además, el plan de construcción acordado es explícito: primero la aplicación
completa (bloque A), después la capa de firewall real de forma aislada (bloque B) y
por último la interconexión (bloque C).

Eso exige que el backend funcione de punta a punta durante semanas sin que exista
todavía una implementación real de iptables.

## Opciones consideradas

### A — Desarrollar siempre dentro de la VM
**Ventajas:** un solo camino de código; lo que ves es lo que hay.
**Inconvenientes:** ciclo de iteración lento; los tests necesitan privilegios; el
CI no puede ejecutar nada; imposible cumplir la secuencia A→B→C.

### B — Mockear `subprocess` en los tests
**Ventajas:** no hay código de producción extra.
**Inconvenientes:** los mocks se esparcen por toda la suite; se acoplan a detalles
de implementación; no sirven para levantar la aplicación en desarrollo, solo para
tests.

### C — Un `Protocol` con dos implementaciones
`FirewallBackend` como interfaz, `FakeFirewallBackend` en memoria e
`IptablesBackend` real, seleccionadas por `settings.firewall_backend`.
**Ventajas:** la aplicación entera corre en el Mac; los tests no necesitan
privilegios; el CI ejecuta todo; la frontera queda explícita en el código.
**Inconvenientes:** el fake puede desviarse de la realidad.

## Decisión

**Opción C.**

El inconveniente del fake que miente es real y es el riesgo principal del plan de
construcción por bloques. Se neutraliza con dos medidas obligatorias:

1. **Diseñar contra salidas reales.** El paso A2 captura la salida literal de
   `iptables -S`, `iptables -L -v -n` y del error de cadena inexistente, y las
   guarda en `tests/fixtures/iptables_output/`. El parser y el renderer se escriben
   contra esas fixtures, no contra una idea de cómo debería ser el formato.
2. **Tests de contrato.** `tests/contract/` contiene una única suite parametrizada
   por backend. En el Mac se ejecuta solo con el fake; dentro de la VM, con ambos.
   Cualquier divergencia de comportamiento salta en el bloque B, cuando corregirla
   es barato, y no en el bloque C con un frontend ya construido encima.

Sin esas dos medidas esta decisión sería imprudente. Con ellas, el fake deja de ser
una suposición y pasa a ser una implementación verificada.

## Consecuencias

**Positivas:** el MVP completo es demostrable en el Mac, sin VM y sin privilegios —
suficiente para grabar la demo del portfolio. Los tests corren en cualquier sitio,
incluido GitHub Actions. El bloque C se reduce a cambiar una variable de entorno.
La costura documenta la arquitectura mejor que un diagrama.

**Negativas:** hay que mantener dos implementaciones sincronizadas. El fake es
código de producción que nunca se ejecuta en producción. Existe el riesgo, si se
descuidan los tests de contrato, de descubrir divergencias tarde.

**Qué invalidaría esta decisión:** que el fake resultara imposible de mantener
fiel — por ejemplo, si el proyecto empezara a depender de comportamientos del
kernel (conntrack, contadores en tiempo real) que un doble en memoria no puede
reproducir de forma honesta. En ese caso, sustituirlo por un contenedor Linux
ligero con iptables real.
