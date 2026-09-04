# ADR-0018 — La política se reconcilia al arrancar

- **Fecha:** 2026-09-04
- **Estado:** Aceptado

## Contexto

Las reglas viven en SQLite, que es la fuente de verdad ([ADR-0001](0001-db-como-fuente-de-verdad.md)),
y llegan a iptables cuando alguien aplica. Un reinicio rompe esa correspondencia sin que
nadie haga nada mal: el kernel arranca sin las cadenas `FWDASH_*`, `ensure_scaffold()` las
crea **vacías** —montar no es poblar, invariante que destapó el contrato de B5— y las reglas
siguen guardadas pero no puestas.

El síntoma es exactamente el que este proyecto existe para evitar: el dashboard enseña
`applied` sobre una cadena vacía. La detección de drift lo acabaría diciendo, pero solo si
alguien mira; mientras tanto la máquina está sin la política que su operador cree tener.

Hasta aquí esto estaba anotado como `TODO(C2)` en `app/main.py` y como coste asumido en el
[ADR-0015](0015-la-aplicacion-arranca-aunque-el-firewall-no-responda.md).

## Opciones consideradas

### A — Que lo haga systemd
Un `ExecStartPost` que llame a `POST /firewall/apply` con `curl`. No toca código de la
aplicación. A cambio necesita credenciales dentro de la unidad para autenticarse, tiene que
esperar a que el puerto escuche, y deja la garantía fuera del programa: quien arranque la
app de otra forma (`uvicorn` a mano, un test, un contenedor) no la tiene.

### B — Reconciliar en el `lifespan`, solo si hay reglas guardadas
Aplicar al arrancar, pero saltárselo cuando la tabla `rules` está vacía. Ahorra tres
comandos en el caso más común.

### C — Reconciliar en el `lifespan`, siempre
El arranque llama a `apply_chains` sobre las tres cadenas, haya reglas o no.

## Decisión

**Opción C**, condicionada a `AUTO_APPLY`.

Frente a A: la garantía es de la aplicación, y por tanto vale en cualquier forma de
arrancarla y se puede probar sin VM ni systemd (`backend/tests/integration/test_arranque.py`).
Además no exige meter una contraseña en la unidad para que el servicio se llame a sí mismo.

Frente a B: **con la política vacía, lo que escribe `apply_chains` son las reglas guardián**.
Saltarse el apply por no haber reglas de usuario deja el puerto de gestión sin su guardián
hasta el primer apply, es decir, deja abierta exactamente la ventana que las reglas guardián
existen para cerrar. El caso "no hay nada que hacer" no es tal, y tratarlo como especial
introduce un estado del sistema que depende de una condición que no se ve.

`AUTO_APPLY=false` sí lo apaga, y es coherente: esa variable significa "no escribas en el
firewall por tu cuenta", y arrancar no es una excepción. Quien la apaga quiere un flujo de
staging, y un arranque que aplicara igual le quitaría la decisión en el peor momento
posible, un reinicio no planeado.

Un fallo de la reconciliación **no impide arrancar**: es el ADR-0015 extendido al apply. Las
reglas afectadas quedan en `failed` con su `last_error` y el fallo entra en la auditoría —eso
ya lo hacía `apply_chains`—; lo que decide este ADR es no propagarlo.

## Consecuencias

**Positivas:**

- Un reinicio de la VM restaura la política sin intervención. Es el paso C2 del plan.
- Los guardianes están puestos desde el arranque, antes de que exista la primera regla capaz
  de cerrar el puerto de gestión.
- El arranque deja el sistema en el estado que la detección de drift considera limpio, así
  que un `has_drift` recién arrancado significa algo de verdad.
- Con esto `/ready` ya puede decir la verdad, y en la misma sesión se le añadió el sondeo del
  firewall: hasta aquí devolvía `firewall: not_checked` y un 200 —"listo" sobre una
  aplicación incapaz de aplicar una regla—, que era el coste asumido en el ADR-0015 y la
  deuda nº 9. Ahora `not_mounted` y `error` degradan a 503.

**Negativas:**

- El arranque ahora **escribe** en iptables. Un servicio que reinicia en bucle reescribe las
  tres cadenas en cada intento; es idempotente, pero deja de ser cierto que arrancar sea una
  operación de solo lectura.
- Cambia el estado observable del arranque, y con él un test de A5 que afirmaba que las
  cadenas quedaban vacías (`test_el_lifespan_deja_el_firewall_listo`). La invariante que
  aquel test cuidaba —`ensure_scaffold` no puebla— sigue viva y probada en
  `tests/contract/`, que es donde le corresponde: es del backend, no de la aplicación.
- El `lifespan` necesita una sesión de base de datos fuera de una petición. Se le pasa la
  fábrica a `create_app` en vez de coger la global, para que los tests puedan apuntarla a su
  base en memoria; si se hubiera cogido la global, el arranque de los tests habría escrito en
  la base que dijera el `.env` de la máquina, que es la segunda trampa que se cazó en B5.

**Qué invalidaría esta decisión:** que aplicar dejase de ser barato o idempotente —por
ejemplo con miles de reglas, donde reconstruir tres cadenas en cada arranque se notaría—, o
que apareciera un caso legítimo de "arrancar sin tocar el firewall" distinto de
`AUTO_APPLY=false`.
