# ADR-0015 — La aplicación arranca aunque el firewall no responda

- **Fecha:** 2026-09-04
- **Estado:** Aceptado

## Contexto

Hasta B3, el `lifespan` capturaba `NotImplementedError` porque `IptablesBackend` no
existía: era un caso de "aún no implementado", no un caso real. Con B3 el backend ya
funciona, y el `ensure_scaffold()` del arranque pasa a poder fallar **de verdad**, por
motivos que van a ocurrir:

- el servicio sin `CAP_NET_ADMIN` porque la unidad de systemd se editó mal
  ([ADR-0003](0003-privilegios-sudo-vs-capabilities.md));
- un `IPTABLES_BIN` que apunta a algo que no existe;
- iptables devolviendo error por cualquier otra razón del sistema.

Hay que decidir qué hace la aplicación cuando eso ocurre, y la respuesta no es obvia: es un
dashboard **de firewall**, así que se puede defender que sin firewall no tiene sentido.

## Opciones

1. **Morir en el arranque.** Coherente con "un firewall que no filtra es peor que ninguno",
   y hace el fallo imposible de ignorar.
2. **Arrancar degradada.** Se registra el fallo, `app.state.firewall` se queda sin poner, y
   la primera petición a `/firewall/*` reintenta la construcción y devuelve el error tipado
   al cliente.

## Decisión

**Opción 2.** El `lifespan` captura `AppError` —la raíz de `FirewallError`, `SecurityError`
e `InvalidRuleError`— y deja que la aplicación arranque.

## Consecuencias

- `/health` y `/auth` siguen respondiendo, que es lo que hace falta para diagnosticar. Un
  dashboard que se niega a arrancar justo cuando el firewall falla no sirve para averiguar
  *por qué* falla.
- Evita un bucle de reinicios en systemd, donde la única traza sería el journal. Con la
  opción 1 el síntoma visible es "la web no carga", que no apunta a nada.
- El error no se pierde: sale en el log de arranque con su `code`, y vuelve a salir —con su
  status HTTP y su `details`— en cuanto alguien pide `/firewall/*`, porque
  `deps.get_firewall_backend()` reconstruye el backend cuando `app.state.firewall` está
  vacío.
- **Coste asumido:** durante ese rato la política de la base de datos no está aplicada y
  nadie lo dice desde fuera. `/ready` sigue devolviendo 200 aunque el firewall no esté
  listo, lo que es incoherente con su nombre. Queda anotado para C2, que es cuando el
  arranque además tendrá que reconciliar la política guardada.
- No cambia nada con `FIREWALL_BACKEND=fake`: ese backend no puede fallar al montarse.

Verificado en `backend/tests/integration/test_firewall_compartido.py`
(`test_la_aplicacion_arranca_aunque_el_firewall_no_responda`).
