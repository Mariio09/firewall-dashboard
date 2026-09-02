# ADR-0011: Escribir la política y aplicarla son dos pasos con dos contratos

- **Fecha:** 2026-09-02
- **Estado:** Aceptado

## Contexto

Con `AUTO_APPLY=true` (el valor por defecto), `POST /rules` hace dos cosas:
escribe la fila y reconstruye la cadena. La pregunta es qué debe devolver cuando
la primera funciona y la segunda no — iptables no responde, faltan privilegios,
la cadena gestionada no existe.

No es un caso raro: es exactamente lo que va a pasar la primera vez que el
backend real arranque en la VM sin `CAP_NET_ADMIN` (ADR-0003).

## Opciones consideradas

### A — Propagar el fallo como 502

Lo que hace un endpoint honesto cuando algo falla. El cliente se entera del
problema del sistema, pero no se entera de que su regla sí se creó, y el
siguiente `GET /rules` desmiente la respuesta anterior.

### B — Deshacer la escritura y devolver 502

Petición y estado quedan atómicos. Convierte un fallo temporal del sistema en
pérdida del trabajo del usuario, y contradice ADR-0001: si la base de datos
manda, no puede depender de que iptables la autorice.

### C — Devolver 201 con el estado real de la regla

`sync_state = failed` y `last_error` puesto. El cliente recibe la verdad
completa: la regla existe y todavía no está en el firewall.

## Decisión

Opción C para las mutaciones de `/rules`. Opción A para `POST /firewall/apply`.

La diferencia no es de gusto, es de qué ha pedido el cliente. Quien llama a
`POST /rules` pide que la regla exista, y **existe**: la base de datos es la
fuente de verdad (ADR-0001), no iptables. Quien llama a `POST /firewall/apply`
pide una sola cosa —que se aplique— y esa sí ha fallado.

## Consecuencias

**Positivas:** `sync_state` deja de ser decorativo y se vuelve el contrato de
error de `/rules`. Era ya el corazón del modelo; ahora también es lo que el
frontend tiene que mirar después de un 201. Habilita el flujo de staging: con
`AUTO_APPLY=false` la regla se queda en `pending` y no hay nada excepcional en
ello, porque `pending` ya significaba eso.

**Negativas:** un cliente que ignore `sync_state` cree que todo fue bien. Se
mitiga porque la tabla del dashboard pinta la columna de estado desde el primer
día, y porque el error completo queda en el log y en `audit_events` con
`result = failure`. Y obliga a distinguir `pending` de `missing` en la detección
de drift: si no, crear una regla encendería el banner de drift.

**Qué invalidaría esta decisión:** que la aplicación dejara de tener una fuente
de verdad propia y pasara a leer la política de iptables. Entonces escribir sin
aplicar no significaría nada.
