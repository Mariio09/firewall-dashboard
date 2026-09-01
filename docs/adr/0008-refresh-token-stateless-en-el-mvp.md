# ADR-0008: Refresh token stateless en el MVP

- **Fecha:** 2026-09-01
- **Estado:** Aceptado

## Contexto

El paso A4 emite un par de tokens: un access de 30 minutos y un refresh de 7 días. El
access no se revoca porque no hace falta: caduca antes de que dé tiempo a nada. El refresh
es otra cosa. Un token que vale una semana y que no se puede invalidar sigue funcionando
después de desactivar la cuenta, cambiar la contraseña o despedir a quien lo tenía.

El enum de `audit_events` incluye `auth.logout` desde A1, así que en algún momento del
diseño se dio por hecho que habría una sesión que cerrar.

## Opciones consideradas

### A — Tabla `refresh_tokens` con rotación y revocación
Un modelo con `jti`, `user_id`, `expires_at` y `revoked_at`; cada refresco invalida el
token entregado y emite uno nuevo; `/logout` marca el actual como revocado.
**Ventajas:** es lo correcto. Permite cerrar sesión de verdad, detectar la reutilización de
un refresh ya consumido (señal clásica de robo) y echar a alguien al instante.
**Inconvenientes:** un modelo, la migración 0002, un endpoint más y una tanda de tests, en
un paso cuyo entregable es "login funcional".

### B — Refresh stateless
Un JWT firmado con el claim `type: "refresh"`, sin ningún registro en la base de datos.
**Ventajas:** cero infraestructura; el paso A4 se cierra con lo que pide el plan.
**Inconvenientes:** no hay revocación posible antes de la caducidad.

### C — Solo access token
**Ventajas:** nada que revocar.
**Inconvenientes:** volver a introducir la contraseña cada 30 minutos, que es la clase de
fricción que termina con `ACCESS_TOKEN_EXPIRE_MINUTES=1440` en el `.env`.

## Decisión

**Opción B para el MVP.** El refresh es un JWT con `type: "refresh"` y no existe tabla de
tokens. `/logout` no se implementa: un logout que no invalida nada es teatro, y el frontend
puede borrar el token de su almacenamiento sin ayuda del backend.

Lo que sí se comprueba en cada refresco es el estado de la cuenta. `auth_service.refresh()`
relee el usuario de la base de datos y falla con 401 si está desactivado o ya no existe.
Eso da la mitad útil de una revocación —cortar la renovación— sin tabla ninguna: quien es
desactivado conserva, como mucho, 30 minutos de access token.

Lo mismo vale para el rol: cada petición autenticada relee al usuario en vez de fiarse del
claim `role` del token, así que degradar a alguien surte efecto en la siguiente petición y
no cuando le caduque el token.

## Consecuencias

**Positivas:** A4 cierra sin migración nueva y con el formato de token ya preparado para el
cambio — el `jti` viaja dentro aunque hoy no se consulte, así que añadir la tabla más
adelante no cambia lo que ven los clientes.

**Negativas:** un refresh robado es válido hasta que caduca. El riesgo se asume porque el
backend no sale de la red local y el MVP tiene un único usuario; en cuanto alguna de las dos
cosas deje de ser cierta, la revocación pasa a ser obligatoria. `auth.logout` se queda en el
enum de auditoría sin nadie que lo emita: es deuda declarada, no un descuido.

**Qué invalidaría esta decisión:** más de un usuario real, exponer el backend fuera de la
red local, o querer enseñar detección de reutilización de tokens como parte del portfolio
—que es, por cierto, la razón más probable de que esto acabe implementándose—.
