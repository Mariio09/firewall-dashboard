# ADR-0012: El frontend no lleva librería de UI

- **Fecha:** 2026-09-02
- **Estado:** Aceptado

## Contexto

A6 monta la interfaz: login, tabla de reglas, formulario, badge de estado, banner
de drift y un diálogo de preview. Es el momento en que un proyecto de React
decide con qué se pinta, y esa elección no se revierte barato: arrastra un
toolchain, un vocabulario de clases o de componentes, y a veces una plantilla
entera.

Restricciones previas: coste 0 € sin tarjeta, y que esto es un proyecto de
portfolio — lo va a leer alguien que juzga criterio, no volumen.

## Opciones consideradas

### A — Tailwind

Rápido de iterar. Añade PostCSS, su configuración y su build, y mete el diseño
dentro del JSX en forma de cadenas de clases.

### B — Librería de componentes (shadcn/ui, Radix, MUI)

El resultado se ve profesional sin esfuerzo, a cambio de muchas dependencias y de
que la interfaz deje de decir nada sobre quien la escribió.

### C — CSS propio

Un archivo, tema oscuro, variables de color en `:root`.

## Decisión

Opción C: `frontend/src/styles.css`, con tokens en `:root` y clases por bloque.

El argumento no es purismo, es proporción. La superficie visual de este MVP son
una tabla, tres badges, dos diálogos y un formulario. Mantener un toolchain de
CSS para eso cuesta más que escribirlo, y una librería de componentes resolvería
un problema que aquí no existe: el de un equipo grande que necesita consistencia
sin coordinarse.

Hay además una razón de portfolio, y conviene decirla en voz alta: en un proyecto
cuyo valor es el criterio, una plantilla de terceros borra justo la parte que se
está enseñando.

## Consecuencias

**Positivas:** cero dependencias nuevas en A6 — el `npm install` sigue siendo el
de A0 y `npm audit` tiene la misma superficie. El tema se cambia entero editando
las variables de `:root`.

**Negativas:** cada componente nuevo trae su CSS, y no hay red de seguridad de
accesibilidad ni de foco atrapado; el `<Modal>` hace lo justo (Escape y clic
fuera). El día que haga falta un combobox, un date picker de verdad o un menú
anidado, escribirlos a mano será peor idea que traerse Radix solo para eso.

**Qué invalidaría esta decisión:** la fase 3, que trae gráficas por IP, puerto y
tiempo. Una librería de gráficas **no** contradice este ADR: lo que se decide
aquí es no traer un sistema de UI, no renunciar a una dependencia concreta que
resuelva un problema concreto.
