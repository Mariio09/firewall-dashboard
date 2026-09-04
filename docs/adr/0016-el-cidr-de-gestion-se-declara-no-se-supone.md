# ADR-0016 — El CIDR de gestión se declara, no se supone

- **Fecha:** 2026-09-04
- **Estado:** Aceptado

## Contexto

`MANAGEMENT_ALLOWED_CIDR` alimenta la regla guardián que abre el puerto de la API
(`docs/ARCHITECTURE.md` §0). Hasta B4 tenía valor por defecto en `app/core/config.py`:

```python
management_allowed_cidr: IPvAnyNetwork = Field(default="192.168.64.0/24")
```

`192.168.64.0/24` es el rango **habitual** del bridge de Multipass en macOS, no uno
garantizado: cambia si el bridge se recrea, si hay conflicto con otra red, o entre versiones
y máquinas. En el Mac donde se desarrolla esto la red real es `192.168.252.0/24`, así que el
default es **falso**.

Con un default falso, el guardián abre el puerto de gestión a una subred donde no está
nadie: la regla escrita para evitar el auto-bloqueo es exactamente la que lo provoca, y lo
hace al aplicar la primera política real.

Lo que hace este fallo peligroso es su forma: **la aplicación arranca, los tests pasan y el
`.env` parece correcto**. Un CIDR válido no es un CIDR verdadero, y ningún validador de
tipos distingue una cosa de la otra.

## Opciones

1. **Dejar el default y documentarlo.** Cero fricción; el riesgo se traslada a que alguien
   lea la documentación en el momento justo.
2. **Corregir el default al valor de este Mac.** Cambia un valor falso por otro que también
   caducará.
3. **Quitar el default y exigirlo cuando las reglas son reales.** Igual que
   `JWT_SECRET_KEY`: si falta, la aplicación no arranca y dice cómo consultarlo.

## Decisión

**Opción 3.** El campo pasa a `IPvAnyNetwork | None = None` y un `model_validator` lo exige
cuando `is_strict_environment` **o** `firewall_backend == "iptables"`.

La condición no es solo el entorno, y ese matiz es la decisión de verdad: lo que hace
peligroso el hueco no es llamarse `vm`, es que las reglas lleguen a iptables. `dev` con el
backend real escribe reglas reales, así que entra también.

Con `fake` se rellena con `127.0.0.0/8` —una red de laboratorio evidentemente inútil como red
de gestión— y se avisa con un `RuntimeWarning`. Un valor que no engaña a nadie es mejor que
uno plausible.

## Consecuencias

- Un despliegue sin el dato **no arranca**, en vez de arrancar con un guardián que apunta a
  la nada. El error dice cómo obtenerlo: `ip -4 -o addr show scope global`.
- No afecta a la VM: `infra/scripts/deploy_vm.sh` ya derivaba el CIDR de la interfaz real, y
  por eso B1 y B3 nunca vieron el problema.
- Rompe cualquier `.env` de desarrollo que use el backend real sin declararlo. Es el
  objetivo, no un efecto secundario.
- **Coste asumido:** una variable obligatoria más en el arranque, y el fixture de tests
  (`backend/tests/conftest.py`) y el arnés de B3 tienen que declararla.

Verificado en `backend/tests/unit/test_config.py`: cuatro casos de rechazo (vm/prod/dev con
`iptables`, y `vm` con `fake`), la contraprueba de que con `fake` sí arranca, y un test de
regresión que comprueba que el literal `192.168.64.0/24` ya no está en el campo.

Relacionado: [ADR-0003](0003-privilegios-sudo-vs-capabilities.md) ·
[ADR-0014](0014-el-despliegue-vive-en-opt.md) · `docs/RUNBOOK.md`
