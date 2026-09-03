# ADR-0013 — El código entra en la VM clonado, no montado

## Contexto

Hasta aquí, el código fuente vivía en el Mac y se **montaba** en
la VM con `multipass mount`, para editar con el editor de siempre y que el
proceso corra en la VM sobre los mismos archivos, sin `rsync` ni redespliegues.

En B0 eso dejó de funcionar. El repo está en `~/Downloads/firewall-dashboard`,
que macOS protege con **TCC**, y `multipassd` corre como demonio de sistema sin
permiso para leerla. El síntoma es traicionero: `multipass mount` **devuelve 0**
—el montaje se registra— y dentro de la VM el directorio sale vacío
(`ls` da `total 0`) y leer un archivo da `Operation not permitted`.

Comprobado con un montaje de control en una carpeta no protegida, que sí lee. No es un fallo de
multipass ni del sshfs: es un permiso.

## Opciones

1. **Mover el repo a `~/dev/`.** Sale del ámbito de TCC y no depende de ningún
   permiso concedido a mano. Rompe el venv: los scripts de `backend/.venv/bin/`
   llevan la ruta absoluta en el shebang y el hook de git su `INSTALL_PYTHON`.
2. **Acceso total al disco a `multipassd`.** Nada se mueve. A cambio, un permiso
   manual por máquina, que las actualizaciones de macOS pueden resetear, y darle
   a un demonio de fondo acceso al disco entero.
3. **Clonar el repo dentro de la VM.** Ni permisos ni mudanza. Se pierde la
   edición en vivo: al otro lado hay una copia, no los mismos archivos.

## Decisión

**Opción 3.** El código entra en la VM **clonado desde un `git bundle`**
transferido con `multipass transfer`, no montado.

El bundle es lo que hace la opción viable: el repo remoto es **privado**, así
que un `git clone` desde GitHub exigiría credenciales dentro de una VM que
existe para que te bloquees a propósito (`B4 - Provocar el auto-bloqueo`). Con
un bundle no hay secretos en la VM, ni hace falta que la VM tenga red.

```bash
make vm-clone   # primera vez
make vm-sync    # cada vez que quieras llevar cambios
```

`multipass mount` sigue en el `Makefile` como alternativa, para quien tenga el
repo en una carpeta que `multipassd` sí pueda leer.

## Consecuencias

- **Habilita** cerrar B0 sin tocar permisos del sistema ni reorganizar el
  entorno de desarrollo, y sin meter credenciales del repo privado en la VM.
- **Cierra** la edición en vivo. Dentro de la VM hay una copia: editar un
  archivo en el Mac ya no basta.
- **Coste asumido**: solo viaja lo **commiteado**. Probar algo en la VM obliga a
  commitear antes. En el bloque B, donde cada paso toca `iptables` de verdad,
  eso es disciplina más que estorbo; en un ciclo de iteración rápida, molesta.
- **Riesgo**: que la VM se quede en un commit viejo sin que nadie lo note, y se
  depure código que no es el que corre. **Mitigación**: `b0_verify.sh` compara
  `git rev-parse HEAD` a los dos lados y avisa si el árbol del Mac tiene cambios
  sin commitear. Es la misma lección de A5 y A6: lo que no se puede demostrar,
  miente en verde.
- Obligó a añadir **`git` a `packages`** en `infra/cloud-init.yaml`: la imagen
  cloud de Ubuntu no lo trae.

**Sustituye** la decisión anterior de montar el repo con `multipass mount`
(ver `docs/ARCHITECTURE.md`).
