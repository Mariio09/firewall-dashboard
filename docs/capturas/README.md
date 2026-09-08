# Capturas del README (paso C5)

Cuatro imágenes, y cada una tiene que demostrar algo que las otras no. Un README
con seis pantallazos del mismo formulario no enseña un sistema; estos cuatro sí,
porque juntos recorren las tres capas.

Se toman con el bloque C ya conmutado (`FIREWALL_BACKEND=iptables`, es decir
después de `make c-verify FASE=c0`) y con el frontend apuntando a la VM
(`make c-front`). Guarda los PNG **aquí**, con estos nombres exactos, y
descomenta el bloque de la sección *Capturas* del `README.md`.

| Archivo | Qué tiene que verse | Cómo llegar |
|---|---|---|
| `01-dashboard.png` | La tabla de reglas con al menos tres reglas, sus badges de `sync_state` en `applied`, y el badge de estado del firewall diciendo `iptables`. Es la foto de "esto es una herramienta, no un formulario" | `make dev-frontend`, entra como `admin` y crea tres reglas con nombres que se entiendan (`Bloquear escáner del 22`, no `prueba 3`) |
| `02-drift.png` | El banner de drift encendido y las filas afectadas en `drift` | con el dashboard abierto: `multipass exec firewall-lab -- sudo iptables -A FWDASH_INPUT -s 198.51.100.99/32 -j DROP` y recarga. Para limpiarlo, pulsa *aplicar* |
| `03-preview.png` | El diálogo de aplicar con los comandos exactos, guardianes incluidos | el botón de aplicar, antes de confirmar. Es la mitigación nº2 del auto-bloqueo, y se ve en una imagen |
| `04-iptables.png` | Una terminal con `sudo iptables -S FWDASH_INPUT` y, dentro, **la misma regla** de la captura 01 con su etiqueta `fwdash:<uuid8>` | `multipass exec firewall-lab -- sudo iptables -S FWDASH_INPUT`. Que el uuid corto coincida con el de la UI es el punto entero de la imagen |

## Antes de publicar

- Ninguna captura puede llevar un token, una contraseña ni el `.env`. La 03
  enseña el CIDR de gestión y el puerto: es topología de una red host-only de
  laboratorio, y es aceptable; cualquier otra cosa, no.
- Recorta la ventana, no la pantalla entera.
- Tema oscuro: es el único tema del frontend (ADR-0012). No hay modo claro que
  activar; la captura debe verse como la app se ve de verdad.
