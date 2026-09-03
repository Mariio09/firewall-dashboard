# Modelo de seguridad

> Este documento es tan parte del proyecto como el código. Un dashboard que
> ejecuta `iptables` con privilegios de root es, por definición, una superficie de
> ataque: lo que distingue un proyecto serio de un script peligroso es haber
> pensado dónde están los límites y ser honesto sobre los que no se cubren.

---

## 1. Qué se está protegiendo

| Activo | Por qué importa |
|---|---|
| La política de firewall de la VM | Es el control de acceso a la máquina entera |
| La ejecución de comandos como root | `iptables` requiere `CAP_NET_ADMIN`; abusarlo es RCE con privilegios |
| Credenciales de usuarios | Hashes en la base de datos, tokens JWT en tránsito |
| Topología de la red | Las reglas revelan qué hay detrás del firewall |

## 2. Contra quién

1. **Atacante en la red local.** Alcanza el puerto de la API. Es el modelo
   principal: el backend no se expone a internet, pero "red local" incluye
   cualquier dispositivo comprometido de la LAN.
2. **Usuario autenticado con rol bajo.** Un `viewer` que intenta modificar reglas.
3. **Entrada maliciosa vía formulario.** El vector clásico: una "IP" que en
   realidad es `1.2.3.4; rm -rf /`.
4. **Fuera de alcance:** atacante con acceso físico a la VM, o con root ya
   obtenido. Si ya es root, este proyecto es irrelevante.

---

## 3. Inyección de comandos — la amenaza principal

Toda la aplicación existe para traducir entrada de usuario en comandos de sistema.
Es exactamente el escenario donde nace la inyección de comandos.

**Cinco capas, ninguna suficiente por sí sola:**

1. **Sin shell, nunca.** Todos los comandos se ejecutan con
   `subprocess.run(argv, shell=False)` y argumentos en lista. Sin shell, `;`, `|`,
   `$()`, backticks y comillas dejan de tener significado: pasan al binario como
   texto literal. Esto no *mitiga* la inyección de shell, la **elimina por
   construcción**.
2. **Un único punto de ejecución.** `subprocess` solo se importa en
   `app/firewall/runner.py`. Auditar ese archivo audita el proyecto entero.
   `tests/unit/test_architecture.py` falla en CI si alguien lo importa en otro
   sitio, así que la regla no depende de la disciplina de nadie.
3. **Allowlist de binarios.** Un argv cuyo ejecutable no esté en
   `ALLOWED_BINARIES` lanza `SecurityError` antes de tocar el sistema.
4. **Validación tipada en la frontera.** `RuleSpec` es inmutable y se valida al
   construirse: no existe una ruta de código capaz de fabricar una spec inválida.
   Las IPs pasan por `ipaddress`, los puertos se comprueban en rango, las
   interfaces contra una expresión regular estricta.
5. **Normalización.** Los valores se guardan canonizados (`1.2.3.4` → `1.2.3.4/32`),
   lo que además hace que la comparación de drift sea fiable.

**Además:** `shell=True` está prohibido en todo el repositorio, y hay un test que
lo verifica leyendo los archivos.

**La allowlist cubre también la configuración.** El nombre lógico (`iptables`) lo
pone el renderer, pero la ruta real sale de `IPTABLES_BIN`: un `.env` que apuntara
a otro ejecutable dejaría la allowlist en decoración. El constructor de
`SubprocessRunner` exige ruta absoluta y que el nombre del archivo esté en
`ALLOWED_BINARIES`, y el resto de binarios se resuelven como hermanos suyos en el
mismo directorio, nunca por PATH.

**Entorno mínimo y timeout.** El proceso hijo recibe solo `PATH` y `LC_ALL=C`: no
hereda nada del padre, así que no hay secuestro por variable de entorno ni salida
dependiente del locale. Todo comando lleva timeout, porque un `iptables` esperando
el lock de xtables bloquearía el worker indefinidamente.

**Cómo se verifica.** Los tests del runner no usan un mock de `subprocess.run`:
apuntan a un `iptables` falso que registra su argv y su entorno, así que
`shell=False` y el entorno mínimo se comprueban mirando lo que el hijo vio de
verdad. Un `--comment "; touch PWNED"` llega literal y no crea el archivo.
`make b2-verify` repite esa prueba fuera de pytest.

---

## 4. Privilegios: la parte incómoda

El backend necesita modificar reglas de red. Hay dos formas de dárselo y no son
equivalentes.

### Opción A — sudoers restringido

```
Cmnd_Alias FWDASH_CMDS = /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore
fwdash ALL=(root) NOPASSWD: FWDASH_CMDS
```

**Sé honesto sobre lo que esto es.** `NOPASSWD` sobre `iptables` completo es, en la
práctica, equivalente a root:

- `iptables-restore` reescribe la política entera desde stdin.
- Targets como `NFQUEUE` o `TEE` redirigen tráfico a procesos arbitrarios.
- No hay forma de restringir *qué* reglas se pueden crear, solo *qué binario* se
  invoca.

No es un privilegio acotado. Es un privilegio **nombrado**. La contención real no
está aquí, está en las cinco capas de la sección 3.

### Opción B — capabilities (recomendada)

Sin sudo. Se le da al proceso exactamente la capacidad que necesita:

```ini
[Service]
User=fwdash
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/firewall-dashboard
```

`CAP_NET_ADMIN` es precisamente el permiso que `iptables` requiere, sin conceder
nada más. `NoNewPrivileges=yes` impide escalar. `ProtectSystem=strict` deja el
sistema de archivos en solo lectura salvo el directorio de datos.


> ⚠️ **Este fragmento es del diseño, no la unidad real.** Al aplicarlo en B1 se vio
> que no arrancaba: `ProtectHome=yes` oculta `/home`, donde estaban el `ExecStart`
> y el `.env`. El despliegue se movió a `/opt` ([ADR-0014](adr/0014-el-despliegue-vive-en-opt.md))
> y `ReadWritePaths` pasó a `StateDirectory`. Además, **A y B no se combinan**:
> `NoNewPrivileges=yes` anula el setuid de `sudo`, así que con el servicio va
> `USE_SUDO=false`. La unidad que se instala de verdad es
> `infra/systemd/firewall-dashboard.service`; el porqué, en la corrección del
> [ADR-0003](adr/0003-privilegios-sudo-vs-capabilities.md).

**El proyecto soporta ambas** (`USE_SUDO` en `.env`) y documenta A como atajo de
desarrollo y B como el modo correcto. El razonamiento completo está en
`docs/adr/0003-privilegios-sudo-vs-capabilities.md`.

---

## 5. Autenticación y autorización

- Contraseñas con **Argon2id** (`argon2-cffi`), no bcrypt: es el ganador del
  Password Hashing Competition y resiste mejor el crackeo con GPU.
- **JWT** de vida corta (30 min) + refresh token. El secreto se genera con
  `openssl rand -hex 32` y jamás se versiona.
- **RBAC de tres roles**: `viewer` (solo lectura), `operator` (gestiona reglas),
  `admin` (además gestiona usuarios). Se comprueba en las dependencias de FastAPI,
  no dentro de cada endpoint.
- **Auditoría**: toda mutación de la política queda en `audit_events` con usuario,
  timestamp, estado anterior y posterior, y resultado. También los intentos de
  login fallidos.

## 6. Exposición de red

- El backend hace bind a la interfaz de Multipass (`192.168.64.0/24`), que es
  host-only: no está expuesta a la LAN ni a internet.
- CORS restringido al origen del frontend, sin comodines.
- Alternativa más estricta: bind a `127.0.0.1` y túnel
  `ssh -L 8000:localhost:8000`.

## 7. Protección contra el auto-bloqueo

Gestionar un firewall *a través de la red que ese firewall filtra* significa que un
error de configuración corta el acceso a la herramienta que lo arreglaría.

1. **Reglas guardián** en cabecera de cada cadena gestionada, inyectadas por el
   renderer, ausentes de la base de datos, imposibles de desactivar por API. El
   caso más traicionero es `OUTPUT`: sin `ACCEPT` de `ESTABLISHED,RELATED` en
   salida, se cortan las **respuestas** de la propia API — la petición entra pero
   nunca vuelve, y parece un timeout genérico.
2. **Dry-run** (`GET /firewall/preview`) devuelve los comandos exactos sin
   ejecutarlos.
3. **Vía de escape fuera de banda**: `multipass shell firewall-lab` no usa TCP, así
   que sigue funcionando aunque se cierre la red entera. Ver `docs/RUNBOOK.md`.
4. **Fase 2**: apply con rollback automático si no llega confirmación en N
   segundos (patrón `iptables-apply`).

## 8. Cadena de suministro

`pip-audit` y `gitleaks` en pre-commit y en CI; `bandit` sobre `app/`; Dependabot
para actualizaciones.

---

## 9. Limitaciones conocidas

Admitir lo que un sistema *no* protege da más credibilidad que fingir que es un
producto terminado.

- **`sudo iptables` sin contraseña es equivalente a root** si se elige la opción A.
  La opción B lo reduce, no lo elimina.
- **Sin rate limiting en el login** en el MVP. Un atacante en la LAN puede hacer
  fuerza bruta contra `/auth/login`. Previsto para la fase 2 junto con la detección
  de patrones.
- **Sin HTTPS.** El tráfico entre el Mac y la VM va en claro por una red host-only.
  Aceptable en un laboratorio, inaceptable en cualquier otro sitio.
- **Sin protección CSRF explícita**: se mitiga usando `Authorization: Bearer` en
  lugar de cookies, pero no está auditado.
- **El token JWT se guarda en memoria del frontend**, de modo que se pierde al
  refrescar. Es la opción segura frente a `localStorage`, pero degrada la
  experiencia.
- **Sin multi-tenancy.** Un `admin` gestiona el firewall entero.
- **El drift se detecta, no se previene.** Alguien con acceso a la VM puede
  modificar `iptables` a mano; la aplicación lo señalará en el siguiente sondeo,
  pero no lo impide.

---

## 10. Reportar un problema

Es un proyecto de laboratorio, no un producto en producción. Si encuentras un
fallo de seguridad, abre un issue — no hay datos reales de terceros en riesgo.
