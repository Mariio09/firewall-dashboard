# firewall-dashboard — Arquitectura

> Documento de diseño previo a la implementación. Nada de esto está escrito aún en
> código: es la propuesta para que la validemos antes de generar el scaffolding.

**Decisiones ya confirmadas**

| Punto | Decisión |
|---|---|
| Fuente de verdad de las reglas | SQLite (la DB manda, iptables la refleja) |
| Persistencia | SQLAlchemy 2.0 + SQLite + Alembic desde el día 1 |
| Frontend | Vite + React + TypeScript |
| Auth | JWT con usuarios en DB |
| Secuencia de construcción | A) app completa → B) firewall aislado → C) interconexión (§8) |
| Cadenas gestionadas | `INPUT` + `OUTPUT` + `FORWARD`, cada una con su cadena `FWDASH_*` |
| IPv6 | Columna `ip_version` en el modelo; solo v4 implementado en el MVP |

---

## 0. La decisión que condiciona todo lo demás

Antes del árbol de carpetas hay que fijar *cómo* se lleva la DB a iptables, porque
de eso depende la mitad del diseño.

**Propuesta: cadena propia + reconstrucción idempotente.**

El backend **nunca** escribe directamente en las cadenas del sistema. En el arranque
crea sus propias cadenas y un único salto hacia cada una:

```
iptables -N FWDASH_INPUT                  # cadenas gestionadas por la app
iptables -N FWDASH_OUTPUT
iptables -N FWDASH_FORWARD
iptables -I INPUT   1 -j FWDASH_INPUT     # únicos puntos de contacto con el sistema
iptables -I OUTPUT  1 -j FWDASH_OUTPUT
iptables -I FORWARD 1 -j FWDASH_FORWARD
```

A partir de ahí, "aplicar" significa siempre lo mismo: vaciar la cadena gestionada y
reconstruirla entera desde la DB, en orden. Una sola operación, siempre igual, tanto si
añades una regla como si borras diez. La reconciliación itera sobre las tres cadenas de
forma independiente: cada una es un `apply_ruleset` separado.

Por qué esto y no `iptables -I INPUT ...` regla a regla:

- **Idempotencia.** El estado final solo depende de la DB. No hay forma de acumular
  reglas duplicadas ni de que un fallo a medias deje la cadena inconsistente.
- **Aislamiento.** Nunca tocas reglas que no son tuyas (Docker, ufw, lo que sea que
  haya en la VM). Si desinstalas el proyecto, borras el salto y la cadena y no queda
  rastro.
- **Orden explícito.** En iptables el orden es semántica pura: la primera regla que
  hace match gana. Reconstruir entero te permite tratar el orden como un campo
  (`position`) que el usuario reordena en la UI, en vez de pelear con índices de
  inserción.
- **Detección de *drift* trivial.** Comparas `iptables -S FWDASH_INPUT` contra lo que
  dice la DB. Si alguien tocó iptables a mano, lo ves.
- **Escala a las fases siguientes.** La fase 2 (logging) necesita insertar reglas con
  target `LOG` *antes* de cada `DROP`. Con reconstrucción completa eso es un
  `if rule.log_enabled: emitir dos reglas`. Con inserción incremental es un infierno
  de índices.

Consecuencia de diseño: el adaptador de iptables expone **una** operación de
escritura, `apply_ruleset(chain, rules)`, no un `add_rule`/`delete_rule`. Toda la
lógica de "qué reglas hay" vive en la DB y en los servicios.

### El problema del auto-bloqueo (léelo antes de aplicar nada)

Gestionas un firewall *a través de la red que ese firewall filtra*. Un `DROP` mal
puesto en `INPUT` te deja fuera de la VM y de la propia API. Tres mitigaciones que
propongo integrar en la arquitectura desde el principio, no como parche:

1. **Reglas guardián no borrables.** La app emite siempre, como primeras líneas de cada
   cadena gestionada, un bloque fijo que no está en la DB de reglas de usuario: lo
   inyecta el propio renderizador y no se puede desactivar por API.

   | Cadena | Guardianes emitidos siempre en cabecera |
   |---|---|
   | `FWDASH_INPUT` | `ACCEPT` de `ESTABLISHED,RELATED`; `ACCEPT` en `lo`; `ACCEPT` al puerto de gestión desde `MANAGEMENT_ALLOWED_CIDR` |
   | `FWDASH_OUTPUT` | `ACCEPT` de `ESTABLISHED,RELATED`; `ACCEPT` en `lo`; `ACCEPT` desde el puerto de gestión hacia `MANAGEMENT_ALLOWED_CIDR` |
   | `FWDASH_FORWARD` | `ACCEPT` de `ESTABLISHED,RELATED` |

   Los guardianes de `OUTPUT` importan más de lo que parece: sin el `ESTABLISHED,RELATED`
   de salida, una regla de usuario que filtre tráfico saliente corta las **respuestas** de
   la propia API y te quedas sin dashboard aunque la petición sí haya entrado. Es el modo
   de auto-bloqueo más confuso de diagnosticar, porque desde fuera parece un timeout.
2. **Dry-run.** `GET /firewall/preview` devuelve los comandos exactos que se
   ejecutarían, sin ejecutarlos. Es un endpoint, no un modo escondido.
3. **Apply con confirmación (fase 2).** Se aplica el ruleset, se guarda el anterior,
   y si no llega un `POST /firewall/confirm` en N segundos, se hace rollback
   automático. Es el patrón de `iptables-apply`. Es también, francamente, la
   funcionalidad que más va a llamar la atención en una entrevista.

---

## 1. Estructura de carpetas

```
firewall-dashboard/
├── README.md
├── LICENSE
├── .gitignore
├── .env.example                    # plantilla, sí se versiona
├── Makefile                        # atajos: make dev, make test, make vm-deploy
│
├── docs/
│   ├── ARCHITECTURE.md             # este documento
│   ├── SECURITY.md                 # modelo de amenazas y decisiones de seguridad
│   ├── RUNBOOK.md                  # qué hacer si te bloqueas a ti mismo
│   ├── SETUP_VM.md                 # Multipass paso a paso
│   ├── API.md                      # o simplemente enlace a /docs de FastAPI
│   └── adr/                        # Architecture Decision Records
│       ├── 0001-db-como-fuente-de-verdad.md
│       ├── 0002-cadena-propia-fwdash.md
│       ├── 0003-privilegios-sudo-vs-capabilities.md
│       └── TEMPLATE.md
│
├── infra/
│   ├── cloud-init.yaml             # provisión de la VM (sin secretos)
│   ├── sudoers.d/firewall-dashboard # plantilla, ver §4.3
│   ├── systemd/firewall-dashboard.service
│   └── scripts/
│       ├── bootstrap_vm.sh
│       └── panic_reset.sh          # limpia FWDASH_* y devuelve INPUT a ACCEPT
│
├── backend/
│   ├── pyproject.toml              # deps + config de ruff/mypy/pytest
│   ├── alembic.ini
│   ├── alembic/
│   │   ├── env.py
│   │   └── versions/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                 # create_app(): monta routers, middlewares, handlers
│   │   │
│   │   ├── core/                   # cosas transversales, sin lógica de negocio
│   │   │   ├── config.py           # Pydantic Settings (§4)
│   │   │   ├── logging.py          # configuración de structlog
│   │   │   ├── security.py         # hash de passwords, encode/decode JWT
│   │   │   └── exceptions.py       # jerarquía AppError (§5.2)
│   │   │
│   │   ├── db/
│   │   │   ├── base.py             # DeclarativeBase + import de todos los modelos
│   │   │   ├── session.py          # engine, sessionmaker, get_session()
│   │   │   └── seed.py             # usuario admin inicial desde .env
│   │   │
│   │   ├── models/                 # SQLAlchemy — cómo se guarda
│   │   │   ├── rule.py
│   │   │   ├── packet_log.py
│   │   │   ├── alert.py
│   │   │   ├── user.py
│   │   │   └── audit_event.py
│   │   │
│   │   ├── schemas/                # Pydantic — el contrato HTTP
│   │   │   ├── rule.py             # RuleCreate / RuleUpdate / RuleRead
│   │   │   ├── auth.py
│   │   │   ├── firewall.py         # FirewallStatus, ApplyPreview
│   │   │   ├── log.py
│   │   │   └── common.py           # Page[T], ErrorResponse
│   │   │
│   │   ├── services/               # lógica de negocio; orquesta models + firewall
│   │   │   ├── rule_service.py     # CRUD + reordenación + validación de negocio
│   │   │   ├── firewall_service.py # reconciliación DB → iptables, drift, preview
│   │   │   ├── auth_service.py
│   │   │   ├── audit_service.py
│   │   │   ├── log_service.py      # fase 2 (stub)
│   │   │   └── detection_service.py# fase 4 (stub)
│   │   │
│   │   ├── firewall/               # ⚠️ ÚNICO lugar del repo que ejecuta subprocess
│   │   │   ├── spec.py             # RuleSpec: el tipo frontera, inmutable y validado
│   │   │   ├── validators.py       # IP/CIDR/puerto/protocolo/interfaz — centralizado
│   │   │   ├── base.py             # FirewallBackend (Protocol)
│   │   │   ├── renderer.py         # RuleSpec[] → list[list[str]] (argv, no strings)
│   │   │   ├── parser.py           # salida de iptables -S / -L -v -n → estructuras
│   │   │   ├── runner.py           # CommandRunner: subprocess con allowlist y timeout
│   │   │   ├── iptables.py         # IptablesBackend (implementación real)
│   │   │   └── fake.py             # InMemoryBackend (tests + desarrollo en Mac)
│   │   │
│   │   ├── api/
│   │   │   ├── deps.py             # get_db, get_current_user, get_firewall_backend
│   │   │   ├── errors.py           # exception handlers → JSON uniforme
│   │   │   └── v1/
│   │   │       ├── router.py       # agrega los routers de v1
│   │   │       ├── health.py
│   │   │       ├── auth.py
│   │   │       ├── rules.py
│   │   │       ├── firewall.py
│   │   │       ├── logs.py         # fase 2 (stub)
│   │   │       └── stats.py        # fase 3 (stub)
│   │   │
│   │   └── workers/                # fase 2: procesos de fondo
│   │       └── log_collector.py    # tail de journalctl → packet_logs
│   │
│   └── tests/
│       ├── conftest.py             # fixtures: app, client, db en memoria, fake backend
│       ├── unit/
│       │   ├── firewall/           # validators, renderer, parser — sin I/O
│       │   └── services/
│       ├── integration/            # TestClient + SQLite temporal + FakeBackend
│       ├── contract/               # misma suite contra fake e iptables (§8)
│       ├── e2e_vm/                 # @pytest.mark.requires_iptables, skip por defecto
│       └── fixtures/
│           └── iptables_output/    # salidas reales capturadas, para el parser
│
└── frontend/
    ├── package.json
    ├── vite.config.ts
    ├── tsconfig.json
    ├── .env.example                # VITE_API_BASE_URL
    └── src/
        ├── main.tsx
        ├── App.tsx
        ├── api/
        │   ├── client.ts           # wrapper de fetch: inyecta JWT, maneja 401
        │   ├── schema.d.ts         # tipos generados desde el OpenAPI de FastAPI
        │   └── endpoints/
        │       ├── rules.ts
        │       └── auth.ts
        ├── features/               # organizado por dominio, no por tipo de archivo
        │   ├── auth/
        │   ├── rules/              # RulesTable, RuleForm, useRules
        │   ├── firewall/           # StatusBadge, ApplyButton, DriftBanner
        │   ├── logs/               # fase 2
        │   └── dashboard/          # fase 3
        ├── components/ui/          # primitivas sin lógica de dominio
        ├── hooks/
        ├── lib/                    # formateo, constantes, helpers
        └── routes/
```

**La regla que sostiene la estructura**: las dependencias van en una sola dirección.

```
api/  →  services/  →  firewall/  +  models/
              ↓
            db/                      core/  (todos pueden usarlo)
```

Un router nunca importa `firewall/`. Un servicio nunca importa `fastapi`. El paquete
`firewall/` no sabe que existe una base de datos ni una API. Si esa regla se rompe,
se rompe la testabilidad, así que conviene dejarla escrita en el README y —si
quieres— forzarla con `import-linter` en CI.

**Por qué no hay capa `repositories/`**: con SQLAlchemy 2.0 la sesión ya *es* el
repositorio, y añadir una capa de mapeo sobre él en un proyecto de este tamaño es
ceremonia sin retorno. Los servicios reciben una `Session` por inyección, que es
suficiente para testear con una DB en memoria. Si algún día la persistencia se vuelve
compleja, se añade sin tocar `api/`.

---

## 2. Modelo de datos

Creamos **todas** las tablas ahora (aunque `packet_logs`, `alerts` y `audit_events`
queden vacías hasta la fase 2), precisamente para no migrar esquema después. Alembic
está desde el principio, así que aunque nos equivoquemos el coste es bajo.

### 2.1 `users`

| Columna | Tipo | Notas |
|---|---|---|
| `id` | int PK | |
| `username` | str(50) | unique, indexado |
| `email` | str(255) | nullable, unique |
| `hashed_password` | str(255) | Argon2 (mejor que bcrypt hoy; `argon2-cffi`) |
| `role` | enum | `admin` \| `operator` \| `viewer` |
| `is_active` | bool | permite desactivar sin borrar |
| `created_at` / `last_login_at` | datetime UTC | |

`viewer` solo lee, `operator` gestiona reglas, `admin` además gestiona usuarios. Tres
roles es el mínimo que hace que el RBAC signifique algo; con dos parece decorativo.

### 2.2 `rules` — la entidad central

| Columna | Tipo | Notas |
|---|---|---|
| `id` | int PK | interno |
| `uuid` | str(36) | unique. Identificador público y etiqueta en iptables |
| `name` | str(100) | legible: "Bloquear escáner chino" |
| `description` | text | **el porqué**. Vale oro para explicar el proyecto |
| `chain` | enum | `INPUT` \| `OUTPUT` \| `FORWARD` — las tres gestionadas en el MVP |
| `table_name` | enum | `filter` (por ahora solo filter; el campo evita migrar si añades `nat`) |
| `ip_version` | int | `4` \| `6`, default `4`. El MVP solo genera reglas v4 (§9.1) |
| `action` | enum | `ACCEPT` \| `DROP` \| `REJECT` |
| `protocol` | enum | `tcp` \| `udp` \| `icmp` \| `all` |
| `src_ip` | str(43) | nullable. Guardado siempre normalizado a CIDR (`1.2.3.4/32`) |
| `dst_ip` | str(43) | nullable |
| `src_port` | str(11) | nullable. Puerto o rango `8000:8010` |
| `dst_port` | str(11) | nullable |
| `in_interface` | str(16) | nullable |
| `out_interface` | str(16) | nullable |
| `position` | int | orden dentro de la cadena. Único por `chain` |
| `enabled` | bool | desactivar sin borrar → se omite al renderizar |
| `log_enabled` | bool | fase 2: emite una regla `LOG` antes de la de acción |
| `log_prefix` | str(29) | límite real de iptables. Se autogenera: `FWD:<uuid8>` |
| `sync_state` | enum | `pending` \| `applied` \| `failed` \| `drift` |
| `last_error` | text | nullable, stderr saneado del último fallo |
| `expires_at` | datetime | nullable. Bloqueos temporales (fase 4: auto-ban) |
| `hit_count` / `bytes_count` | int | contadores leídos de `iptables -L -v -n` |
| `created_at` / `updated_at` / `applied_at` | datetime UTC | |
| `created_by_id` | FK users | nullable con `ON DELETE SET NULL` |

Detalles no obvios:

- **`src_ip` como texto normalizado, no como entero.** Un `INET` no existe en SQLite y
  guardar enteros complica las consultas manuales. Normalizamos con el módulo
  `ipaddress` al validar, de modo que `1.2.3.4` y `1.2.3.4/32` sean la misma fila.
- **Puertos como `str`, no `int`.** Porque `80` y `8000:8010` son ambos válidos en
  iptables. El validador acepta las dos formas y rechaza todo lo demás.
- **`position` único por cadena**, con `UniqueConstraint(chain, position)` diferido, o
  bien reasignación en bloque al reordenar. Recomiendo lo segundo por simplicidad:
  `POST /rules/reorder` recibe la lista de uuids y reescribe `position` de 10 en 10
  (deja hueco para inserciones sin renumerar todo).
- **`sync_state` es lo que hace visible la reconciliación** en la UI: una regla puede
  existir en la DB y no estar aplicada. Esa distinción es el corazón del diseño y
  además queda muy bien en la tabla del frontend.

### 2.3 `packet_logs` — fase 2, tabla creada ya

| Columna | Tipo | Notas |
|---|---|---|
| `id` | int PK | |
| `ts` | datetime UTC | indexado |
| `src_ip` / `dst_ip` | str(43) | |
| `src_port` / `dst_port` | int | nullable |
| `protocol` | str(10) | |
| `in_interface` | str(16) | |
| `rule_uuid` | str(36) | nullable, extraído del `log_prefix`. **Sin FK real** |
| `raw` | text | línea original, para depurar el parser |

Índices: `(ts)`, `(src_ip, ts)`, `(dst_port, ts)`. Los tres son exactamente las
consultas de las gráficas de la fase 3, así que ponerlos ahora es gratis.

`rule_uuid` deliberadamente **sin foreign key**: un log es un hecho histórico y debe
sobrevivir al borrado de la regla que lo generó. Si pones FK, o pierdes logs o te
bloquea el borrado.

Nota de capacidad: esta tabla crece rápido. Prevé desde ya una tarea de retención
(borrar > 30 días) y considera agregados por hora en fase 3 en vez de consultar la
tabla cruda.

### 2.4 `alerts` — fase 4

`id`, `ts`, `kind` (`brute_force` | `port_scan` | `rate_limit`), `severity`,
`src_ip`, `details` (JSON), `related_rule_uuid`, `acknowledged_at`,
`acknowledged_by_id`.

### 2.5 `audit_events` — transversal, desde el día 1

`id`, `ts`, `user_id`, `action` (`rule.create`, `firewall.apply`, `auth.login_failed`…),
`entity_type`, `entity_id`, `payload` (JSON del antes/después), `result`
(`success`|`failure`), `client_ip`.

Es la tabla que separa "una app que toca iptables" de "una herramienta de seguridad".
En una entrevista, poder decir *"toda mutación de la política queda auditada con quién,
cuándo y qué cambió"* vale más que tres gráficas.

---

## 3. La capa de abstracción sobre iptables

Cuatro piezas pequeñas en vez de una clase grande. Cada una se testea sola.

### 3.1 `spec.py` — el tipo frontera

```python
@dataclass(frozen=True, slots=True)
class RuleSpec:
    chain: Chain
    action: Action
    protocol: Protocol = Protocol.ALL
    src_ip: str | None = None
    # ... resto de campos

    def __post_init__(self) -> None:
        validate_spec(self)   # se valida al construir
```

`RuleSpec` es inmutable, no conoce SQLAlchemy ni Pydantic, y **no se puede construir
inválido**. Esa es la respuesta a "validación centralizada, no repartida por los
endpoints": la validación no está en un sitio *por convención*, está en el único sitio
por donde es posible pasar.

El flujo completo queda:

```
RuleCreate (Pydantic, valida forma HTTP)
   → RuleModel (SQLAlchemy, persiste)
      → RuleSpec (valida semántica de red)
         → argv: ["iptables", "-A", "FWDASH_INPUT", "-s", "1.2.3.4/32", "-j", "DROP"]
```

Tres validaciones distintas porque protegen de tres cosas distintas: Pydantic protege
el contrato, el modelo protege la integridad, `RuleSpec` protege el sistema.

### 3.2 `validators.py` — todo el saneamiento, en un archivo

```python
def validate_ip_or_cidr(value: str) -> str   # ipaddress.ip_network(strict=False) → str normalizado
def validate_port_spec(value: str) -> str    # "80" | "8000:8010", 1..65535, inicio < fin
def validate_interface(value: str) -> str    # ^[a-zA-Z0-9@._-]{1,15}$
def validate_chain(value: str) -> Chain
def validate_log_prefix(value: str) -> str   # ≤29 chars, sin comillas ni saltos
```

Cada uno lanza `InvalidRuleError` con un mensaje útil. Ninguna otra parte del código
tiene permiso para interpretar una IP o un puerto.

### 3.3 `runner.py` — el único punto con `subprocess`

```python
class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], *, timeout: float = 10.0) -> CommandResult: ...

class SubprocessRunner:
    ALLOWED_BINARIES = frozenset({"iptables", "iptables-save", "iptables-restore"})

    def run(self, argv, *, timeout=10.0) -> CommandResult:
        # 1. argv[0] (tras 'sudo') debe estar en ALLOWED_BINARIES → si no, SecurityError
        # 2. todos los elementos deben ser str (nada de None ni ints colados)
        # 3. subprocess.run(argv, shell=False, timeout=..., capture_output=True,
        #                   env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
        # 4. log estructurado del argv completo antes de ejecutar
```

`shell=False` es el valor por defecto de `subprocess.run`, pero lo dejamos explícito
porque es el punto entero del ejercicio. `env` mínimo y `LC_ALL=C` para que el parser
no dependa del locale de la VM. Timeout siempre, porque un `iptables` colgado con
`-w` mal puesto bloquea el worker.

### 3.4 `base.py` / `iptables.py` / `fake.py` — el backend intercambiable

```python
class FirewallBackend(Protocol):
    def ensure_scaffold(self) -> None: ...
    def apply_ruleset(self, chain: str, specs: Sequence[RuleSpec]) -> ApplyResult: ...
    def read_ruleset(self, chain: str) -> list[NativeRule]: ...
    def read_counters(self, chain: str) -> dict[str, Counters]: ...
    def teardown(self) -> None: ...
```

Solo **una** operación de escritura, coherente con §0.

- `IptablesBackend`: recibe un `CommandRunner` por constructor.
- `FakeFirewallBackend`: guarda las specs en una lista en memoria. Implementa el mismo
  Protocol.

**Cómo se testea sin iptables**, que era el requisito. Hay dos costuras, y cada una
cubre una cosa:

| Costura | Qué inyectas | Qué testea |
|---|---|---|
| `CommandRunner` | runner falso que devuelve stdout enlatado | que `IptablesBackend` construye el argv correcto y que el parser lee bien salidas reales |
| `FirewallBackend` | `FakeFirewallBackend` | servicios y endpoints completos, sin subprocess |

En `api/deps.py`, `get_firewall_backend()` devuelve uno u otro según
`settings.firewall_backend`. Efecto secundario muy práctico: **puedes levantar el
backend entero en tu Mac** con `FIREWALL_BACKEND=fake` y desarrollar el frontend sin
tocar la VM. La VM solo hace falta para lo real.

Para el parser: guarda salidas reales de `iptables -S` y `iptables -L -v -n` en
`tests/fixtures/iptables_output/`. Son los tests más valiosos del repo, porque el
formato de iptables tiene bastantes casos raros.

### 3.5 Endpoints del MVP

```
POST   /api/v1/auth/login              → access + refresh token
POST   /api/v1/auth/refresh
GET    /api/v1/auth/me

GET    /api/v1/rules                   ?chain=&enabled=&q=&page=
POST   /api/v1/rules
GET    /api/v1/rules/{uuid}
PATCH  /api/v1/rules/{uuid}
DELETE /api/v1/rules/{uuid}
POST   /api/v1/rules/{uuid}/toggle
POST   /api/v1/rules/reorder           body: {"uuids": [...]}

POST   /api/v1/firewall/apply          reconcilia DB → iptables
GET    /api/v1/firewall/preview        dry-run: devuelve el argv sin ejecutar
GET    /api/v1/firewall/status         drift, contadores, scaffold ok, última aplicación

GET    /api/v1/health                  liveness (sin auth)
GET    /api/v1/ready                   readiness: DB + iptables accesible
```

Fase 2+ añade `/logs`, `/stats/{top-ips,timeline,ports}` y `/alerts` — carpetas
nuevas, cero cambios en lo anterior.

Sobre si `POST /rules` aplica al instante: propongo que sí por defecto
(`settings.auto_apply=true`), pero que la ruta de aplicación sea *siempre* la misma
función de reconciliación. Así, poner `auto_apply=false` para tener un flujo de
staging tipo Terraform (`plan` → `apply`) es cambiar un flag, no reescribir nada.

---

## 4. Configuración y entornos

### 4.1 Qué corre dónde

La tabla siguiente describe el estado **final** (bloque C del §8). Durante el bloque A
no hay VM en absoluto: backend, frontend, DB y tests corren todos en el Mac con
`FIREWALL_BACKEND=fake`.

| Componente | Máquina | Motivo |
|---|---|---|
| Frontend (`vite dev`) | **Mac** | solo habla HTTP; no necesita Linux |
| Backend FastAPI | **VM `firewall-lab`** | necesita ejecutar `iptables` |
| SQLite (`firewall.db`) | **VM** | vive junto al backend, en `/var/lib/firewall-dashboard/` |
| Alembic | **VM** | migra la DB que está en la VM |
| Tests unitarios + integración | **Mac** | usan `FakeFirewallBackend`, no necesitan iptables |
| Tests `e2e_vm` | **VM** | tocan iptables real |
| Código fuente | **Mac**, montado en la VM | `multipass mount ~/dev/firewall-dashboard firewall-lab:/home/ubuntu/app` |

Editas en tu Mac con tu editor de siempre; el proceso corre en la VM sobre el mismo
árbol de archivos. Sin `rsync` ni redespliegues.

Un detalle importante: el backend **no puede** hacer bind a `127.0.0.1` si quieres
llegar desde el Mac. Bind a la IP de la interfaz de Multipass (la red `192.168.64.0/24`
en Apple Silicon), que es host-only y no está expuesta a tu LAN. Eso cumple "no expongas
el backend fuera de mi red local" sin necesidad de túnel. Si prefieres máxima
paranoia: bind a `127.0.0.1` y `ssh -L 8000:localhost:8000 ubuntu@<ip-vm>`.

### 4.2 `.env.example` (backend)

```ini
# --- App ---
APP_ENV=dev                          # dev | vm | prod
APP_NAME=firewall-dashboard
LOG_LEVEL=INFO
LOG_FORMAT=console                   # console | json

# --- API ---
API_HOST=0.0.0.0                     # en la VM: la IP de la interfaz de Multipass
API_PORT=8000
API_V1_PREFIX=/api/v1
CORS_ORIGINS=http://localhost:5173

# --- Base de datos ---
DATABASE_URL=sqlite:///./firewall.db  # en la VM: /var/lib/firewall-dashboard/firewall.db

# --- Auth ---
JWT_SECRET_KEY=                       # openssl rand -hex 32 — NUNCA se commitea
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=             # solo para el primer arranque

# --- Firewall ---
FIREWALL_BACKEND=fake                 # fake | iptables  ← el interruptor Mac/VM
IPTABLES_BIN=/usr/sbin/iptables
IPTABLES_TABLE=filter
MANAGED_CHAIN_PREFIX=FWDASH
USE_SUDO=true
COMMAND_TIMEOUT_SECONDS=10
AUTO_APPLY=true
MANAGEMENT_PORT=8000                  # se protege con regla guardián
MANAGEMENT_ALLOWED_CIDR=192.168.64.0/24
```

Con Pydantic Settings en `core/config.py`: tipos reales (`IPvAnyNetwork`, `SecretStr`),
validación al arrancar, y un `@lru_cache` en `get_settings()`. Si falta `JWT_SECRET_KEY`
en producción, la app no arranca. Fallar en el arranque es siempre mejor que fallar en
la primera petición.

Frontend, `.env.example`: `VITE_API_BASE_URL=http://192.168.64.5:8000/api/v1`.

### 4.3 Privilegios: sudoers vs capabilities

Me pediste redactar la línea de sudoers, no ejecutarla. Aquí está — y una alternativa
que creo mejor.

**Opción A — sudoers restringido** (`/etc/sudoers.d/firewall-dashboard`, permisos 0440,
validar con `visudo -c -f`):

```
Cmnd_Alias FWDASH_CMDS = /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore
fwdash ALL=(root) NOPASSWD: FWDASH_CMDS
Defaults!FWDASH_CMDS !requiretty
```

**Sé honesto sobre esto en el README**, porque es justo lo que te van a preguntar:
`NOPASSWD` sobre `iptables` completo es, en la práctica, equivalente a root. Con
`iptables-restore` se puede reescribir toda la política, y con `-j` a targets como
`NFQUEUE` se abre bastante superficie. No es un privilegio acotado de verdad; es un
privilegio *nombrado*.

**Opción B — capabilities (la que recomiendo).** Nada de sudo: se le da al proceso
exactamente la capacidad que necesita, vía systemd:

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

`CAP_NET_ADMIN` es exactamente el permiso que `iptables` necesita, sin conceder nada
más, y `NoNewPrivileges` impide escalar. Poder explicar en una entrevista *por qué
elegiste capabilities sobre sudo* es, con diferencia, mejor señal que la propia
funcionalidad del dashboard.

Propuesta práctica: soporta las dos (`USE_SUDO` en `.env`), documenta A como camino
rápido de desarrollo y B como el modo correcto, y escribe el ADR
`0003-privilegios-sudo-vs-capabilities.md` explicando el razonamiento.

En cualquier caso: **yo no toco `/etc/sudoers` ni ejecuto nada contra iptables real.**
Te dejo los archivos en `infra/` y los aplicas tú cuando los hayas revisado.

---

## 5. Convenciones

### 5.1 Naming

- Python `snake_case`; clases `PascalCase`; constantes `UPPER_SNAKE`.
- Módulos de servicio: `<dominio>_service.py`, funciones en imperativo
  (`create_rule`, `apply_ruleset`).
- Schemas Pydantic con sufijo de intención: `RuleCreate`, `RuleUpdate`, `RuleRead`,
  `RuleListItem`. Nunca reutilizar un schema para entrada y salida: acaba filtrando
  campos internos.
- Modelos SQLAlchemy en singular (`Rule`), tablas en plural (`rules`).
- Booleanos con prefijo verbal: `is_active`, `has_drift`, `log_enabled`.
- Frontend: componentes `PascalCase.tsx`, hooks `useAlgo.ts`, tipos derivados del
  OpenAPI, nunca escritos a mano.
- Todos los `datetime` en **UTC** en la DB; la conversión a Europe/Madrid pasa en el
  frontend. Esto ahorra un dolor de cabeza garantizado en las gráficas de la fase 3.

### 5.2 Errores

Jerarquía en `core/exceptions.py`:

```
AppError                    (base, lleva code + message + details)
├── ValidationError         → 422
│   └── InvalidRuleError
├── NotFoundError           → 404
├── ConflictError           → 409   (posición duplicada, regla ya existente)
├── AuthError               → 401
├── PermissionError         → 403
└── FirewallError           → 502
    ├── FirewallCommandError    (iptables devolvió != 0)
    ├── FirewallTimeoutError
    └── FirewallDriftError      → 409
```

Un único handler en `api/errors.py` las traduce a una respuesta uniforme:

```json
{
  "error": {
    "code": "invalid_rule",
    "message": "El puerto '99999' está fuera del rango válido (1-65535)",
    "details": {"field": "dst_port"},
    "request_id": "01J..."
  }
}
```

Dos reglas que no se saltan: los servicios lanzan excepciones de dominio, **nunca**
`HTTPException` (eso los ataría a FastAPI y rompería los tests unitarios); y el
`stderr` crudo de iptables va al log completo pero al cliente solo saneado —
puede contener rutas y detalles de la topología.

### 5.3 Logging de la aplicación

`structlog`, JSON en la VM y coloreado en dev. No confundir con `packet_logs`: esto es
telemetría de la app.

- Middleware que genera `request_id` (ULID) y lo mete en el contexto de todo el log de
  esa petición y en la respuesta de error.
- **Cada invocación de iptables se loguea antes de ejecutarse**, con el argv completo,
  el usuario que la origina y el `request_id`. Es tu pista de auditoría técnica, y se
  complementa con la tabla `audit_events` (que es la de negocio).
- Nunca loguear: passwords, tokens JWT, el `JWT_SECRET_KEY`. Añade un processor de
  structlog que censure claves por nombre, no confíes en la disciplina.

### 5.4 Tests desde el día 1

`pytest` + `pytest-cov` + `pytest-asyncio` + `httpx`.

```
tests/unit/          rápidos, sin I/O.       Objetivo: >90% en firewall/ y services/
tests/integration/   TestClient + SQLite temporal + FakeBackend
tests/contract/      misma suite parametrizada por backend (fake | iptables) — §8
tests/e2e_vm/        marker requires_iptables, skip por defecto
```

En `pyproject.toml`: `addopts = "-m 'not requires_iptables' --cov=app"`. Así `pytest` a
secas funciona en tu Mac, y en la VM lanzas `pytest -m requires_iptables`.

Fixtures clave en `conftest.py`: `db_session` (SQLite en memoria, rollback por test),
`fake_firewall`, `client` (con `dependency_overrides` para inyectar ambos),
`auth_headers` (token de un usuario de prueba).

Los cuatro tests que escribiría primero, antes que ninguna feature:

1. `validate_port_spec` rechaza `0`, `65536`, `80; rm -rf /`, `8000:80`.
2. El renderer produce el argv esperado para una spec conocida.
3. El parser lee correctamente una salida real de `iptables -S`.
4. `SubprocessRunner` lanza `SecurityError` si el binario no está en la allowlist.

### 5.5 Tooling

`ruff` (lint + format), `mypy --strict` sobre `app/firewall/` como mínimo, `bandit`
(linter de seguridad para Python — muy pertinente en este repo), `pip-audit`,
`gitleaks`. Todo en `pre-commit` y repetido en un workflow de GitHub Actions. Un CI en
verde en el README es señal barata y efectiva en un portfolio.

---

## 6. Documentación

- **`README.md`**: qué es y por qué existe, captura del dashboard (lo primero que mira
  un reclutador), arquitectura en 5 líneas, setup en dos bloques (Mac y VM), stack,
  estado de las fases, y un aviso claro de que es un laboratorio.
- **`docs/SECURITY.md`**: el documento que te van a hacer preguntar en una entrevista.
  Modelo de amenazas (activos, atacantes, superficie), inyección de comandos y cómo se
  mitiga, el modelo de privilegios y sus límites reales, autenticación y RBAC, y una
  sección honesta de **limitaciones conocidas**. Admitir lo que no protege da más
  credibilidad que fingir que es un producto.
- **`docs/adr/`**: un ADR corto por decisión (contexto, opciones, decisión,
  consecuencias). Las cuatro decisiones de este documento son los cuatro primeros.
  Es la mejor herramienta que conozco para responder "¿por qué lo hiciste así?" sin
  improvisar.
- **`docs/RUNBOOK.md`**: cómo recuperar el acceso si te bloqueas
  (`multipass shell firewall-lab` sigue funcionando aunque la red esté cerrada, porque
  no pasa por TCP), cómo correr `panic_reset.sh`, cómo restaurar desde `iptables-save`.
- **`docs/SETUP_VM.md`**: Multipass paso a paso, incluido el `mount`.

---

## 7. Git

### 7.1 `.gitignore`

```gitignore
# Python
__pycache__/
*.py[cod]
.venv/
venv/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/
dist/
*.egg-info/

# Entorno y secretos  ← lo importante
.env
.env.*
!.env.example
*.pem
*.key
secrets/

# Base de datos (contiene IPs reales de tu red)
*.db
*.sqlite
*.sqlite3
data/

# Volcados de iptables (revelan tu topología de red)
*.rules
iptables-backup-*
infra/**/*.local.*

# VM
.multipass/
*.cloud-init.local.yaml

# Node
node_modules/
frontend/dist/
.vite/

# macOS / editores
.DS_Store
.idea/
.vscode/*
!.vscode/extensions.json
```

Los tres bloques que la gente olvida y aquí importan: el `.db` (guarda las IPs reales
de tu red doméstica), los volcados de iptables (son un mapa de tu red) y el
`cloud-init` si le metes claves SSH. Añade `gitleaks` en pre-commit como red de
seguridad.

### 7.2 Ramas y commits

Para un proyecto de una persona, `git flow` sobra. Propongo:

- `main` siempre desplegable. Ramas `feat/`, `fix/`, `docs/`, `refactor/`,
  `test/`, `chore/`.
- **Conventional Commits** (`feat(rules): añadir endpoint de reordenación`). Aparte de
  ser buena práctica, permite generar el CHANGELOG solo y hace que tu historial se lea
  como un proyecto profesional — que es medio objetivo aquí.
- Un **tag por fase**: `v0.1.0-mvp`, `v0.2.0-logging`, `v0.3.0-dashboard`,
  `v0.4.0-detection`. Muestra progresión, que es exactamente lo que quieres que se vea.
- Aunque trabajes solo, **abre PR contra `main`** y deja que CI corra. El historial de
  PRs con descripción es material de conversación en una entrevista.
- Primer commit: el scaffolding completo con `chore: scaffolding inicial del proyecto`.

---

## 8. Plan de construcción en tres bloques

Secuencia acordada: **(A)** aplicación completa, front y back → **(B)** capa de firewall
real, aislada → **(C)** interconexión.

Esto encaja bien con el diseño porque ya existe la costura del §3.4: `FirewallBackend`
es un Protocol con dos implementaciones. El bloque A se construye entero contra
`FakeFirewallBackend`, el bloque B construye `IptablesBackend` sin que la app lo sepa,
y el bloque C es cambiar una variable de entorno. No es una separación forzada para
que te cuadre el calendario: es la misma frontera que ya tenía el diseño.

### El riesgo real de este orden, y cómo lo neutralizamos

Construir semanas contra un doble tiene un fallo clásico: **el fake miente**. Si diseño
el Protocol imaginando cómo se comporta iptables, acabo con una interfaz cómoda que no
corresponde a la realidad, y el bloque C deja de ser "cambiar una variable" para
convertirse en la reescritura que querías evitar.

Dos medidas, ambas baratas:

**1. Una expedición de reconocimiento a la VM** (20 minutos, una sola vez). Decidido:
la hacemos en **A2**, justo antes de escribir el parser — así arrancas hoy el
scaffolding y el núcleo sin depender de Multipass, y capturas las fixtures en el momento
en que empiezan a hacer falta. Levantas la VM, ejecutas media docena de comandos de
*solo lectura* y guardas las salidas literales en `tests/fixtures/iptables_output/`:

```bash
iptables -S
iptables -L -v -n
iptables -S FWDASH_INPUT          # cómo falla cuando la cadena no existe
iptables --version
```

Con eso el Protocol se diseña contra **salidas reales**, no contra mi idea de cómo son.
Después apagas la VM y no la vuelves a tocar hasta el bloque B. Es la única vez que el
bloque A roza la VM, y es lectura pura: no modifica nada.

**2. Tests de contrato** (`tests/contract/`). Una única suite de tests, parametrizada
por backend, que se ejecuta contra los dos:

```python
@pytest.fixture(params=["fake", "iptables"])
def backend(request): ...
```

En el Mac corre solo con `fake`; en la VM, con los dos. Si el fake se desvía de la
realidad, el test de contrato lo detecta en el bloque B — no cuando ya tienes el
frontend encima. Esta es la técnica estándar para mantener honesto un doble de prueba,
y es exactamente lo que convierte el bloque C en un no-evento.

### Bloque A — La aplicación (todo en el Mac)

Ni Multipass ni iptables (salvo la expedición inicial). `FIREWALL_BACKEND=fake`.

| # | Paso | Entregable verificable |
|---|---|---|
| A0 | Scaffolding: árbol, `pyproject.toml`, tooling, `.env.example`, `.gitignore`, ADRs 0001-0004 | `pytest` y `ruff` corren en verde sobre un repo vacío |
| A1 | Núcleo: `config`, `logging`, `exceptions`, modelos, migración inicial, `/health` | `alembic upgrade head` crea la DB; `/health` responde |
| A2 | **Expedición de reconocimiento a la VM** (solo lectura) — justo antes de tocar el parser | fixtures reales en `tests/fixtures/iptables_output/` |
| A3 | `firewall/`: `spec`, `validators`, `renderer`, `parser`, `base`, `fake` + sus tests | la pieza delicada, terminada y testeada, sin subprocess |
| A4 | Auth: usuarios, JWT, RBAC, `seed` del admin | login funcional |
| A5 | `/rules` CRUD + `/firewall/{apply,preview,status}` contra el fake | tests de integración en verde |
| A6 | Frontend: login, tabla de reglas, formulario, badge de estado | **el MVP entero funciona en tu Mac** |

Al final del bloque A tienes una aplicación completa y demostrable. Corre en tu portátil,
sin VM, sin privilegios: el `FakeBackend` guarda las reglas en memoria y la UI las
muestra. Para grabar un gif de demo del portfolio, esto ya sirve.

Fíjate en que `firewall/` (A3) se construye **entero** en el bloque A, incluidos
`renderer` y `parser`. No es contradictorio: esos módulos son funciones puras que
traducen datos a `argv` y texto a estructuras. No ejecutan nada. Lo único que se queda
para el bloque B es `runner.py` y `iptables.py`, que son las dos piezas pequeñas que
tocan el sistema.

### Bloque B — El firewall (todo en la VM, sin la app)

Aquí no existe FastAPI. Trabajas contra `iptables` directamente y contra un script de
pruebas.

| # | Paso | Entregable verificable |
|---|---|---|
| B0 | VM `firewall-lab` provisionada: `cloud-init`, `multipass mount`, `SETUP_VM.md` | `multipass shell` entra y el código del Mac se ve dentro |
| B1 | Privilegios: sudoers o capabilities (§4.3), usuario `fwdash`, unidad systemd | `iptables -S` corre sin contraseña como `fwdash` |
| B2 | `runner.py`: subprocess con allowlist, timeout, env mínimo | test que verifica que un binario fuera de la allowlist lanza `SecurityError` |
| B3 | `iptables.py`: `ensure_scaffold`, `apply_ruleset`, `read_ruleset`, `read_counters` | cadena `FWDASH_INPUT` creada y poblada desde un script |
| B4 | Reglas guardián + `panic_reset.sh` + `RUNBOOK.md` | te bloqueas a propósito y recuperas el acceso |
| B5 | Tests de contrato corriendo con los dos backends | `pytest -m requires_iptables` en verde en la VM |

B4 merece énfasis: **provoca el auto-bloqueo a propósito**, en un entorno donde no
importa, y comprueba que sabes salir. `multipass shell firewall-lab` no pasa por TCP, así
que sigue funcionando aunque cierres la red entera. Es mucho mejor descubrir eso aquí que
la noche antes de una entrevista.

### Bloque C — La interconexión

Si A y B se han hecho bien, esto es corto:

| # | Paso |
|---|---|
| C0 | `FIREWALL_BACKEND=iptables` en el `.env` de la VM; el backend arranca allí |
| C1 | Red: bind a la interfaz de Multipass, CORS del frontend, `VITE_API_BASE_URL` |
| C2 | Reconciliación en el arranque: la app reconstruye `FWDASH_INPUT` desde la DB |
| C3 | Detección de drift real: tocas iptables a mano y compruebas que la UI lo señala |
| C4 | Recorrido completo: crear regla en la UI → verificar con `iptables -S` en la VM |
| C5 | Cierre del MVP: capturas en el README, `SECURITY.md`, tag `v0.1.0-mvp` |

C3 y C4 son los que de verdad cierran el círculo. Todo lo anterior estaba probado por
separado; estos dos son los primeros que atraviesan las tres capas a la vez.

### Lo que cambia respecto al plan anterior

Poco, y es buena señal: el orden original ya llevaba iptables real al paso 7 de 8. La
diferencia es que ahora el bloque B se hace **como una unidad aislada y completa** —
incluidos privilegios, runbook y recuperación de auto-bloqueo — en vez de resolverse
sobre la marcha mientras conectas. Es más limpio, y te da tres hitos con demo propia en
vez de uno.

El precio a pagar es la fidelidad del fake, y es justo lo que cubren la expedición de
reconocimiento y los tests de contrato.

---

## 9. Puntos cerrados y puntos abiertos

**Cerrados:**

1. **IPv6** → columna `ip_version` en el modelo desde la primera migración, validadores
   preparados para ambas familias, pero el MVP solo genera reglas `iptables` v4. Añadir
   `ip6tables` después es una implementación más del Protocol, sin migración de esquema.
2. **Cadenas** → las tres: `INPUT`, `OUTPUT` y `FORWARD`, cada una con su cadena
   `FWDASH_*` y su bloque de guardianes (§0). Coste asumido: más superficie de test en
   A3/B5 y el riesgo de auto-bloqueo por `OUTPUT`, que es exactamente lo que ejercita el
   paso B4.

**Abiertos** (ninguno bloquea el bloque A):

3. **Persistencia tras reboot de la VM.** Con la DB como fuente de verdad, la app
   reconstruye la cadena al arrancar. ¿Te vale eso, o quieres además
   `iptables-persistent`? Recomiendo lo primero — reconstruir desde la DB es más
   coherente y demuestra el diseño.
4. **`docker` en la VM.** Si vas a correr Docker dentro de `firewall-lab`, sus reglas y
   las tuyas conviven en `INPUT`/`FORWARD`. La cadena propia lo hace seguro, pero
   conviene saberlo antes.
5. **El apply con rollback automático** (§0.3), ¿lo metemos en el MVP o en fase 2? Es
   la funcionalidad más vistosa del proyecto, pero también la más compleja.
