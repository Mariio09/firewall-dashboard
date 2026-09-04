#!/usr/bin/env bash
# =========================================================================== #
# b4_bloqueo.sh — provoca el auto-bloqueo DENTRO de la VM. Paso 2 de B4.
#
#   No lo lances a mano: lo orquesta `b4_verify.sh` desde el Mac.
#     uso: b4_bloqueo.sh <guardian|ssh|cidr> <segundos_de_ventana>
#
# ESTO SI MODIFICA REGLAS REALES. Todo lo que hace es reversible y la reversion
# esta ARMADA ANTES de bloquear nada.
#
# --------------------------------------------------------------------------- #
# POR QUE SE EJECUTA CON systemd-run Y NO EN LA SESION SSH
#
# El probe de B4 (paso 0) midio que `multipass exec` entra por SSH: bash <- sudo
# <- sshd <- sshd <- systemd. Es decir, **el proceso que corta la red es hijo de
# la conexion que la red sostiene**. Si se ejecutara dentro de la sesion, al
# cortar el 22 la sesion podria morir y llevarse el script a medias: reglas
# aplicadas, reversion nunca ejecutada, VM inalcanzable.
#
# `systemd-run` lo saca de la sesion y lo cuelga de systemd (PID 1). Ahi sobrevive
# a que la sesion muera, y el temporizador de rescate tambien.
#
# --------------------------------------------------------------------------- #
# LA RED DE SEGURIDAD, EN ORDEN
#
#   1. `iptables-save` a /root ANTES de tocar nada.
#   2. Temporizador de rescate ARMADO ANTES de aplicar el bloqueo: a los N
#      segundos ejecuta panic_reset.sh y restaura el backup, pase lo que pase.
#      Es el patron de `iptables-apply`, y es el que convierte "me he bloqueado"
#      en "estuve bloqueado dos minutos".
#   3. El bloqueo se aplica DESPUES.
#
# El orden no es un detalle: armar la reversion despues de bloquear seria confiar
# en llegar a ejecutar una linea desde el otro lado de la puerta que acabas de
# cerrar.
# =========================================================================== #
set -uo pipefail

FASE="${1:?falta la fase: guardian|ssh|cidr}"
VENTANA="${2:-90}"

APP=/opt/firewall-dashboard
PY="$APP/backend/.venv/bin/python"
PANIC="$APP/infra/scripts/panic_reset.sh"
DIR_LOG=/var/log/b4
LOG="$DIR_LOG/$FASE.log"
SELLO="$DIR_LOG/$FASE.estado"

[[ $EUID -eq 0 ]] || { echo "ERROR: se ejecuta como root" >&2; exit 1; }
mkdir -p "$DIR_LOG"

registrar() { printf '%s  %s\n' "$(date -Iseconds)" "$*" | tee -a "$LOG"; }

registrar "=== fase '$FASE', ventana de ${VENTANA}s ==="
registrar "kernel=$(uname -r) iptables=$(iptables --version)"

# --------------------------------------------------------------------------- #
# 1. Copia de seguridad
# --------------------------------------------------------------------------- #
BACKUP="/root/b4-antes-$FASE-$(date +%Y%m%d-%H%M%S).rules"
iptables-save > "$BACKUP"
registrar "backup en $BACKUP ($(grep -c . "$BACKUP") lineas)"

# --------------------------------------------------------------------------- #
# 2. Rescate armado ANTES de bloquear
# --------------------------------------------------------------------------- #
RESCATE=/root/b4_rescate.sh
cat > "$RESCATE" <<RESC
#!/usr/bin/env bash
# Generado por b4_bloqueo.sh. Se ejecuta solo, desde systemd, pase lo que pase.
set -uo pipefail
echo "\$(date -Iseconds)  RESCATE: disparado" >> "$LOG"
bash "$PANIC" >> "$LOG" 2>&1 || echo "\$(date -Iseconds)  RESCATE: panic_reset fallo" >> "$LOG"
iptables-restore < "$BACKUP" && echo "\$(date -Iseconds)  RESCATE: backup restaurado" >> "$LOG"
echo "recuperado" > "$SELLO"
echo "\$(date -Iseconds)  RESCATE: terminado" >> "$LOG"
RESC
chmod +x "$RESCATE"

# Una unidad por ejecucion: `--unit` con un nombre repetido falla si la anterior
# sigue en el sistema, y un rescate que no se arma por un choque de nombres es
# exactamente el fallo que no nos podemos permitir.
UNIDAD="b4-rescate-$(date +%s)"
if ! systemd-run --unit="$UNIDAD" --on-active="$VENTANA" --timer-property=AccuracySec=1s \
        /bin/bash "$RESCATE" >>"$LOG" 2>&1; then
    registrar "ABORTADO: no se pudo armar el rescate. No se bloquea nada."
    exit 1
fi
registrar "rescate armado: $UNIDAD dentro de ${VENTANA}s"

# Contraprueba de que el rescate EXISTE de verdad, no de que el comando no fallo.
if systemctl list-timers --all --no-legend 2>/dev/null | grep -q "$UNIDAD"; then
    registrar "contraprueba OK: el temporizador $UNIDAD aparece en list-timers"
else
    registrar "ABORTADO: el temporizador no aparece en list-timers. No se bloquea nada."
    systemctl stop "$UNIDAD.timer" 2>/dev/null
    exit 1
fi

echo "bloqueando" > "$SELLO"

# --------------------------------------------------------------------------- #
# 3. El bloqueo, por la via de la aplicacion
# --------------------------------------------------------------------------- #
# Se usa el backend real del propio proyecto, no `iptables -A` a mano: lo que hay
# que demostrar es que la CADENA DE MONTAJE de la aplicacion puede dejarte fuera,
# no que iptables sabe bloquear puertos.
case "$FASE" in
    guardian) CIDR_USADO="derivado"; PUERTO_CORTADO=8000 ;;
    ssh)      CIDR_USADO="derivado"; PUERTO_CORTADO=22   ;;
    cidr)     CIDR_USADO="192.168.64.0/24"; PUERTO_CORTADO=8000 ;;
    *)        registrar "fase desconocida"; exit 1 ;;
esac

if [[ "$CIDR_USADO" == "derivado" ]]; then
    IP_VM="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
    CIDR_USADO="$(echo "$IP_VM" | awk -F. '{print $1"."$2"."$3".0/24"}')"
fi
registrar "management_cidr=$CIDR_USADO  ·  se corta el puerto $PUERTO_CORTADO"

cd "$APP/backend" || { registrar "ABORTADO: no existe $APP/backend"; exit 1; }
CIDR="$CIDR_USADO" PUERTO="$PUERTO_CORTADO" "$PY" - >>"$LOG" 2>&1 <<'PYFIN'
import os

from app.api.deps import build_firewall_backend
from app.core.config import Settings
from app.firewall.spec import Action, Chain, Protocol, RuleSpec

ajustes = Settings(
    _env_file=None,
    app_env="dev",              # 'vm' exigiria JWT_SECRET_KEY, que aqui no pinta nada
    firewall_backend="iptables",
    use_sudo=False,             # root ya puede: la unidad con capabilities es del servicio
    management_port=8000,
    management_allowed_cidr=os.environ["CIDR"],
    log_level="INFO",
)
backend = build_firewall_backend(ajustes)
backend.ensure_scaffold()

regla = RuleSpec(
    chain=Chain.INPUT,
    action=Action.DROP,
    protocol=Protocol.TCP,
    dst_port=os.environ["PUERTO"],
    comment="b4-auto-bloqueo",
)
resultado = backend.apply_ruleset(Chain.INPUT, [regla])
print("APLICADO", resultado.applied, "reglas;", len(resultado.commands), "comandos")
for comando in resultado.commands:
    print("   ", " ".join(comando))
PYFIN
SALIDA_PY=$?
registrar "aplicacion terminada con codigo $SALIDA_PY"

# --------------------------------------------------------------------------- #
# 4. Lo que se ve desde DENTRO mientras dura el bloqueo
# --------------------------------------------------------------------------- #
# El efecto, no la ausencia de error: la regla tiene que estar en la cadena.
# Tres condiciones INDEPENDIENTES sobre la misma linea, y ninguna asume el orden
# de los flags. iptables reescribe lo que se le da —el renderer emite
# `-p tcp --dport 22 -m comment ...` y `-S` lo devuelve como
# `-p tcp -m comment ... -m tcp --dport 22 -j DROP`—, asi que un patron con el
# orden dentro daria falso negativo sobre una regla perfectamente aplicada.
# Es la trampa de la nota `Normalizacion de iptables`, y es la razon por la que
# el proyecto compara por estructura y no por texto (ADR-0006).
LINEA="$(iptables -S FWDASH_INPUT 2>/dev/null \
    | grep -- "--dport $PUERTO_CORTADO" | grep -- '-j DROP' | grep -- 'b4-auto-bloqueo')"
if [[ -n "$LINEA" ]]; then
    registrar "efecto OK: el DROP del puerto $PUERTO_CORTADO esta en FWDASH_INPUT"
    registrar "  $LINEA"
else
    registrar "efecto NO comprobado: el DROP no aparece en la cadena"
    iptables -S FWDASH_INPUT 2>&1 | sed 's/^/    /' | tee -a "$LOG" >/dev/null
fi

# Contraprueba del metodo: los mismos tres filtros, sobre un puerto que NADIE ha
# cortado, tienen que no encontrar nada. Si encontraran algo, el "efecto OK" de
# arriba no estaria demostrando nada.
if iptables -S FWDASH_INPUT 2>/dev/null \
    | grep -- "--dport 65000" | grep -q -- '-j DROP'; then
    registrar "contraprueba FALLIDA: encuentra un DROP del 65000, que nadie ha creado"
else
    registrar "contraprueba OK: el mismo metodo no encuentra un DROP que no existe"
fi

# La sesion SSH que ya estaba abierta: ¿sigue viva? Es la pregunta que decide si
# tener una shell abierta antes de aplicar sirve de algo.
registrar "conexiones al 22 vivas ahora: $(ss -tn state established '( sport = :22 )' 2>/dev/null | tail -n +2 | wc -l)"

# Y por que sigue viva: el guardian de conntrack. Sus contadores lo demuestran;
# decir 'la mantiene conntrack' sin mirarlos seria repetir la teoria.
registrar "contadores de los guardianes de FWDASH_INPUT:"
iptables -L FWDASH_INPUT -v -n -x --line-numbers 2>/dev/null | sed 's/^/    /' | tee -a "$LOG" >/dev/null

registrar "=== bloqueo activo. El rescate se dispara solo. ==="
