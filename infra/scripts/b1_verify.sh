#!/usr/bin/env bash
# =========================================================================== #
# b1_verify.sh — arnes del paso B1: privilegios del usuario de servicio
#
#   Ejecutar DENTRO de la VM, como root:
#     sudo bash /opt/firewall-dashboard/infra/scripts/b1_verify.sh
#
# NO MODIFICA NADA. Solo lee, y lanza procesos efimeros con `systemd-run` que
# se limpian solos. No toca la politica de iptables ni el servicio.
#
# --------------------------------------------------------------------------- #
# LA REGLA DE ESTE ARNES (aprendida en A5, cobrada cara en B0)
#
# Un arnes que no puede demostrar que hizo lo que dice, MIENTE EN VERDE. En B0
# el montaje se dio por bueno con un `test -f`, que pasa aunque no se pueda leer
# ni un byte. Aqui NADA se comprueba por codigo de salida: cada comprobacion mira
# el EFECTO — que la politica se lea de verdad, que el UID sea el que toca, que
# el conjunto efectivo de capabilities contenga cap_net_admin.
#
# Y cada afirmacion positiva viene con su CONTRAPRUEBA: demostrar que `fwdash`
# puede leer iptables no vale nada si no se demuestra antes que, sin privilegios,
# no puede. Si no, lo unico probado es que iptables es permisivo.
# =========================================================================== #
set -uo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-/opt/firewall-dashboard}"
APP_DIR="${APP_DIR:-/home/ubuntu/app}"
CONF_FILE="/etc/firewall-dashboard/backend.env"
DATA_DIR="/var/lib/firewall-dashboard"
UNIDAD="/etc/systemd/system/firewall-dashboard.service"
SUDOERS="/etc/sudoers.d/firewall-dashboard"
USUARIO="fwdash"
IPT="/usr/sbin/iptables"

ACIERTOS=0; FALLOS=0; SALTADOS=0
V=$'\033[32m'; R=$'\033[31m'; A=$'\033[33m'; N=$'\033[0m'
[[ -t 1 ]] || { V=""; R=""; A=""; N=""; }

ok()      { printf "  %sOK%s      %s\n" "$V" "$N" "$1"; ACIERTOS=$((ACIERTOS+1)); }
fallo()   { printf "  %sFALLO%s   %s\n" "$R" "$N" "$1"; [[ -n "${2:-}" ]] && printf "          %s\n" "$2"; FALLOS=$((FALLOS+1)); }
saltado() { printf "  %s-%s       %s\n" "$A" "$N" "$1"; SALTADOS=$((SALTADOS+1)); }
seccion() { printf "\n%s\n" "$1"; }

# Ejecuta algo como fwdash y devuelve su salida (stdout+stderr) sin morir.
como_fwdash() { runuser -u "$USUARIO" -- "$@" 2>&1; }

# Ejecuta algo como fwdash en una unidad transitoria, con las propiedades que se
# le pasen antes del `--`. `--pipe` devuelve la salida real del proceso.
en_unidad() {
    local props=() ; while [[ "$1" != "--" ]]; do props+=(-p "$1"); shift; done; shift
    systemd-run --quiet --wait --pipe --collect -p User="$USUARIO" "${props[@]}" -- "$@" 2>&1
}

#: Una politica de iptables de verdad SIEMPRE trae la cadena INPUT.
POLITICA='^-P INPUT '

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: hay que ejecutarlo como root (usa sudo)." >&2
    exit 1
fi

echo "================================================================"
echo " B1 — privilegios del usuario de servicio '$USUARIO'"
echo " $(date -Is)  ·  $(hostname)  ·  $($IPT --version 2>/dev/null)"
echo "================================================================"

# --------------------------------------------------------------------------- #
seccion "1. El usuario de servicio"

if id "$USUARIO" &>/dev/null; then
    UID_FW="$(id -u "$USUARIO")"
    if [[ "$UID_FW" -lt 1000 ]]; then
        ok "'$USUARIO' existe y es usuario de sistema (uid $UID_FW)"
    else
        fallo "'$USUARIO' tiene uid $UID_FW" "un usuario de servicio deberia ser de sistema (<1000): useradd --system"
    fi

    SHELL_FW="$(getent passwd "$USUARIO" | cut -d: -f7)"
    if [[ "$SHELL_FW" == */nologin || "$SHELL_FW" == */false ]]; then
        ok "no tiene shell de login ($SHELL_FW)"
    else
        fallo "shell de login: $SHELL_FW" "deberia ser /usr/sbin/nologin"
    fi

    ESTADO_PASS="$(passwd -S "$USUARIO" 2>/dev/null | awk '{print $2}')"
    if [[ "$ESTADO_PASS" == "L" || "$ESTADO_PASS" == "NP" ]]; then
        ok "cuenta sin contraseña utilizable (passwd -S: $ESTADO_PASS)"
    else
        fallo "la cuenta tiene contraseña utilizable (passwd -S: $ESTADO_PASS)" "usermod --lock $USUARIO"
    fi
else
    fallo "'$USUARIO' no existe" "lanza deploy_vm.sh"
fi

# --------------------------------------------------------------------------- #
seccion "2. El despliegue en $DEPLOY_DIR"

MAIN="$DEPLOY_DIR/backend/app/main.py"
CONTENIDO="$(como_fwdash head -c 200 "$MAIN")"
# Leer contenido, no `test -f`: es exactamente la diferencia que dejo pasar el
# montaje roto de B0.
if [[ "$CONTENIDO" == *"FastAPI"* || "$CONTENIDO" == *"import"* ]]; then
    ok "$USUARIO LEE el codigo desplegado (main.py, $(wc -c <<<"$CONTENIDO") bytes)"
else
    fallo "$USUARIO no puede leer $MAIN" "${CONTENIDO:0:120}"
fi

ESCRITURA="$(como_fwdash touch "$DEPLOY_DIR/.testigo-escritura")"
if [[ -e "$DEPLOY_DIR/.testigo-escritura" ]]; then
    rm -f "$DEPLOY_DIR/.testigo-escritura"
    fallo "$USUARIO puede ESCRIBIR en $DEPLOY_DIR" "el codigo desplegado deberia ser de root y solo lectura para el servicio"
else
    ok "$USUARIO no puede escribir en $DEPLOY_DIR (${ESCRITURA##*: })"
fi

UVICORN="$DEPLOY_DIR/backend/.venv/bin/uvicorn"
VER_UVICORN="$(como_fwdash "$UVICORN" --version)"
if [[ "$VER_UVICORN" == *[0-9].[0-9]* ]]; then
    ok "$USUARIO EJECUTA el venv desplegado ($VER_UVICORN)"
else
    fallo "$USUARIO no puede ejecutar $UVICORN" "${VER_UVICORN:0:160}"
fi

if [[ -d "$APP_DIR/.git" ]]; then
    DUENO="$(stat -c %U "$APP_DIR")"
    HEAD_CLON="$(runuser -u "$DUENO" -- git -C "$APP_DIR" rev-parse --short HEAD 2>/dev/null)"
    HEAD_DESPLEGADO="$(cat "$DEPLOY_DIR/.desplegado" 2>/dev/null)"
    if [[ -n "$HEAD_CLON" && "$HEAD_CLON" == "$HEAD_DESPLEGADO" ]]; then
        ok "lo desplegado es el commit del clon ($HEAD_CLON)"
    else
        fallo "el despliegue va desfasado: clon=$HEAD_CLON, /opt=$HEAD_DESPLEGADO" "vuelve a lanzar deploy_vm.sh tras el vm-sync"
    fi
else
    saltado "no hay clon en $APP_DIR: no se puede comparar el commit desplegado"
fi

# --------------------------------------------------------------------------- #
seccion "3. La configuracion en $CONF_FILE"

if [[ -f "$CONF_FILE" ]]; then
    MODO="$(stat -c %a "$CONF_FILE")"; DUENOS="$(stat -c %U:%G "$CONF_FILE")"
    if [[ "$MODO" == "640" && "$DUENOS" == "root:$USUARIO" ]]; then
        ok "permisos correctos ($MODO $DUENOS): el secreto JWT no lo lee nadie mas"
    else
        fallo "permisos $MODO $DUENOS" "deberia ser 640 root:$USUARIO"
    fi

    SECRETO="$(como_fwdash grep -c '^JWT_SECRET_KEY=.\{32,\}' "$CONF_FILE")"
    if [[ "$SECRETO" == "1" ]]; then
        ok "$USUARIO lee el .env y JWT_SECRET_KEY tiene longitud real"
    else
        fallo "$USUARIO no lee el .env, o JWT_SECRET_KEY esta vacia o es corta" "con APP_ENV=vm la aplicacion se niega a arrancar sin ella"
    fi

    if grep -q '^APP_ENV=vm' "$CONF_FILE"; then
        ok "APP_ENV=vm (el entorno estricto: sin secreto no arranca)"
    else
        fallo "APP_ENV no es 'vm'" "en la VM tiene que serlo, o los fallos de configuracion pasan desapercibidos"
    fi

    if grep -qE '^[A-Z_]+=.*[^#]#' "$CONF_FILE"; then
        fallo "hay comentarios al final de una linea con valor" "systemd se queda con la linea ENTERA como valor del EnvironmentFile"
    else
        ok "sin comentarios en linea (systemd los tomaria como parte del valor)"
    fi
else
    fallo "no existe $CONF_FILE" "lanza deploy_vm.sh"
fi

# --------------------------------------------------------------------------- #
seccion "4. Linea base: sin privilegios, $USUARIO NO puede"

SIN_PRIV="$(como_fwdash "$IPT" -S)"
if grep -qE "$POLITICA" <<<"$SIN_PRIV"; then
    fallo "$USUARIO lee la politica SIN privilegios" "algo se los esta dando de mas; todo lo que viene despues no prueba nada"
else
    ok "sin privilegios no lee la politica (${SIN_PRIV##*: })"
fi

# --------------------------------------------------------------------------- #
seccion "5. Opcion A del ADR-0003 — sudoers"

if [[ -f "$SUDOERS" ]]; then
    MODO_SUDO="$(stat -c %a "$SUDOERS")"
    if [[ "$MODO_SUDO" == "440" ]]; then
        ok "permisos 0440"
    else
        fallo "permisos $MODO_SUDO" "sudo ignora (o rechaza) el archivo si no es 0440"
    fi

    SINTAXIS="$(visudo -c -f "$SUDOERS" 2>&1)"
    if [[ "$SINTAXIS" == *"parsed OK"* ]]; then
        ok "sintaxis validada con visudo -c"
    else
        fallo "visudo -c no valida el archivo" "$SINTAXIS"
    fi

    CON_SUDO="$(como_fwdash sudo -n "$IPT" -S)"
    if grep -qE "$POLITICA" <<<"$CON_SUDO"; then
        ok "$USUARIO lee la politica con 'sudo -n iptables' ($(grep -c . <<<"$CON_SUDO") lineas)"
    else
        fallo "sudo -n iptables no devuelve la politica" "${CON_SUDO:0:200}"
    fi

    # Contraprueba: el alias limita QUE binario, y eso si hay que demostrarlo.
    FUERA="$(como_fwdash sudo -n /usr/bin/id -u)"
    if [[ "$FUERA" == "0" ]]; then
        fallo "$USUARIO ejecuta como root un binario FUERA del alias" "el Cmnd_Alias no esta limitando nada"
    else
        ok "un binario fuera del Cmnd_Alias es rechazado"
    fi
else
    saltado "no instalado: $SUDOERS (opcion A no aplicada)"
fi

# --------------------------------------------------------------------------- #
seccion "6. Opcion B del ADR-0003 — capabilities"

CON_CAP="$(en_unidad AmbientCapabilities=CAP_NET_ADMIN -- "$IPT" -S)"
if grep -qE "$POLITICA" <<<"$CON_CAP"; then
    ok "con CAP_NET_ADMIN ambient, $USUARIO lee la politica SIN sudo"
else
    fallo "con CAP_NET_ADMIN no lee la politica" "${CON_CAP:0:200}"
fi

# Contraprueba de la contraprueba: que sea la AMBIENT la que trabaja, y no que
# el bounding set baste. Si esto pasara, la unidad podria quitar Ambient y nadie
# se enteraria hasta B3.
SOLO_BOUNDING="$(en_unidad CapabilityBoundingSet=CAP_NET_ADMIN -- "$IPT" -S)"
if grep -qE "$POLITICA" <<<"$SOLO_BOUNDING"; then
    fallo "lee la politica con SOLO el bounding set" "entonces la prueba anterior no demuestra que AmbientCapabilities haga falta"
else
    ok "con solo CapabilityBoundingSet no basta: la ambient es la que trabaja"
fi

# LA COMPROBACION CENTRAL DE B1. El backend no ejecuta iptables: lanza un
# SUBPROCESO que lo ejecuta. Las ambient sobreviven al execve; las heredadas por
# otras vias, no. Si esto falla, B2 y B3 se construyen sobre arena.
HIJO="$(en_unidad AmbientCapabilities=CAP_NET_ADMIN -- \
    /usr/bin/python3 -c "import subprocess;print(subprocess.run(['$IPT','-S'],capture_output=True,text=True).stdout)")"
if grep -qE "$POLITICA" <<<"$HIJO"; then
    ok "un SUBPROCESO lanzado desde python hereda la capability (asi la usara el runner de B2)"
else
    fallo "el subproceso de python NO hereda CAP_NET_ADMIN" "${HIJO:0:200}"
fi

if [[ -f "$SUDOERS" && -f "$UNIDAD" ]]; then
    # Las dos opciones no se apilan: NoNewPrivileges anula el setuid de sudo.
    MEZCLA="$(en_unidad NoNewPrivileges=yes -- /usr/bin/sudo -n "$IPT" -S)"
    if grep -qE "$POLITICA" <<<"$MEZCLA"; then
        fallo "sudo funciona bajo NoNewPrivileges=yes" "contradice lo que documenta el ADR-0003; revisalo"
    else
        ok "bajo NoNewPrivileges=yes, sudo no escala (por eso USE_SUDO=false)"
    fi
fi

# --------------------------------------------------------------------------- #
seccion "7. El servicio"

if [[ -f "$UNIDAD" ]]; then
    # `verify` tambien escupe avisos benignos; solo cuentan los errores reales.
    VERIFICA="$(systemd-analyze verify firewall-dashboard.service 2>&1)"
    GRAVE="$(grep -iE 'error|failed|not found|invalid|unknown (lvalue|section)' <<<"$VERIFICA")"
    if [[ -z "$GRAVE" ]]; then
        ok "systemd-analyze verify sin errores${VERIFICA:+ (avisos: $(grep -c . <<<"$VERIFICA"))}"
    else
        fallo "systemd-analyze verify encuentra errores" "$GRAVE"
    fi

    if [[ -f "$CONF_FILE" ]] && grep -q '^USE_SUDO=true' "$CONF_FILE"; then
        fallo "USE_SUDO=true con la unidad instalada" "la unidad lleva NoNewPrivileges=yes: el sudo del runner devolvera EPERM"
    else
        ok "USE_SUDO=false: coherente con NoNewPrivileges=yes"
    fi

    ESTADO="$(systemctl is-active firewall-dashboard 2>&1)"
    if [[ "$ESTADO" == "active" ]]; then
        ok "el servicio esta activo"
    else
        fallo "el servicio no esta activo (is-active: $ESTADO)" "$(systemctl status firewall-dashboard --no-pager -n 15 2>&1 | tail -15)"
    fi

    PID="$(systemctl show -p MainPID --value firewall-dashboard 2>/dev/null)"
    if [[ -n "$PID" && "$PID" != "0" ]]; then
        DUENO_PROC="$(ps -o user= -p "$PID" | tr -d ' ')"
        if [[ "$DUENO_PROC" == "$USUARIO" ]]; then
            ok "el proceso corre como $USUARIO (pid $PID), no como root"
        else
            fallo "el proceso corre como '$DUENO_PROC'" "deberia ser $USUARIO"
        fi

        CAPEFF="$(awk '/^CapEff:/{print $2}' "/proc/$PID/status" 2>/dev/null)"
        DECODIFICADO="$(capsh --decode="$CAPEFF" 2>/dev/null)"
        if [[ "$DECODIFICADO" == *"cap_net_admin"* ]]; then
            ok "conjunto EFECTIVO del proceso: ${DECODIFICADO#*=}"
        else
            fallo "el proceso no tiene cap_net_admin efectiva (CapEff=$CAPEFF)" "$DECODIFICADO"
        fi

        NNP="$(awk '/^NoNewPrivs:/{print $2}' "/proc/$PID/status" 2>/dev/null)"
        if [[ "$NNP" == "1" ]]; then
            ok "NoNewPrivs activo en el proceso"
        else
            fallo "NoNewPrivs=$NNP en el proceso" "la unidad dice NoNewPrivileges=yes pero el kernel no lo refleja"
        fi
    else
        fallo "no hay proceso principal (MainPID=$PID)" "el servicio no llego a arrancar"
    fi

    if [[ -f "$CONF_FILE" ]]; then
        HOST="$(awk -F= '/^API_HOST=/{print $2}' "$CONF_FILE")"
        PUERTO="$(awk -F= '/^API_PORT=/{print $2}' "$CONF_FILE")"
        SALUD="$(curl -fsS --max-time 5 "http://$HOST:$PUERTO/health" 2>&1)"
        if [[ "$SALUD" == *'"firewall_backend"'* ]]; then
            ok "GET /health responde en $HOST:$PUERTO → ${SALUD:0:120}"
        else
            fallo "GET /health no responde en $HOST:$PUERTO" "${SALUD:0:200}"
        fi

        if [[ "$HOST" == "127.0.0.1" || "$HOST" == "localhost" ]]; then
            fallo "API_HOST=$HOST" "el frontend del Mac no llegara; bind a la IP de la interfaz de Multipass"
        else
            ok "API_HOST=$HOST (red host-only de Multipass, no expuesta a la LAN)"
        fi
    fi

    DB="$DATA_DIR/firewall.db"
    if [[ -s "$DB" ]] && [[ "$(stat -c %U "$DB")" == "$USUARIO" ]]; then
        TABLAS="$(runuser -u "$USUARIO" -- "$DEPLOY_DIR/backend/.venv/bin/python" -c \
            "import sqlite3;print(len(sqlite3.connect('$DB').execute(\"select name from sqlite_master where type='table'\").fetchall()))" 2>&1)"
        if [[ "$TABLAS" =~ ^[0-9]+$ ]] && (( TABLAS > 0 )); then
            ok "la DB es de $USUARIO y tiene $TABLAS tablas (alembic paso de verdad)"
        else
            fallo "la DB existe pero no se puede leer o esta vacia" "$TABLAS"
        fi
    else
        fallo "no hay DB utilizable en $DB" "propietario: $(stat -c %U "$DB" 2>/dev/null || echo 'no existe')"
    fi
else
    saltado "no instalada: $UNIDAD (opcion B no aplicada)"
fi

# --------------------------------------------------------------------------- #
echo
echo "================================================================"
printf " %sOK: %d%s   %sFALLOS: %d%s   %sSALTADOS: %d%s\n" \
    "$V" "$ACIERTOS" "$N" "$R" "$FALLOS" "$N" "$A" "$SALTADOS" "$N"
echo "================================================================"
if (( FALLOS > 0 )); then
    echo "B1 NO esta cerrado."
    exit 1
fi
if (( SALTADOS > 0 )); then
    echo "Sin fallos, pero hay comprobaciones saltadas: lee cuales antes de cerrar B1."
fi
echo "B1 verificado."
