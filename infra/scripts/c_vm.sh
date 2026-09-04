#!/usr/bin/env bash
# =========================================================================== #
# c_vm.sh — la mitad del bloque C que solo se puede hacer DENTRO de la VM.
#
#   No lo lances a mano: lo orquesta `c_verify.sh` desde el Mac.
#     uso: c_vm.sh <subcomando> [args]
#
# Subcomandos:
#   datos                     lo que hay ahora mismo. Solo lectura
#   admin-pass                imprime SOLO la contraseña del admin (no se loguea)
#   armar <segundos>          red de seguridad: backup + rescate por systemd-run
#   desarmar <unidad>         cancela el rescate
#   conmutar                  FIREWALL_BACKEND=iptables + reinicio del servicio  <-- C0
#   reiniciar                 systemctl restart y espera a que /health responda
#   cadena <INPUT|OUTPUT|FORWARD>   imprime la cadena gestionada
#   vaciar <INPUT|...>        `iptables -F` de la cadena gestionada             <-- C2
#   drift-anadir              mete una regla AJENA a mano en FWDASH_INPUT       <-- C3
#   drift-quitar <patron>     borra a mano la regla que case con el patron      <-- C3
#
# --------------------------------------------------------------------------- #
# LO QUE HACE PELIGROSO A ESTE SCRIPT, Y COMO SE ACOTA
#
# `conmutar` es el unico punto del proyecto donde una variable de entorno
# convierte una aplicacion que escribia en memoria en una que escribe reglas
# reales. A partir de ese reinicio, el servicio aplica la politica de la base de
# datos EL SOLO al arrancar (C2, ADR-0018). Por eso:
#
#   1. `armar` va SIEMPRE antes, y arma la reversion con `systemd-run`, fuera de
#      la sesion SSH que `multipass exec` sostiene. B4 midio que esa sesion es
#      hija de la conexion que la red mantiene: un rescate lanzado desde dentro
#      moriria con ella. (`--on-active` sin `--no-block`, ademas, no vuelve.)
#   2. `conmutar` COMPRUEBA que el CIDR de gestion del `.env` es el de la
#      interfaz de verdad y aborta si no lo es. Es el fallo del ADR-0016: un
#      CIDR valido pero falso escribe el guardian que te deja fuera, y ningun
#      validador de tipos puede verlo.
#   3. Nada se da por hecho por el codigo de salida: cada paso vuelve a LEER el
#      archivo o la cadena para comprobar el efecto.
# =========================================================================== #
set -uo pipefail

APP=/opt/firewall-dashboard
CONF=/etc/firewall-dashboard/backend.env
PANIC="$APP/infra/scripts/panic_reset.sh"
SERVICIO=firewall-dashboard
IPTABLES=/usr/sbin/iptables
PREFIJO=FWDASH
DIR_LOG=/var/log/c

[[ $EUID -eq 0 ]] || { echo "ERROR: se ejecuta como root (sudo)." >&2; exit 1; }
mkdir -p "$DIR_LOG"

registrar() { printf '%s  %s\n' "$(date -Iseconds)" "$*"; }

# Lee una clave del EnvironmentFile. Anclado al principio de linea: un
# `grep MANAGEMENT_PORT` casaria tambien con MANAGEMENT_SSH_PORT.
leer_conf() { sed -n "s/^$1=//p" "$CONF" | head -1; }

cidr_derivado() {
    local ip
    ip="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
    echo "$ip" | awk -F. '{print $1"."$2"."$3".0/24"}'
}

base_api() { echo "http://$(leer_conf API_HOST):$(leer_conf API_PORT)"; }

esperar_health() {
    local limite="${1:-45}" i=0 url
    url="$(base_api)/health"
    while (( i < limite )); do
        curl -fsS -o /dev/null --max-time 3 "$url" && return 0
        sleep 1; i=$((i+1))
    done
    return 1
}

cadena_de() {
    case "${1:-}" in
        INPUT|OUTPUT|FORWARD) echo "${PREFIJO}_$1" ;;
        *) echo "ERROR: cadena '${1:-}' no es INPUT, OUTPUT ni FORWARD" >&2; exit 1 ;;
    esac
}

# --------------------------------------------------------------------------- #
case "${1:-}" in

datos)
    echo "SERVICIO=$(systemctl is-active $SERVICIO 2>/dev/null)"
    echo "BACKEND=$(leer_conf FIREWALL_BACKEND)"
    echo "CIDR_ENV=$(leer_conf MANAGEMENT_ALLOWED_CIDR)"
    echo "CIDR_REAL=$(cidr_derivado)"
    echo "SSH_PORT=$(leer_conf MANAGEMENT_SSH_PORT)"
    echo "MGMT_PORT=$(leer_conf MANAGEMENT_PORT)"
    echo "AUTO_APPLY=$(leer_conf AUTO_APPLY)"
    echo "API=$(base_api)"
    echo "DESPLEGADO=$(cat $APP/.desplegado 2>/dev/null)"
    ;;

# Se imprime sola y sin adornos: quien la llama la mete en una variable, no en
# el log. No se registra en ningun sitio.
admin-pass)
    leer_conf BOOTSTRAP_ADMIN_PASSWORD
    ;;

armar)
    VENTANA="${2:?falta la ventana en segundos}"
    SELLO="$DIR_LOG/rescate.log"
    BACKUP_IPT="/root/c-antes-$(date +%Y%m%d-%H%M%S).rules"
    BACKUP_ENV="/root/c-backend.env-$(date +%Y%m%d-%H%M%S)"

    iptables-save > "$BACKUP_IPT" || { registrar "ABORTADO: iptables-save fallo"; exit 1; }
    cp -p "$CONF" "$BACKUP_ENV"
    registrar "backup: $BACKUP_IPT ($(grep -c . "$BACKUP_IPT") lineas) y $BACKUP_ENV"

    RESCATE=/root/c_rescate.sh
    cat > "$RESCATE" <<RESC
#!/usr/bin/env bash
# Generado por c_vm.sh. Lo lanza systemd, no la sesion: sobrevive a que la
# sesion muera, que es justo el modo de fallo del que hay que protegerse.
set -uo pipefail
echo "\$(date -Iseconds)  RESCATE: disparado" >> "$SELLO"
# 1. Acceso primero: politicas a ACCEPT y fuera las cadenas gestionadas.
bash "$PANIC" >> "$SELLO" 2>&1 || echo "\$(date -Iseconds)  RESCATE: panic fallo" >> "$SELLO"
iptables-restore < "$BACKUP_IPT" && echo "\$(date -Iseconds)  RESCATE: iptables restaurado" >> "$SELLO"
# 2. Y la causa: el .env vuelve a como estaba, asi que el servicio no puede
#    volver a escribir reglas reales al arrancar.
cp -p "$BACKUP_ENV" "$CONF" && echo "\$(date -Iseconds)  RESCATE: .env restaurado" >> "$SELLO"
chown root:fwdash "$CONF"; chmod 0640 "$CONF"
systemctl restart $SERVICIO >> "$SELLO" 2>&1
echo "\$(date -Iseconds)  RESCATE: terminado" >> "$SELLO"
RESC
    chmod +x "$RESCATE"

    UNIDAD="c-rescate-$(date +%s)"
    if ! systemd-run --unit="$UNIDAD" --on-active="$VENTANA" --timer-property=AccuracySec=1s \
            /bin/bash "$RESCATE" >/dev/null 2>&1; then
        registrar "ABORTADO: no se pudo armar el rescate. No se conmuta nada."
        exit 1
    fi
    # Que el comando no fallara no prueba que el temporizador exista.
    if systemctl list-timers --all --no-legend 2>/dev/null | grep -q "$UNIDAD"; then
        registrar "rescate armado y verificado: $UNIDAD dentro de ${VENTANA}s"
        echo "UNIDAD=$UNIDAD"
    else
        registrar "ABORTADO: el temporizador no aparece en list-timers."
        systemctl stop "$UNIDAD.timer" 2>/dev/null
        exit 1
    fi
    ;;

desarmar)
    UNIDAD="${2:?falta la unidad}"
    # `--no-block` no es adorno: `systemctl stop` espera a que el trabajo termine,
    # y si systemd tiene la cola ocupada se queda ahi. El 2026-09-04 colgo el
    # arnes entero hasta que salto el propio rescate que intentaba desarmar. Se
    # encola la parada y se comprueba el EFECTO, que es lo unico que importaba.
    systemctl stop --no-block "$UNIDAD.timer" 2>/dev/null
    systemctl stop --no-block "$UNIDAD.service" 2>/dev/null

    for _ in 1 2 3 4 5 6 7 8 9 10; do
        systemctl list-timers --all --no-legend 2>/dev/null | grep -q "$UNIDAD" || break
        sleep 1
    done

    if systemctl list-timers --all --no-legend 2>/dev/null | grep -q "$UNIDAD"; then
        registrar "AVISO: el temporizador $UNIDAD SIGUE armado a los 10s"
        systemctl list-timers --all --no-legend 2>/dev/null | grep "$UNIDAD" | sed 's/^/    /'
        exit 1
    fi
    registrar "rescate $UNIDAD desarmado y comprobado"
    ;;

conmutar)
    ACTUAL="$(leer_conf FIREWALL_BACKEND)"
    if [[ "$ACTUAL" == "iptables" ]]; then
        registrar "el .env ya decia FIREWALL_BACKEND=iptables: no se toca"
    else
        # ADR-0016. Lo primero, y aborta: un CIDR de gestion que no es el de la
        # interfaz escribe el guardian que abre el puerto a una red donde no hay
        # nadie, y el resultado es que la regla escrita para evitar el bloqueo es
        # la que lo provoca.
        ENV_CIDR="$(leer_conf MANAGEMENT_ALLOWED_CIDR)"
        REAL_CIDR="$(cidr_derivado)"
        if [[ "$ENV_CIDR" != "$REAL_CIDR" ]]; then
            registrar "ABORTADO: MANAGEMENT_ALLOWED_CIDR=$ENV_CIDR y la interfaz esta en $REAL_CIDR."
            registrar "           Corrigelo en $CONF antes de conmutar (ADR-0016)."
            exit 1
        fi
        registrar "CIDR de gestion comprobado contra la interfaz: $ENV_CIDR"

        # ADR-0017: el canal de rescate solo se protege si se declara. El .env de
        # esta VM se genero antes de que existiera la variable.
        if [[ -z "$(leer_conf MANAGEMENT_SSH_PORT)" ]]; then
            printf 'MANAGEMENT_SSH_PORT=22\n' >> "$CONF"
            registrar "añadido MANAGEMENT_SSH_PORT=22 (no estaba: .env anterior al ADR-0017)"
        fi

        # Con python3 y no con `sed -i`: sed -i recrea el archivo y le cambia
        # dueño y permisos, y este lleva el secreto JWT en 0640 root:fwdash.
        python3 - "$CONF" <<'PYFIN'
import re, sys
ruta = sys.argv[1]
with open(ruta, encoding="utf-8") as f:
    texto = f.read()
nuevo, n = re.subn(r"(?m)^FIREWALL_BACKEND=.*$", "FIREWALL_BACKEND=iptables", texto)
if n != 1:
    sys.exit(f"ERROR: se esperaba 1 linea FIREWALL_BACKEND y hay {n}")
with open(ruta, "w", encoding="utf-8") as f:
    f.write(nuevo)
PYFIN
        [[ $? -eq 0 ]] || { registrar "ABORTADO: no se pudo reescribir $CONF"; exit 1; }
        chown root:fwdash "$CONF"; chmod 0640 "$CONF"

        # El efecto, releido del archivo. No el codigo de salida de python.
        if [[ "$(leer_conf FIREWALL_BACKEND)" != "iptables" ]]; then
            registrar "ABORTADO: el .env sigue sin decir iptables"
            exit 1
        fi
        registrar "$CONF: FIREWALL_BACKEND=$ACTUAL -> iptables"
    fi

    systemctl restart "$SERVICIO"
    if esperar_health 45; then
        registrar "servicio reiniciado y respondiendo en $(base_api)/health"
    else
        registrar "ABORTADO: el servicio no responde tras el reinicio. El rescate esta armado."
        systemctl --no-pager -n 30 status "$SERVICIO" 2>&1 | sed 's/^/    /'
        exit 1
    fi
    ;;

reiniciar)
    systemctl restart "$SERVICIO"
    if esperar_health 45; then
        registrar "servicio reiniciado y respondiendo"
    else
        registrar "ERROR: el servicio no responde tras el reinicio"
        exit 1
    fi
    ;;

cadena)
    "$IPTABLES" -S "$(cadena_de "${2:-}")"
    ;;

vaciar)
    CAD="$(cadena_de "${2:-}")"
    ANTES="$("$IPTABLES" -S "$CAD" | grep -c '^-A' )"
    "$IPTABLES" -F "$CAD" || { registrar "ERROR: no se pudo vaciar $CAD"; exit 1; }
    DESPUES="$("$IPTABLES" -S "$CAD" | grep -c '^-A' )"
    registrar "$CAD vaciada a mano: $ANTES -> $DESPUES reglas"
    [[ "$DESPUES" -eq 0 ]] || { registrar "ERROR: $CAD no quedo vacia"; exit 1; }
    ;;

drift-anadir)
    # Contra TEST-NET (RFC 5737): no existe, asi que no corta nada de nadie.
    # Sin etiqueta `fwdash:`, que es lo que la hace AJENA a ojos del parser.
    "$IPTABLES" -A "${PREFIJO}_INPUT" -s 198.51.100.99/32 \
        -m comment --comment "c3-drift-a-mano" -j DROP \
        || { registrar "ERROR: no se pudo añadir la regla de drift"; exit 1; }
    if "$IPTABLES" -S "${PREFIJO}_INPUT" | grep -q 'c3-drift-a-mano'; then
        registrar "regla ajena añadida a mano en ${PREFIJO}_INPUT"
    else
        registrar "ERROR: la regla de drift no aparece en la cadena"; exit 1
    fi
    ;;

drift-quitar)
    PATRON="${2:?falta el patron}"
    CAD="${PREFIJO}_INPUT"
    # Por numero de linea de `-L --line-numbers` y no por `-D <regla>`: iptables
    # reescribe lo que se le da (ADR-0006), asi que reconstruir la regla para
    # borrarla es justo lo que no funciona.
    NUM="$("$IPTABLES" -L "$CAD" -n --line-numbers | awk -v p="$PATRON" '$0 ~ p {print $1; exit}')"
    if [[ -z "$NUM" ]]; then
        registrar "ERROR: no hay ninguna regla que case con '$PATRON' en $CAD"; exit 1
    fi
    "$IPTABLES" -D "$CAD" "$NUM" || { registrar "ERROR: no se pudo borrar la linea $NUM"; exit 1; }
    if "$IPTABLES" -L "$CAD" -n | grep -q "$PATRON"; then
        registrar "ERROR: la regla '$PATRON' sigue en $CAD"; exit 1
    fi
    registrar "borrada a mano la regla '$PATRON' (linea $NUM de $CAD)"
    ;;

*)
    echo "uso: c_vm.sh <datos|admin-pass|armar|desarmar|conmutar|reiniciar|cadena|vaciar|drift-anadir|drift-quitar>" >&2
    exit 1
    ;;
esac
