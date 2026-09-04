#!/usr/bin/env bash
# =========================================================================== #
# b4_probe_vm.sh — mediciones DENTRO de la VM. Paso 0 de B4.
#
#   No lo lances a mano: lo transfiere y lo ejecuta `b4_probe_anchor.sh`.
#
# SOLO LECTURA. No ejecuta ni un `iptables -A`, ni un `-P`, ni un `-F`. Lo unico
# que hace es mirar: por donde ha entrado el proceso que lo esta ejecutando, que
# hay escuchando, y que sobreviviria a un reinicio.
#
# La pregunta que responde es la del RUNBOOK: **`multipass shell` / `multipass
# exec`, ¿pasan por la red de la VM?** Toda la seguridad del bloque B descansa en
# que la respuesta sea "no", y hasta hoy nadie la habia medido.
# =========================================================================== #
set -uo pipefail

V=$'\033[32m'; R=$'\033[31m'; A=$'\033[33m'; N=$'\033[0m'
[[ -t 1 ]] || { V=""; R=""; A=""; N=""; }

seccion() { printf "\n%s\n" "$1"; }
dato()    { printf "  %sDATO%s    %s\n" "$A" "$N" "$1"; }
ok()      { printf "  %sOK%s      %s\n" "$V" "$N" "$1"; }
mal()     { printf "  %sOJO%s     %s\n" "$R" "$N" "$1"; }

echo "--- dentro de la VM: $(hostname) · $(date -Iseconds) · uid=$(id -u) ---"

# --------------------------------------------------------------------------- #
seccion "V1. ¿Por donde ha entrado este proceso?"

# La cadena de ancestros hasta PID 1. Si `multipass exec` llega por SSH, en algun
# eslabon habra un sshd (en Ubuntu 24.04, OpenSSH 9.8 lo parte en `sshd-session`).
# Si llega fuera de banda, el ancestro sera un agente del hipervisor.
CADENA=""
pid=$$
for _ in $(seq 1 20); do
    comm="$(cat "/proc/$pid/comm" 2>/dev/null)" || break
    CADENA="${CADENA:+$CADENA <- }${comm}($pid)"
    [[ "$pid" == "1" ]] && break
    pid="$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null)"
    [[ -z "$pid" || "$pid" == "0" ]] && break
done
dato "cadena de ancestros: $CADENA"

if grep -qiE 'sshd' <<< "$CADENA"; then
    mal "hay un sshd en la cadena: este proceso ha ENTRADO POR SSH, es decir, POR LA RED"
    VEREDICTO_SSH="si"
else
    ok "no hay sshd en la cadena de ancestros"
    VEREDICTO_SSH="no"
fi

# Contraprueba de la comprobacion anterior: si la cadena no tiene sshd, hay que
# demostrar que el metodo SABE encontrar uno. Buscamos sshd en el sistema entero;
# si tampoco aparece ahi, la deteccion no probaba nada.
if pgrep -a sshd >/dev/null 2>&1; then
    ok "contraprueba: pgrep si encuentra procesos sshd en la maquina"
    dato "$(pgrep -a sshd | head -5 | tr '\n' ' | ')"
else
    mal "contraprueba fallida: no hay NINGUN sshd corriendo, la comprobacion de arriba no prueba nada"
fi

# --------------------------------------------------------------------------- #
seccion "V2. La conexion, vista desde el otro lado"

GW="$(ip route show default 2>/dev/null | awk '{print $3; exit}')"
IP_VM="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
CIDR_VM="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | head -1)"
dato "IP de la VM: ${IP_VM:-?}  ·  red: ${CIDR_VM:-?}  ·  gateway (= el Mac): ${GW:-?}"

SS22="$(ss -tnp state established '( sport = :22 )' 2>/dev/null | tail -n +2)"
if [[ -n "$SS22" ]]; then
    mal "hay conexiones SSH establecidas AHORA MISMO contra esta VM:"
    printf "          %s\n" "$SS22"
    PEER="$(awk '{print $4}' <<< "$SS22" | cut -d: -f1 | head -1)"
    if [[ -n "$GW" && "$PEER" == "$GW" ]]; then
        mal "y el otro extremo ($PEER) es el gateway: la sesion viene del Mac por la red"
    fi
else
    ok "no hay ninguna conexion establecida al puerto 22"
fi

# ¿Existe algun transporte fuera de banda por el que pudiera entrar multipass?
seccion "V3. ¿Hay de verdad un canal fuera de banda?"
VSOCK="$(ss --vsock 2>/dev/null | tail -n +2)"
if [[ -n "$VSOCK" ]]; then
    dato "sockets vsock activos: $(wc -l <<< "$VSOCK")"
else
    dato "sin sockets vsock (o este ss no los soporta)"
fi
PUERTOS_VIRTIO="$(ls /dev/virtio-ports/ 2>/dev/null | tr '\n' ' ')"
dato "puertos virtio: ${PUERTOS_VIRTIO:-ninguno}"
AGENTES="$(pgrep -a -f 'qemu-ga|multipass|cloud-init' 2>/dev/null | head -5 | tr '\n' ' | ')"
dato "agentes candidatos: ${AGENTES:-ninguno}"
dato "sshd escuchando en: $(ss -tlnp 2>/dev/null | awk '/:22 /{print $4}' | tr '\n' ' ')"

# La prueba documental: si multipassd habla por SSH, tiene que haber dejado su
# clave publica en el authorized_keys del usuario ubuntu. Es evidencia
# independiente de quien este conectado en este instante.
AK=/home/ubuntu/.ssh/authorized_keys
if [[ -r "$AK" ]]; then
    dato "authorized_keys de ubuntu: $(grep -c . "$AK") clave(s)"
    printf "          %s\n" "$(awk '{print $1, substr($2,1,20)"...", $3}' "$AK" | head -3)"
    mal "hay claves instaladas: el acceso de multipass esta preparado para ir por SSH"
else
    dato "no hay authorized_keys legible para ubuntu"
fi

# --------------------------------------------------------------------------- #
seccion "V4. Si el ancla es SSH, ¿que via de escape queda? (reiniciar)"

# iptables en memoria se pierde al reiniciar SALVO que algo lo restaure. Si nada
# lo restaura, `multipass restart` es una via de escape real y comprobable.
RESTAURADORES=""
dpkg -l 2>/dev/null | grep -qE '^ii\s+(iptables-persistent|netfilter-persistent)' \
    && RESTAURADORES="${RESTAURADORES} paquete-persistent"
[[ -e /etc/iptables/rules.v4 ]] && RESTAURADORES="${RESTAURADORES} /etc/iptables/rules.v4"
systemctl is-enabled netfilter-persistent >/dev/null 2>&1 \
    && RESTAURADORES="${RESTAURADORES} netfilter-persistent.service"
# ufw aparte: `is-enabled` dice si la UNIDAD arranca, no si ufw FILTRA. En Ubuntu
# viene habilitada de fabrica y con el firewall inactivo, asi que darla por
# restauradora es comprobar el nombre en vez del efecto -- el mismo error que en
# B3 costo un rojo sobre codigo correcto. Lo que decide es `ufw status`.
if systemctl is-enabled ufw >/dev/null 2>&1; then
    UFW_ESTADO="$(ufw status 2>/dev/null | head -1)"
    dato "unidad ufw habilitada; su estado real: ${UFW_ESTADO:-desconocido}"
    # Anclado: 'Status: inactive' contiene 'active' y un `grep -i active` da
    # ufw por encendido cuando esta apagado.
    if grep -qE '^[Ss]tatus:[[:space:]]*active' <<< "$UFW_ESTADO"; then
        RESTAURADORES="${RESTAURADORES} ufw(activo)"
    else
        ok "ufw esta habilitado pero INACTIVO: no restaura ninguna regla al arrancar"
    fi
fi

if [[ -z "$RESTAURADORES" ]]; then
    ok "nada restaura iptables al arrancar: un reinicio deja la VM con las cadenas vacias"
    dato "=> 'multipass restart firewall-lab' es una via de escape REAL aunque SSH este cortado"
else
    mal "hay algo que restaura reglas al arrancar:${RESTAURADORES}"
    dato "=> reiniciar NO garantiza recuperar el acceso. Revisalo antes de bloquearte"
fi

# ¿Y el servicio de la app? Si arranca solo y aplica reglas, el reinicio se anula solo.
if systemctl is-enabled firewall-dashboard >/dev/null 2>&1; then
    mal "firewall-dashboard esta HABILITADO: al reiniciar arranca y puede reaplicar la politica"
    dato "backend configurado: $(grep -h '^FIREWALL_BACKEND=' /etc/firewall-dashboard/backend.env 2>/dev/null || echo '?')"
    dato "auto_apply: $(grep -h '^AUTO_APPLY=' /etc/firewall-dashboard/backend.env 2>/dev/null || echo 'no definido (default true)')"
else
    ok "firewall-dashboard no esta habilitado al arranque"
fi

# --------------------------------------------------------------------------- #
seccion "V5. Estado actual del firewall (para saber de que partimos)"

for c in INPUT OUTPUT FORWARD; do
    dato "politica $c: $(iptables -S "$c" 2>/dev/null | awk -v c="$c" '$1=="-P" && $2==c {print $3}')"
done
CADENAS_FWDASH="$(iptables -S 2>/dev/null | awk '$1=="-N" && $2 ~ /^FWDASH_/ {print $2}' | tr '\n' ' ')"
dato "cadenas gestionadas presentes: ${CADENAS_FWDASH:-ninguna}"
dato "reglas totales en filter: $(iptables -S 2>/dev/null | grep -c '^-A')"

# --------------------------------------------------------------------------- #
seccion "V6. El CIDR de gestion, medido contra la red real"

ENV_CIDR="$(grep -h '^MANAGEMENT_ALLOWED_CIDR=' /etc/firewall-dashboard/backend.env 2>/dev/null | cut -d= -f2-)"
dato "MANAGEMENT_ALLOWED_CIDR desplegado: ${ENV_CIDR:-no definido}"
RED_REAL="$(echo "${IP_VM:-0.0.0.0}" | awk -F. '{print $1"."$2"."$3".0/24"}')"
dato "red real de esta VM (derivada de $IP_VM): $RED_REAL"
if [[ "$ENV_CIDR" == "$RED_REAL" ]]; then
    ok "coinciden: el guardian de gestion apunta a la subred donde esta el Mac"
else
    mal "NO coinciden: el guardian abriria el puerto a una subred que no es la tuya"
fi
if [[ "$ENV_CIDR" == "192.168.64.0/24" && "$RED_REAL" != "192.168.64.0/24" ]]; then
    mal "ademas es exactamente el default de config.py: nadie lo derivo de la interfaz"
fi

echo
echo "--- fin de las mediciones (ancla-por-ssh=$VEREDICTO_SSH) ---"
