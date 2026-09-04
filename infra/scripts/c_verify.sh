#!/usr/bin/env bash
# =========================================================================== #
# c_verify.sh — arnes del BLOQUE C: la interconexion, de punta a punta
#
#   Ejecutar EN EL MAC, desde la raiz del repo:
#     bash infra/scripts/c_verify.sh | tee c.log
#
#   O bien:  make c-verify           (una fase suelta: make c-verify FASE=c3)
#
# ESTE ARNES MODIFICA REGLAS REALES y CONFIGURACION REAL de la VM: cambia
# `FIREWALL_BACKEND` a `iptables` en /etc/firewall-dashboard/backend.env, reinicia
# el servicio, crea y borra reglas por la API, y toca iptables a mano para
# provocar drift. Todo con la reversion ARMADA ANTES (c_vm.sh armar) y con
# limpieza al final. Pide confirmacion.
#
# --------------------------------------------------------------------------- #
# LAS CINCO FASES, Y QUE DEMUESTRA CADA UNA
#
#   C1  red        el Mac llega al 8000 de la VM y CORS deja pasar al frontend
#   C0  el cambio  FIREWALL_BACKEND=iptables: la aplicacion escribe de verdad
#   C2  arranque   se vacia la cadena a mano, se reinicia, y vuelve sola (ADR-0018)
#   C3  drift      se toca iptables a mano y la API lo señala; un apply lo arregla
#   C4  recorrido  regla creada por la API -> visible en `iptables -S` de la VM
#
# C1 va ANTES que C0 a proposito: es la unica fase que no modifica nada, y si el
# Mac no llega al 8000 con el backend `fake` tampoco va a llegar despues. Un
# fallo de red diagnosticado antes de conmutar es un fallo de red; diagnosticado
# despues, es media hora buscandolo en el sitio equivocado.
#
# --------------------------------------------------------------------------- #
# LO QUE ESTE ARNES SE NIEGA A HACER
#
# Van cinco trampas en este proyecto de la misma familia —comprobar el nombre y
# no el efecto—, cuatro de ellas DENTRO de arneses escritos para evitarla. Las
# reglas que salen de ahi, y que aqui se aplican:
#
#   · se comprueba el EFECTO (la regla esta en la cadena, el archivo dice X),
#     nunca el codigo de salida ni la palabra en un mensaje;
#   · cada patron trae pegada la entrada que lo engañaria, y se demuestra que no
#     lo engaña, ANTES de usarlo para afirmar nada;
#   · no se silencia el error de la fuente de datos: un `2>/dev/null` sobre
#     iptables convirtio un fallo en tres politicas vacias (B4);
#   · se mide en el momento en que el mecanismo actua, y las dos veces: "esto
#     falla ahora" no dice nada si no se ha demostrado antes que funcionaba.
# =========================================================================== #
set -uo pipefail

FASES_PEDIDAS="${1:-todas}"
VM="${VM:-firewall-lab}"
VENTANA="${VENTANA:-240}"          # segundos hasta el rescate automatico de C0
APP=/opt/firewall-dashboard
C_VM="$APP/infra/scripts/c_vm.sh"

V=$'\033[32m'; R=$'\033[31m'; A=$'\033[33m'; N=$'\033[0m'
[[ -t 1 ]] || { V=""; R=""; A=""; N=""; }
ACIERTOS=0; FALLOS=0
seccion() { printf "\n%s\n" "$1"; }
dato()    { printf "  %sDATO%s    %s\n" "$A" "$N" "$1"; }
ok()      { printf "  %sOK%s      %s\n" "$V" "$N" "$1"; ACIERTOS=$((ACIERTOS+1)); }
fallo()   { printf "  %sFALLO%s   %s\n" "$R" "$N" "$1"; FALLOS=$((FALLOS+1)); }

en_vm()      { multipass exec "$VM" -- "$@" </dev/null; }
en_vm_root() { multipass exec "$VM" -- sudo "$@" </dev/null; }
cvm()        { multipass exec "$VM" -- sudo bash "$C_VM" "$@" </dev/null; }

# macOS no trae `timeout`, y aqui hace falta: un servicio que no arranca deja el
# curl esperando, y un arnes que se cuelga no informa de nada.
con_limite() {
    local limite="$1"; shift
    "$@" >/tmp/c-limite.out 2>&1 & local pid=$!
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1; i=$((i+1))
        if (( i >= limite )); then kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; return 124; fi
    done
    wait "$pid"
}

# --------------------------------------------------------------------------- #
# Utilidades de JSON y de API
# --------------------------------------------------------------------------- #
campo() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null; }

TOKEN=""
api_get()  { curl -fsS --max-time 20 -H "Authorization: Bearer $TOKEN" "$API$1"; }
api_post() {
    curl -fsS --max-time 30 -X POST -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/json' -d "${2:-{\}}" "$API$1"
}
api_delete() {
    curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -X DELETE \
        -H "Authorization: Bearer $TOKEN" "$API$1"
}

# El estado del firewall, cacheado en una variable para no pedirlo dos veces por
# comprobacion. Devuelve 1 si no se pudo leer: una comprobacion sobre una
# respuesta vacia saldria "verde" con `grep -q` y no habria medido nada.
ESTADO=""
leer_estado() {
    ESTADO="$(api_get /firewall/status)" || { ESTADO=""; return 1; }
    [[ -n "$ESTADO" ]]
}
estado_campo() { printf '%s' "$ESTADO" | campo "$1"; }

echo "================================================================"
echo " BLOQUE C — la interconexion"
echo " $(date -Iseconds)  ·  $(hostname)  ·  VM=$VM  ·  ventana=${VENTANA}s"
echo "================================================================"

case "$FASES_PEDIDAS" in
    todas) FASES="c1 c0 c2 c3 c4" ;;
    c0|c1|c2|c3|c4) FASES="$FASES_PEDIDAS" ;;
    *) echo "uso: bash infra/scripts/c_verify.sh [todas|c0|c1|c2|c3|c4]" >&2; exit 1 ;;
esac
hace() { [[ " $FASES " == *" $1 "* ]]; }

# =========================================================================== #
seccion "0. Pre-vuelo (nada se modifica todavia)"
# =========================================================================== #

command -v multipass >/dev/null || { echo "ERROR: esto se ejecuta en el Mac." >&2; exit 1; }
[[ "$(multipass info "$VM" 2>/dev/null | awk '/^State:/{print $2}')" == "Running" ]] \
    || { echo "ERROR: la VM no esta corriendo." >&2; exit 1; }

IP_VM="$(multipass info "$VM" | awk '/IPv4/{print $2}')"
[[ "$IP_VM" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "ERROR: no se pudo leer la IP de la VM." >&2; exit 1; }
API="http://$IP_VM:8000/api/v1"
dato "IP de la VM: $IP_VM   ·   API: $API"

# El extractor de JSON, probado antes de usarlo para afirmar nada. Si `campo`
# devolviera siempre vacio, TODAS las comprobaciones de mas abajo dirian lo
# mismo que si el sistema estuviera roto -- y ninguna lo distinguiria.
if [[ "$(printf '{"a":{"b":7}}' | campo "d['a']['b']")" == "7" ]] \
   && [[ -z "$(printf 'no soy json' | campo "d['a']")" ]]; then
    ok "contraprueba: el extractor de JSON lee un valor anidado y falla en silencio con basura"
else
    echo "ERROR: python3 no puede leer JSON aqui. Sin eso este arnes no mide nada." >&2
    exit 1
fi

# iptables, SIN silenciar su error (leccion de B4).
SALIDA_IPT="$(en_vm_root iptables -S 2>&1)"; CODIGO_IPT=$?
if [[ $CODIGO_IPT -ne 0 || -z "$SALIDA_IPT" ]]; then
    echo "ERROR: iptables no responde dentro de la VM (codigo $CODIGO_IPT)." >&2
    echo "       $(head -1 <<< "$SALIDA_IPT")" >&2
    echo "       Diagnostico: make vm-diag-iptables" >&2
    exit 1
fi
ok "iptables responde en la VM ($(grep -c . <<< "$SALIDA_IPT") lineas)"

# ufw comparte INPUT con nosotros: si filtra, nada de lo que pase aqui es
# atribuible a este arnes. El patron va anclado y con contraprueba, porque
# 'Status: inactive' CONTIENE la palabra 'active' (trampa de B4).
UFW_ACTIVO='^[Ss]tatus:[[:space:]]*active'
if ! (grep -qE "$UFW_ACTIVO" <<< "Status: active" && ! grep -qE "$UFW_ACTIVO" <<< "Status: inactive"); then
    echo "ERROR: el patron de ufw no distingue activo de inactivo. No sigas." >&2; exit 1
fi
ok "contraprueba: el patron distingue 'Status: active' de 'Status: inactive'"
ESTADO_UFW="$(en_vm_root ufw status 2>/dev/null | head -1)"
REGLAS_UFW="$(grep -c '^-A ufw' <<< "$SALIDA_IPT")"
if grep -qE "$UFW_ACTIVO" <<< "$ESTADO_UFW" || [[ "${REGLAS_UFW:-0}" -gt 0 ]]; then
    echo "ERROR: ufw esta filtrando ('${ESTADO_UFW}', $REGLAS_UFW reglas ufw-*)." >&2
    exit 1
fi
ok "ufw no esta filtrando: lo que pase en INPUT es atribuible a este arnes"

# EL CODIGO QUE CORRE ES EL QUE SE ESCRIBIO. Dos comprobaciones distintas: el
# clon (donde estan los tests) y el DESPLIEGUE de /opt (lo que ejecuta el
# servicio, y por tanto quien tiene o no la reconciliacion de arranque de C2).
HEAD_MAC="$(git --no-optional-locks rev-parse HEAD)"
HEAD_VM="$(en_vm git -C /home/ubuntu/app rev-parse HEAD 2>/dev/null | tr -d '\r')"
if [[ "$HEAD_MAC" != "$HEAD_VM" ]]; then
    echo "ERROR: la VM tiene otro commit.  Mac: ${HEAD_MAC:0:12}  VM: ${HEAD_VM:0:12}" >&2
    echo "       Commitea y luego: make vm-sync" >&2
    exit 1
fi
ok "el clon de la VM esta en el mismo commit que el Mac (${HEAD_MAC:0:12})"

# Y lo que ese OK NO dice: dos maquinas pueden coincidir en un commit VIEJO. Si
# el codigo que se va a probar sigue sin commitear, la comparacion de arriba sale
# verde y la VM no tiene nada de lo nuevo. Paso la primera vez que se lanzo este
# arnes (2026-09-04): commit igual, y `c_vm.sh` sin desplegar.
SUCIO="$(git --no-optional-locks status --porcelain | grep -v '\.log$')"
if [[ -n "$SUCIO" ]]; then
    dato "hay cambios SIN COMMITEAR en el Mac. No viajan a la VM (ADR-0013):"
    sed 's/^/            /' <<< "$SUCIO"
    dato "  si alguno de esos es el codigo que quieres probar, commitealo y:"
    dato "  make vm-sync \&\& make vm-deploy"
fi

DESPLEGADO="$(en_vm cat "$APP/.desplegado" 2>/dev/null | tr -d '\r')"
if [[ "$DESPLEGADO" != "${HEAD_MAC:0:7}" ]]; then
    echo "ERROR: /opt tiene el commit '$DESPLEGADO' y el Mac ${HEAD_MAC:0:7}." >&2
    echo "       Lo que corre el servicio es /opt, no el clon:  make vm-deploy" >&2
    exit 1
fi
ok "el despliegue de /opt es el commit del Mac ($DESPLEGADO)"

if en_vm test -f "$C_VM"; then
    ok "presente en la VM: $C_VM"
else
    echo "ERROR: falta $C_VM en el despliegue." >&2
    if [[ -n "$SUCIO" ]]; then
        echo "       Y arriba hay cambios sin commitear: casi seguro es eso." >&2
    fi
    echo "       git commit ... && make vm-sync && make vm-deploy" >&2
    exit 1
fi

DATOS="$(cvm datos)"
BACKEND_ENV="$(awk -F= '/^BACKEND=/{print $2}' <<< "$DATOS")"
SERVICIO_ACTIVO="$(awk -F= '/^SERVICIO=/{print $2}' <<< "$DATOS")"
CIDR_ENV="$(awk -F= '/^CIDR_ENV=/{print $2}' <<< "$DATOS")"
CIDR_REAL="$(awk -F= '/^CIDR_REAL=/{print $2}' <<< "$DATOS")"
SSH_PORT="$(awk -F= '/^SSH_PORT=/{print $2}' <<< "$DATOS")"
MGMT_PORT="$(awk -F= '/^MGMT_PORT=/{print $2}' <<< "$DATOS")"
sed 's/^/          /' <<< "$DATOS"

[[ "$SERVICIO_ACTIVO" == "active" ]] \
    || { echo "ERROR: el servicio no esta activo en la VM ('$SERVICIO_ACTIVO')." >&2
         echo "       Arrancalo: multipass exec $VM -- sudo systemctl start firewall-dashboard" >&2; exit 1; }
ok "el servicio firewall-dashboard esta activo"

if [[ "$CIDR_ENV" == "$CIDR_REAL" ]]; then
    ok "el CIDR de gestion del .env es el de la interfaz ($CIDR_ENV)"
else
    echo "ERROR: MANAGEMENT_ALLOWED_CIDR=$CIDR_ENV y la interfaz esta en $CIDR_REAL." >&2
    echo "       Es el fallo del ADR-0016: el guardian abriria el puerto a una red vacia." >&2
    echo "       Corrigelo en /etc/firewall-dashboard/backend.env antes de seguir." >&2
    exit 1
fi

# La foto de la que dependen las contrapruebas de C0.
GUARDIANES_ANTES="$(grep -c 'fwdash:guardian' <<< "$SALIDA_IPT")"
dato "guardianes en iptables real ANTES de empezar: $GUARDIANES_ANTES"
dato "backend declarado en el .env de la VM: $BACKEND_ENV"

# La contraseña del admin se lee de la VM y NO se imprime en ningun sitio.
PASS_ADMIN="$(cvm admin-pass | tr -d '\r\n')"
[[ -n "$PASS_ADMIN" ]] || { echo "ERROR: no se pudo leer la contraseña del admin del .env." >&2; exit 1; }
CUERPO_LOGIN="$(curl -fsS --max-time 15 -X POST "$API/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$PASS_ADMIN\"}" 2>/dev/null)"
TOKEN="$(printf '%s' "$CUERPO_LOGIN" | campo "d['access_token']")"
if [[ -n "$TOKEN" ]]; then
    ok "login contra la API de la VM DESDE EL MAC: token obtenido"
else
    echo "ERROR: no se pudo hacer login en $API/auth/login desde el Mac." >&2
    echo "       Es lo primero que tiene que funcionar: sin token no hay bloque C." >&2
    exit 1
fi

echo
echo "  ${A}Lo que va a pasar en $VM (fases: $FASES):${N}"
hace c1 && echo "    C1  se apunta frontend/.env a $IP_VM (en el MAC, con copia de seguridad)"
hace c0 && echo "    C0  FIREWALL_BACKEND=iptables en el .env de la VM y REINICIO del servicio"
hace c0 && echo "        -> a partir de ahi la aplicacion escribe reglas REALES por su cuenta"
hace c2 && echo "    C2  se vacia FWDASH_INPUT a mano y se reinicia el servicio"
hace c3 && echo "    C3  se añade y se borra a mano una regla en FWDASH_INPUT"
hace c4 && echo "    C4  se crean y se borran reglas por la API (DROP contra TEST-NET)"
echo
echo "  La reversion se arma ANTES de conmutar y se dispara sola a los ${VENTANA}s"
echo "  si este arnes muere: panic_reset + iptables-restore + .env como estaba."
echo "  ${A}Ten a mano otra terminal con 'multipass shell $VM'.${N}"
echo
if [[ "${C_SIN_PREGUNTAR:-0}" != "1" ]]; then
    printf "  Escribe 'si' para continuar: "
    read -r respuesta
    [[ "$respuesta" == "si" ]] || { echo "  Cancelado. No se ha tocado nada."; exit 0; }
fi

# =========================================================================== #
if hace c1; then
seccion "C1. La red: del Mac a la VM, y del navegador al backend"
# =========================================================================== #

# 1. El Mac llega al 8000. El curl del arnes de B1 corria DENTRO de la VM: esto
#    es lo primero que sale de verdad de la maquina.
if curl -fsS --max-time 10 -o /dev/null "http://$IP_VM:8000/health"; then
    ok "el Mac llega a http://$IP_VM:8000/health"
else
    fallo "el Mac NO llega al 8000 de la VM: sin esto no hay nada que interconectar"
fi

if curl -fsS --max-time 10 -o /dev/null "$API/health"; then
    ok "y a la API versionada, $API/health"
else
    fallo "el /health versionado no responde"
fi

# 2. CORS. Lo que decide si el navegador deja al frontend leer la respuesta.
CABECERAS="$(curl -sS -D - -o /dev/null --max-time 10 \
    -H 'Origin: http://localhost:5173' "$API/health" 2>/dev/null | tr -d '\r')"
if grep -qi '^access-control-allow-origin: http://localhost:5173' <<< "$CABECERAS"; then
    ok "CORS devuelve el origen del frontend (http://localhost:5173)"
else
    fallo "CORS no autoriza a http://localhost:5173; el navegador bloqueara al frontend"
    sed 's/^/            /' <<< "$CABECERAS" | head -12
fi

# Contraprueba: un origen que NO esta en la lista no puede recibir la cabecera.
# Sin esta mitad, la de arriba pasaria igual con `allow_origins=["*"]`, que es
# una configuracion distinta y peor.
AJENO="$(curl -sS -D - -o /dev/null --max-time 10 \
    -H 'Origin: http://intruso.example' "$API/health" 2>/dev/null | tr -d '\r')"
if grep -qi '^access-control-allow-origin' <<< "$AJENO"; then
    fallo "CORS autoriza tambien a http://intruso.example: la lista no esta filtrando"
else
    ok "contraprueba: un origen ajeno NO recibe la cabecera de CORS"
fi

# 3. El preflight de una peticion con Authorization, que es la que hara la UI.
PREFLIGHT="$(curl -sS -D - -o /dev/null --max-time 10 -X OPTIONS "$API/rules" \
    -H 'Origin: http://localhost:5173' \
    -H 'Access-Control-Request-Method: POST' \
    -H 'Access-Control-Request-Headers: authorization,content-type' 2>/dev/null | tr -d '\r')"
if grep -qi '^access-control-allow-origin: http://localhost:5173' <<< "$PREFLIGHT" \
   && grep -qi '^access-control-allow-headers:.*authorization' <<< "$PREFLIGHT"; then
    ok "el preflight de POST /rules con Authorization pasa"
else
    fallo "el preflight de POST /rules NO pasa: la UI podra leer pero no escribir"
    sed 's/^/            /' <<< "$PREFLIGHT" | head -12
fi

# 4. Apuntar el frontend a la VM. Es un archivo del MAC, no versionado, y se
#    guarda copia: es lo unico de este arnes que toca el repo de Mario.
ENV_FRONT="frontend/.env"
DESTINO="VITE_API_BASE_URL=http://$IP_VM:8000/api/v1"
if [[ -f "$ENV_FRONT" ]] && grep -qxF "$DESTINO" "$ENV_FRONT"; then
    ok "frontend/.env ya apunta a la VM ($DESTINO)"
else
    [[ -f "$ENV_FRONT" ]] && cp "$ENV_FRONT" "$ENV_FRONT.antes-de-c1"
    cat > "$ENV_FRONT" <<ENVFIN
# Apuntado al backend de la VM por infra/scripts/c_verify.sh (paso C1).
# La IP de Multipass NO es fija: si la VM cambia de IP, 'make c-verify FASE=c1'
# vuelve a escribir este archivo. La copia anterior esta en .env.antes-de-c1.
$DESTINO
ENVFIN
    if grep -qxF "$DESTINO" "$ENV_FRONT"; then
        ok "frontend/.env apuntado a la VM ($DESTINO)"
        dato "reinicia 'make dev-frontend': Vite lee el .env al arrancar, no en caliente"
    else
        fallo "no se pudo escribir $ENV_FRONT"
    fi
fi
fi

# =========================================================================== #
if hace c0; then
seccion "C0. El interruptor: FIREWALL_BACKEND=iptables"
# =========================================================================== #

# 1. VER ANTES DE EJECUTAR. El preview es la mitigacion nº2 del auto-bloqueo y
#    aqui es literalmente eso: la lista de comandos que el servicio lanzara solo,
#    en cuanto se reinicie con el backend real (C2, ADR-0018).
PREVIEW="$(api_get /firewall/preview)"
if [[ -z "$PREVIEW" ]]; then
    fallo "no se pudo leer /firewall/preview: no se conmuta a ciegas"
else
    COMANDOS="$(printf '%s' "$PREVIEW" | campo "'\n'.join(c for ch in d['chains'] for c in ch['commands'])")"
    dato "$(grep -c . <<< "$COMANDOS") comandos se ejecutarian al reconciliar:"
    sed 's/^/            /' <<< "$COMANDOS"

    # Detector de lo unico que no se puede permitir: que la politica guardada
    # cierre el puerto de gestion o el canal de rescate. En python y no con
    # `grep` porque hay dos cosas que grep no sabe hacer y que aqui importan:
    # un puerto puede venir como RANGO (`8000:8010`, que el validador acepta) y
    # un `-s` acota a quien afecta la regla. Una regla es peligrosa si descarta,
    # puede alcanzar un puerto protegido, y su origen se solapa con la red de
    # gestion. Las tres condiciones a la vez.
    # El programa va a un archivo y NO a un heredoc: con `python3 - <<'FIN'`
    # el heredoc ES el stdin de python, asi que las lineas que se le pasan por
    # la tuberia no llegarian nunca a `sys.stdin` y el detector no veria nada.
    # Lo cazo su propia contraprueba, que es justo para lo que esta.
    # Con plantilla explicita: `mktemp -t nombre` vale en BSD y falla en GNU.
    DETECTOR="$(mktemp "${TMPDIR:-/tmp}/c-detector.XXXXXX")"
    cat > "$DETECTOR" <<'PYFIN'
import ipaddress
import os
import re
import sys

PROTEGIDOS = {int(p) for p in os.environ["PUERTOS"].split(",") if p.strip()}
GESTION = ipaddress.ip_network(os.environ["CIDR_GESTION"], strict=False)


def alcanza_puerto_protegido(linea: str) -> bool:
    encontrado = re.search(r"--dport (\S+)", linea)
    if encontrado is None:
        return True                      # sin puerto, los alcanza todos
    valor = encontrado.group(1)
    try:
        if ":" in valor:
            inicio, fin = (int(x) for x in valor.split(":", 1))
            return any(inicio <= p <= fin for p in PROTEGIDOS)
        return int(valor) in PROTEGIDOS
    except ValueError:
        return True                      # ilegible: se avisa, no se ignora


def alcanza_la_red_de_gestion(linea: str) -> bool:
    encontrado = re.search(r"(?:^| )-s (\S+)", linea)
    if encontrado is None:
        return True                      # sin origen, cualquiera
    try:
        return ipaddress.ip_network(encontrado.group(1), strict=False).overlaps(GESTION)
    except ValueError:
        return True


for cruda in sys.stdin:
    linea = cruda.rstrip("\n")
    if not linea or not re.search(r"-j (DROP|REJECT)(\s|$)", linea):
        continue
    if alcanza_puerto_protegido(linea) and alcanza_la_red_de_gestion(linea):
        print(linea)
PYFIN
    peligrosas() { CIDR_GESTION="$CIDR_ENV" PUERTOS="${MGMT_PORT:-8000}${SSH_PORT:+,$SSH_PORT}" \
                       python3 "$DETECTOR"; }

    # La contraprueba: seis lineas por las que se sabe la respuesta, y el
    # detector tiene que separar exactamente las tres primeras. Un detector que
    # no se ha probado contra lo que le engaña no es una comprobacion, y este
    # decide si se conmuta o no.
    CASOS_PELIGROSOS=$'-A FWDASH_INPUT -p tcp --dport '"${MGMT_PORT:-8000}"$' -j DROP\n-A FWDASH_INPUT -p tcp --dport 7999:8005 -j REJECT\n-A FWDASH_INPUT -s '"$CIDR_ENV"$' -j DROP'
    CASOS_SEGUROS=$'-A FWDASH_INPUT -p tcp --dport 9001 -j DROP\n-A FWDASH_INPUT -p tcp --dport '"${MGMT_PORT:-8000}"$' -j ACCEPT\n-A FWDASH_INPUT -s 198.51.100.0/24 -p tcp --dport '"${MGMT_PORT:-8000}"$' -j DROP'
    DETECTADOS="$(printf '%s\n%s\n' "$CASOS_PELIGROSOS" "$CASOS_SEGUROS" | peligrosas)"
    if [[ "$DETECTADOS" == "$CASOS_PELIGROSOS" ]]; then
        ok "contraprueba: el detector separa las 3 peligrosas de las 3 seguras (rango y -s incluidos)"
    else
        fallo "el detector de reglas peligrosas no separa lo que debe. No se conmuta:"
        sed 's/^/            /' <<< "$DETECTADOS"
        exit 1
    fi

    ENCONTRADAS="$(printf '%s' "$COMANDOS" | peligrosas)"
    if [[ -n "$ENCONTRADAS" ]]; then
        fallo "la politica guardada podria cerrar el puerto de gestion o el de rescate:"
        sed 's/^/            /' <<< "$ENCONTRADAS"
        echo "  NO se conmuta. Borralas o desactivalas por la API y vuelve a lanzar." >&2
        echo "  (Los guardianes van los primeros y deberian ganarles, pero eso es" >&2
        echo "   justo lo que no conviene estar comprobando con el acceso puesto.)" >&2
        exit 1
    fi
    ok "ninguna regla guardada alcanza los puertos ${MGMT_PORT:-8000}${SSH_PORT:+ y $SSH_PORT} desde $CIDR_ENV"
fi

# 2. La red de seguridad, ARMADA ANTES.
SALIDA_ARMAR="$(cvm armar "$VENTANA")"
UNIDAD="$(awk -F= '/^UNIDAD=/{print $2}' <<< "$SALIDA_ARMAR")"
sed 's/^/          /' <<< "$SALIDA_ARMAR"
if [[ -n "$UNIDAD" ]]; then
    ok "reversion armada y verificada en list-timers ($UNIDAD, ${VENTANA}s)"
else
    fallo "no se pudo armar la reversion: no se conmuta nada"; exit 1
fi

# 3. El cambio.
SALIDA_CONMUTAR="$(cvm conmutar)"; CODIGO_CONMUTAR=$?
sed 's/^/          /' <<< "$SALIDA_CONMUTAR"
if [[ $CODIGO_CONMUTAR -ne 0 ]]; then
    fallo "la conmutacion fallo. La reversion se disparara sola en menos de ${VENTANA}s."
    exit 1
fi
ok "el .env dice iptables y el servicio ha vuelto a responder"

# 4. EL EFECTO, y no que el comando no fallara. Tres medidas independientes.
if leer_estado; then
    BACKEND_VIVO="$(estado_campo "d['backend']")"
    SCAFFOLD="$(estado_campo "d['scaffold_ok']")"
    if [[ "$BACKEND_VIVO" == "iptables" ]]; then
        ok "la API dice que el backend en uso es 'iptables' (no lo que diga el archivo)"
    else
        fallo "la API sigue diciendo backend='$BACKEND_VIVO'"
    fi
    [[ "$SCAFFOLD" == "True" ]] && ok "scaffold_ok: las tres cadenas gestionadas existen y se leen" \
                                || fallo "scaffold_ok=$SCAFFOLD: alguna cadena no se pudo leer"
else
    fallo "no se pudo leer /firewall/status tras conmutar"
fi

# La prueba que no depende de que la aplicacion se crea a si misma: las reglas
# guardian, escritas por el SERVICIO, en el iptables de VERDAD del kernel.
CADENA_INPUT="$(cvm cadena INPUT)"
GUARDIANES_AHORA="$(grep -c 'fwdash:guardian' <<< "$CADENA_INPUT")"
if [[ "${GUARDIANES_AHORA:-0}" -ge 3 ]]; then
    ok "los guardianes estan en el iptables real de la VM ($GUARDIANES_AHORA en FWDASH_INPUT)"
    sed 's/^/            /' <<< "$CADENA_INPUT"
else
    fallo "no hay guardianes en FWDASH_INPUT: el servicio no ha escrito nada real"
    sed 's/^/            /' <<< "$CADENA_INPUT"
fi
if [[ "${GUARDIANES_ANTES:-0}" -eq 0 ]]; then
    ok "contraprueba: antes de conmutar NO habia ninguna regla fwdash:guardian en el kernel"
else
    dato "ya habia $GUARDIANES_ANTES guardianes antes de empezar (el .env ya estaba en iptables):"
    dato "  la comparacion antes/despues no dice nada en esta ejecucion, y no se cuenta como OK"
fi

# Y el guardian del canal de rescate solo si esta declarado (ADR-0017).
if [[ -n "$SSH_PORT" ]]; then
    grep -q 'fwdash:guardian:ssh' <<< "$CADENA_INPUT" \
        && ok "MANAGEMENT_SSH_PORT=$SSH_PORT declarado y su guardian esta puesto" \
        || fallo "MANAGEMENT_SSH_PORT=$SSH_PORT declarado pero no hay guardian de rescate"
else
    dato "MANAGEMENT_SSH_PORT no declarado: el 22 es filtrable como cualquier puerto (ADR-0017)"
fi

# 5. La huella de auditoria del arranque. LOG_LEVEL=INFO existe para esto.
JOURNAL="$(en_vm_root journalctl -u firewall-dashboard -n 80 --no-pager 2>/dev/null)"
grep -q 'politica_reconciliada' <<< "$JOURNAL" \
    && ok "el journal registra 'politica_reconciliada': el arranque aplico la politica (C2)" \
    || dato "no aparece 'politica_reconciliada' en el journal reciente"

# 6. Desarmar: ya no hace falta la red, y dejarla armada reiniciaria el servicio
#    a mitad de las fases siguientes.
if cvm desarmar "$UNIDAD" >/dev/null; then
    ok "reversion desarmada (comprobado en list-timers)"
else
    fallo "la reversion NO se pudo desarmar: se disparara sola. Para y mira."
fi

FOTO_C0="$(en_vm_root iptables -S 2>&1)"
dato "foto de referencia tomada tras C0 ($(grep -c . <<< "$FOTO_C0") lineas)"
fi

# --------------------------------------------------------------------------- #
# Las fases siguientes solo significan algo contra el backend real.
# --------------------------------------------------------------------------- #
if hace c2 || hace c3 || hace c4; then
    if leer_estado && [[ "$(estado_campo "d['backend']")" == "iptables" ]]; then
        :
    else
        echo "ERROR: el backend en uso no es 'iptables'. C2, C3 y C4 medirian el fake." >&2
        echo "       Lanza antes la fase C0:  make c-verify FASE=c0" >&2
        exit 1
    fi
fi

CREADAS=()   # uuids que hay que borrar al terminar, pase lo que pase
limpiar_reglas() {
    local uuid
    for uuid in "${CREADAS[@]:-}"; do
        [[ -n "$uuid" ]] && api_delete "/rules/$uuid" >/dev/null
    done
}
trap limpiar_reglas EXIT

crear_regla() { # nombre, puerto, ip  ->  imprime el uuid
    api_post /rules "{\"name\":\"$1\",\"chain\":\"INPUT\",\"action\":\"DROP\",
        \"protocol\":\"tcp\",\"dst_port\":\"$2\",\"src_ip\":\"$3\"}" | campo "d['uuid']"
}

# =========================================================================== #
if hace c2; then
seccion "C2. Reiniciar no pierde el firewall (ADR-0018)"
# =========================================================================== #

UUID_C2="$(crear_regla 'c-verify C2 sobrevive al reinicio' 9001 198.51.100.20)"
if [[ -n "$UUID_C2" ]]; then
    CREADAS+=("$UUID_C2"); ok "regla creada por la API: ${UUID_C2:0:8}"
else
    fallo "no se pudo crear la regla de C2"; UUID_C2=""
fi

if [[ -n "$UUID_C2" ]]; then
    CORTO="${UUID_C2:0:8}"
    # Medida 1: esta puesta. Con auto-apply, crearla ya la aplica.
    cvm cadena INPUT | grep -q "fwdash:$CORTO" \
        && ok "la regla esta en el iptables real antes de tocar nada" \
        || fallo "la regla no llego a iptables: C2 no se puede medir"

    # Medida 2: se vacia a mano. Es el estado en el que queda la cadena tras un
    # reinicio de la VM -- solo que provocado, y sin esperar a reiniciarla.
    sed 's/^/          /' <<< "$(cvm vaciar INPUT)"
    if cvm cadena INPUT | grep -q "fwdash:$CORTO"; then
        fallo "la cadena no se vacio: lo que venga despues no significa nada"
    else
        ok "FWDASH_INPUT vacia: ni la regla ni los guardianes estan ya en el kernel"
    fi

    # Medida 3: el mecanismo, en el momento en que actua. Nadie llama a /apply.
    sed 's/^/          /' <<< "$(cvm reiniciar)"
    CADENA_TRAS_REINICIO="$(cvm cadena INPUT)"
    if grep -q "fwdash:$CORTO" <<< "$CADENA_TRAS_REINICIO"; then
        ok "tras el reinicio la regla ha VUELTO sola: el arranque reconcilia"
    else
        fallo "la regla no volvio al reiniciar: la reconciliacion de arranque no funciona"
        sed 's/^/            /' <<< "$CADENA_TRAS_REINICIO"
    fi
    [[ "$(grep -c 'fwdash:guardian' <<< "$CADENA_TRAS_REINICIO")" -ge 3 ]] \
        && ok "y los guardianes tambien: el puerto de gestion no queda desprotegido" \
        || fallo "los guardianes no volvieron tras el reinicio"

    if leer_estado; then
        [[ "$(estado_campo "d['has_drift']")" == "False" ]] \
            && ok "y la API considera el estado limpio: has_drift=false" \
            || fallo "tras reconciliar sigue habiendo drift: $(estado_campo "d['chains']")"
    fi
fi
fi

# =========================================================================== #
if hace c3; then
seccion "C3. Drift real: tocar iptables a mano y que la aplicacion lo diga"
# =========================================================================== #

# La contraprueba va PRIMERO y es imprescindible: 'ahora hay drift' no significa
# nada si no se ha demostrado que un momento antes no lo habia.
if leer_estado && [[ "$(estado_campo "d['has_drift']")" == "False" ]]; then
    ok "contraprueba: antes de tocar nada, has_drift=false"
else
    fallo "ya habia drift antes de empezar C3: la fase no puede atribuirse nada"
fi

# 1. Una regla AJENA, metida por fuera de la aplicacion.
sed 's/^/          /' <<< "$(cvm drift-anadir)"
if leer_estado; then
    HAY="$(estado_campo "d['has_drift']")"
    SOBRAN="$(estado_campo "sum(len(c['unexpected']) for c in d['chains'])")"
    if [[ "$HAY" == "True" && "${SOBRAN:-0}" -ge 1 ]]; then
        ok "la API detecta el drift: has_drift=true y $SOBRAN linea(s) en 'unexpected'"
        printf '%s' "$ESTADO" | campo "'\n'.join(u for c in d['chains'] for u in c['unexpected'])" \
            | sed 's/^/            /'
    else
        fallo "la regla ajena no se detecto (has_drift=$HAY, unexpected=$SOBRAN)"
    fi
fi

# 2. Y al reves: quitar a mano una regla que si es nuestra.
if [[ -n "${UUID_C2:-}" ]]; then
    CORTO="${UUID_C2:0:8}"
    sed 's/^/          /' <<< "$(cvm drift-quitar "fwdash:$CORTO")"
    if leer_estado; then
        FALTAN="$(estado_campo "sum(len(c['missing']) for c in d['chains'])")"
        [[ "${FALTAN:-0}" -ge 1 ]] \
            && ok "la API tambien ve lo que FALTA: $FALTAN regla(s) en 'missing'" \
            || fallo "borrar una regla a mano no aparece como 'missing'"
    fi
    # Y la fila, en la base de datos, tiene que haber cambiado de estado.
    SYNC="$(api_get "/rules/$UUID_C2" | campo "d['sync_state']")"
    [[ "$SYNC" == "drift" ]] \
        && ok "la fila de la regla pasa a sync_state=drift" \
        || fallo "la fila sigue en sync_state='$SYNC' con la cadena descuadrada"
fi

# 3. Un apply reconstruye: la base de datos gana siempre (ADR-0001).
if api_post /firewall/apply >/dev/null; then
    if leer_estado && [[ "$(estado_campo "d['has_drift']")" == "False" ]]; then
        ok "un apply devuelve el estado a limpio: has_drift=false"
    else
        fallo "despues del apply sigue habiendo drift"
    fi
    cvm cadena INPUT | grep -q 'c3-drift-a-mano' \
        && fallo "la regla ajena SIGUE en la cadena tras reconstruirla" \
        || ok "la regla ajena ha desaparecido: reconstruir es vaciar y volver a escribir"
    if [[ -n "${UUID_C2:-}" ]]; then
        cvm cadena INPUT | grep -q "fwdash:${UUID_C2:0:8}" \
            && ok "y la regla que se habia borrado a mano ha vuelto" \
            || fallo "la regla borrada a mano no volvio con el apply"
        SYNC="$(api_get "/rules/$UUID_C2" | campo "d['sync_state']")"
        [[ "$SYNC" == "applied" ]] && ok "la fila vuelve a sync_state=applied" \
                                   || fallo "la fila se quedo en '$SYNC'"
    fi
else
    fallo "POST /firewall/apply fallo"
fi
fi

# =========================================================================== #
if hace c4; then
seccion "C4. El recorrido completo: de la API del Mac al kernel de la VM"
# =========================================================================== #

# Es el mismo camino que hace la UI: navegador -> HTTP -> FastAPI -> renderer ->
# runner -> iptables. Lo unico que cambia es quien escribe el JSON.
UUID_C4="$(crear_regla 'c-verify C4 recorrido completo' 9002 198.51.100.21)"
if [[ -z "$UUID_C4" ]]; then
    fallo "no se pudo crear la regla de C4"
else
    CREADAS+=("$UUID_C4")
    CORTO4="${UUID_C4:0:8}"
    ESTADO_ALTA="$(api_get "/rules/$UUID_C4" | campo "d['sync_state']")"
    [[ "$ESTADO_ALTA" == "applied" ]] \
        && ok "la regla nace 'applied': el auto-apply la ha llevado al firewall" \
        || fallo "la regla quedo en '$ESTADO_ALTA' (esperado 'applied')"

    LINEA="$(cvm cadena INPUT | grep -- "fwdash:$CORTO4")"
    if [[ -n "$LINEA" ]] && grep -q -- '--dport 9002' <<< "$LINEA" && grep -q -- '-j DROP' <<< "$LINEA"; then
        ok "la regla creada por HTTP esta en el iptables real, con su puerto y su accion:"
        sed 's/^/            /' <<< "$LINEA"
    else
        fallo "la regla no aparece completa en FWDASH_INPUT"
        cvm cadena INPUT | sed 's/^/            /'
    fi

    # Contraprueba del metodo de busqueda: un uuid que nadie creo no puede
    # aparecer. Sin esto, un `grep` que casara con cualquier cosa daria OK igual.
    cvm cadena INPUT | grep -q 'fwdash:00000000' \
        && fallo "el metodo encuentra un uuid inventado: no estaba midiendo nada" \
        || ok "contraprueba: el mismo metodo NO encuentra un uuid que nadie ha creado"

    # Y la vuelta: borrar en la API tiene que quitarlo del kernel.
    CODIGO="$(api_delete "/rules/$UUID_C4")"
    if [[ "$CODIGO" == "204" ]]; then
        cvm cadena INPUT | grep -q "fwdash:$CORTO4" \
            && fallo "la regla borrada por la API sigue en iptables" \
            || ok "borrarla por la API la quita tambien del kernel"
        CREADAS=("${CREADAS[@]/$UUID_C4}")
    else
        fallo "DELETE /rules/$CORTO4 devolvio $CODIGO"
    fi
fi
fi

# =========================================================================== #
seccion "Limpieza y estado final"
# =========================================================================== #

# Solo hay algo que limpiar si alguna fase creo reglas. En una ejecucion de C1
# suelta —`make c-front`— aplicar aqui seria un efecto secundario que nadie pidio.
if hace c2 || hace c3 || hace c4; then
    limpiar_reglas
    trap - EXIT
    CREADAS=()
    api_post /firewall/apply >/dev/null && ok "reglas del arnes borradas y politica reaplicada" \
        || fallo "no se pudo reaplicar tras la limpieza"

    RESTOS="$(api_get '/rules?size=200' | campo "sum(1 for r in d['items'] if r['name'].startswith('c-verify'))")"
    [[ "${RESTOS:-0}" -eq 0 ]] && ok "no queda ninguna regla 'c-verify' en la base de datos" \
                               || fallo "quedan $RESTOS reglas 'c-verify' sin borrar"
else
    trap - EXIT
    dato "esta ejecucion no creo reglas: no hay nada que limpiar"
fi

FINAL="$(en_vm_root iptables -S 2>&1)"
if [[ -z "$FINAL" ]]; then
    fallo "no se pudo leer la politica final: el estado queda SIN MEDIR"
elif [[ -n "${FOTO_C0:-}" ]]; then
    if diff -u <(printf '%s\n' "$FOTO_C0") <(printf '%s\n' "$FINAL") > /tmp/c-diff.txt; then
        ok "la tabla filter esta igual que justo despues de C0"
    else
        fallo "la tabla filter no volvio a como estaba tras C0:"
        sed 's/^/            /' /tmp/c-diff.txt
    fi
else
    dato "sin foto de C0 en esta ejecucion: no se compara el estado final"
fi
grep -q 'c3-drift-a-mano' <<< "$FINAL" \
    && fallo "queda en el sistema la regla ajena que sembro C3" \
    || ok "no queda rastro de las reglas que sembro el arnes"

# =========================================================================== #
seccion "Resumen"
printf "  %d OK · %d FALLOS\n\n" "$ACIERTOS" "$FALLOS"
if [[ $FALLOS -eq 0 ]]; then
    echo "  Las tres capas estan conectadas y medidas: navegador -> API -> iptables."
    echo "  Queda C5: capturas, SECURITY.md y el tag v0.1.0-mvp."
fi
exit $(( FALLOS > 0 ? 1 : 0 ))
