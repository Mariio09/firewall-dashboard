#!/usr/bin/env bash
# =========================================================================== #
# recon_seed.sh — carga un ruleset representativo para el paso A2
#
#   Ejecutar DENTRO de la VM firewall-lab:
#     sudo bash /tmp/recon_seed.sh          # cargar
#     sudo bash /tmp/recon_seed.sh reset    # deshacer
#
#   Desde el host se lanza solo, dentro de `make recon`.
#
# POR QUE EXISTE
# Una VM recien creada tiene las tres cadenas vacias y las politicas en ACCEPT.
# Esa salida se parsea con cuatro lineas y no ejercita nada: ni el modulo
# conntrack, ni multiport, ni los rangos de puertos, ni las negaciones, ni el
# `--log-prefix` con espacios, ni los contadores con sufijo K/M. Escribir el
# parser contra eso es exactamente el fallo que A2 pretende evitar.
#
# POR QUE ES SEGURO
# Ninguna regla de este script puede dejarte fuera de la VM:
#
#   - FWDASH_INPUT se crea CON todas sus reglas, incluida la DROP final, pero
#     NO se engancha a INPUT. El parser solo ve texto: la linea es identica
#     este la cadena colgada o no, y asi no hay forma de cortar la sesion.
#   - FWDASH_OUTPUT si se engancha, porque solo contiene ACCEPT y RETURN.
#   - FWDASH_FORWARD se engancha y termina en DROP: la VM no enruta nada, de
#     modo que FORWARD esta vacia de trafico. Igual que la politica -P FORWARD
#     DROP, que es la unica politica que se cambia.
#   - Las politicas de INPUT y OUTPUT no se tocan.
#
# Y como no se instala iptables-persistent, un `multipass restart firewall-lab`
# devuelve la VM a cero. Esa es la red de seguridad de verdad.
# =========================================================================== #
set -euo pipefail

IPT="${IPTABLES_BIN:-/usr/sbin/iptables}"
MARCA="recon-a2"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: hay que ejecutarlo como root (usa sudo)." >&2
    exit 1
fi

# --------------------------------------------------------------------------- #
# reset
# --------------------------------------------------------------------------- #
if [[ "${1:-}" == "reset" ]]; then
    echo "=== recon_seed: deshaciendo ==="
    "$IPT" -P FORWARD ACCEPT
    for c in INPUT OUTPUT FORWARD; do
        while "$IPT" -C "$c" -j "FWDASH_$c" 2>/dev/null; do
            "$IPT" -D "$c" -j "FWDASH_$c"
        done
    done
    # Las dos reglas contadoras, reconocibles por su comentario.
    "$IPT" -D OUTPUT -o lo -p icmp -m comment --comment "$MARCA:contador" -j ACCEPT 2>/dev/null || true
    "$IPT" -D INPUT  -i lo -p icmp -m comment --comment "$MARCA:contador" -j ACCEPT 2>/dev/null || true
    for c in INPUT OUTPUT FORWARD; do
        if "$IPT" -L "FWDASH_$c" -n >/dev/null 2>&1; then
            "$IPT" -F "FWDASH_$c"
            "$IPT" -X "FWDASH_$c"
        fi
    done
    echo "Estado resultante:"
    "$IPT" -S
    exit 0
fi

# --------------------------------------------------------------------------- #
# carga
# --------------------------------------------------------------------------- #
echo "=== recon_seed: cargando ruleset de reconocimiento ==="

# 1. Contadores. ACCEPT sobre icmp de loopback: no puede bloquear nada, y el
#    trafico que generamos despues sube los contadores hasta que iptables los
#    imprime con sufijo (1234K), que es la trampa numero uno del parser.
"$IPT" -C OUTPUT -o lo -p icmp -m comment --comment "$MARCA:contador" -j ACCEPT 2>/dev/null \
    || "$IPT" -I OUTPUT 1 -o lo -p icmp -m comment --comment "$MARCA:contador" -j ACCEPT
"$IPT" -C INPUT -i lo -p icmp -m comment --comment "$MARCA:contador" -j ACCEPT 2>/dev/null \
    || "$IPT" -I INPUT 1 -i lo -p icmp -m comment --comment "$MARCA:contador" -j ACCEPT

# 2. FWDASH_INPUT: la cadena rica. Sin enganchar (ver cabecera).
"$IPT" -N FWDASH_INPUT 2>/dev/null || "$IPT" -F FWDASH_INPUT
"$IPT" -A FWDASH_INPUT -i lo -m comment --comment "fwdash:guardian:loopback" -j ACCEPT
"$IPT" -A FWDASH_INPUT -m conntrack --ctstate RELATED,ESTABLISHED \
       -m comment --comment "fwdash:guardian:conntrack" -j ACCEPT
"$IPT" -A FWDASH_INPUT -p tcp --dport 22 -m comment --comment "fwdash:guardian:ssh" -j ACCEPT
"$IPT" -A FWDASH_INPUT -s 192.168.64.0/24 -p tcp --dport 8000 \
       -m comment --comment "fwdash:1:api desde la red host-only" -j ACCEPT
"$IPT" -A FWDASH_INPUT -p tcp -m multiport --dports 80,443,8443 -j ACCEPT
"$IPT" -A FWDASH_INPUT -p tcp --dport 30000:30010 -j ACCEPT
"$IPT" -A FWDASH_INPUT ! -s 10.0.0.0/8 -p tcp --dport 3306 -j DROP
"$IPT" -A FWDASH_INPUT -p udp --sport 1024:65535 --dport 53 -j ACCEPT
"$IPT" -A FWDASH_INPUT -p icmp --icmp-type echo-request -m limit --limit 5/min --limit-burst 3 -j ACCEPT
"$IPT" -A FWDASH_INPUT -i eth0 -p tcp --dport 23 -j LOG --log-prefix "FWDASH DROP telnet: " --log-level 4
"$IPT" -A FWDASH_INPUT -p tcp --dport 23 -j REJECT --reject-with icmp-port-unreachable
"$IPT" -A FWDASH_INPUT -j DROP

# 3. FWDASH_OUTPUT: enganchada, solo permite. Da una cadena propia con trafico
#    real atravesandola, que es lo que necesita la deteccion de drift.
"$IPT" -N FWDASH_OUTPUT 2>/dev/null || "$IPT" -F FWDASH_OUTPUT
"$IPT" -A FWDASH_OUTPUT -o lo -m comment --comment "fwdash:guardian:loopback" -j ACCEPT
"$IPT" -A FWDASH_OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
"$IPT" -A FWDASH_OUTPUT -d 8.8.8.8/32 -p udp --dport 53 -j ACCEPT
"$IPT" -A FWDASH_OUTPUT -j RETURN
"$IPT" -C OUTPUT -j FWDASH_OUTPUT 2>/dev/null || "$IPT" -A OUTPUT -j FWDASH_OUTPUT

# 4. FWDASH_FORWARD: enganchada y terminando en DROP. La VM no enruta.
"$IPT" -N FWDASH_FORWARD 2>/dev/null || "$IPT" -F FWDASH_FORWARD
"$IPT" -A FWDASH_FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
"$IPT" -A FWDASH_FORWARD -i eth0 -o eth1 -p tcp --dport 443 -j ACCEPT
"$IPT" -A FWDASH_FORWARD -j DROP
"$IPT" -C FORWARD -j FWDASH_FORWARD 2>/dev/null || "$IPT" -A FORWARD -j FWDASH_FORWARD

# 5. Unica politica que se cambia, y sobre la cadena que no lleva trafico.
"$IPT" -P FORWARD DROP

# 6. Trafico para mover los contadores por encima del umbral del sufijo.
echo "--- generando trafico de loopback (unos segundos) ---"
ping -f -c 250000 -q 127.0.0.1 >/dev/null 2>&1 || ping -c 4000 -i 0.002 -q 127.0.0.1 >/dev/null 2>&1 || true

echo "=== listo ==="
"$IPT" -S
