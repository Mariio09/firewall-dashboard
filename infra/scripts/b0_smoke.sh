#!/usr/bin/env bash
# =========================================================================== #
# b0_smoke.sh — recorre b0_verify.sh entero con un `multipass` falso
#
#   bash infra/scripts/b0_smoke.sh
#
# PARA QUE SIRVE
# `bash -n` solo mira la sintaxis. No detecta una variable sin definir, una rama
# del flujo que nunca se ejecuta, ni un `awk` que no casa con la salida real.
# Esto ejecuta el arnes de principio a fin contra respuestas simuladas de una VM
# sana, y espera terminar en verde.
#
# Existe porque paso: una edicion se llevo por delante el bloque que define
# EXISTIA, `bash -n` dijo que todo estaba bien, y el arnes murio en el paso 1
# —despues de destruir la VM— sin haber comprobado nada.
#
# QUE **NO** DEMUESTRA
# Que la VM real funcione. Las respuestas son inventadas: valida el FLUJO del
# script, no la maquina. La verificacion de verdad sigue siendo `make vm-provision`
# en el host. Esto es lo que se puede correr en cualquier Linux, sin multipass.
# =========================================================================== #
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STUB="$(mktemp -d "${TMPDIR:-/tmp}/b0smoke.XXXXXX")"
trap 'rm -rf "$STUB"' EXIT

cat > "$STUB/multipass" <<'STUBFIN'
#!/usr/bin/env bash
case "$1" in
  version) echo "multipass  1.16.3+host"; exit 0 ;;
  info)    printf 'Name: firewall-lab\nState: Running\nImage: Ubuntu 24.04 LTS\nIPv4: 192.168.64.7\n'; exit 0 ;;
  delete|launch|transfer|unmount|mount) exit 0 ;;
  exec) shift 2; [[ "$1" == "--" ]] && shift
        case "$*" in
          *"cloud-init status"*)   echo "status: done" ;;
          *"python3 --version"*)   echo "Python 3.12.3" ;;
          *"iptables --version"*)  echo "iptables v1.8.10 (nf_tables)" ;;
          *"iptables -S"*)         printf -- '-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n' ;;
          *"ls -1"*)               echo "17" ;;
          *"head -1"*)             echo ".DEFAULT_GOAL := help" ;;
          *"rev-parse HEAD"*)      git -C "$REPO_REAL" rev-parse HEAD ;;
          *) exit 0 ;;
        esac ;;
  *) exit 0 ;;
esac
STUBFIN

cat > "$STUB/shasum" <<'STUBFIN'
#!/usr/bin/env bash
echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  -"
STUBFIN

chmod +x "$STUB/multipass" "$STUB/shasum"

echo "== Recorriendo b0_verify.sh con multipass simulado =="
REPO_REAL="$RAIZ" PATH="$STUB:$PATH" bash "$RAIZ/infra/scripts/b0_verify.sh" --si
CODIGO=$?

echo
if [[ $CODIGO -eq 0 ]]; then
    echo "SMOKE OK — el arnes recorre las 4 fases y termina en verde."
    echo "Recuerda: esto valida el flujo, no la VM. Verifica con 'make vm-provision'."
else
    echo "SMOKE FALLIDO (codigo $CODIGO) — el arnes no llega al final ni con una VM perfecta."
fi
exit $CODIGO
