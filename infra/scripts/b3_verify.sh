#!/usr/bin/env bash
# =========================================================================== #
# b3_verify.sh — arnes del paso B3: IptablesBackend
#
#   Ejecutar EN EL HOST, desde la raiz del repo:
#     bash infra/scripts/b3_verify.sh | tee b3.log
#
# NO MODIFICA NADA del repo ni del sistema: no toca iptables reales. Crea un
# iptables SIMULADO en un directorio temporal que borra al salir.
#
# --------------------------------------------------------------------------- #
# LA REGLA DE ESTE ARNES (A5, cobrada cara en B0)
#
# Un arnes que no puede demostrar que hizo lo que dice, MIENTE EN VERDE. Nada se
# da por bueno por codigo de salida: el recorrido completo se ejecuta FUERA de
# pytest, contra un iptables simulado que GUARDA ESTADO en disco, y lo que se
# comprueba es ese estado. Que `teardown` limpio se demuestra mirando el archivo,
# no viendo que no salto ninguna excepcion.
#
# Y cada afirmacion positiva con su CONTRAPRUEBA (B1): que el payload de
# inyeccion no se ejecute no prueba nada si no se demuestra antes que el binario
# simulado SI se ejecuto y recibio ese payload como un argumento mas.
#
# --------------------------------------------------------------------------- #
# LO QUE ESTE ARNES NO PRUEBA
#
# Que iptables de verdad acepte estos argv. Eso no se puede probar en el host, y
# es el trabajo de los tests de contrato dentro de la VM (B5,
# `pytest -m requires_iptables`). Lo que si prueba, y es lo que B3 aporta, es que
# la cadena de montaje entera —settings -> SubprocessRunner -> IptablesBackend ->
# renderer -> proceso hijo -> parser— produce el argv correcto, en el orden
# correcto, y lee de vuelta lo que el proceso hijo escribio.
# =========================================================================== #
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKEND="$RAIZ/backend"
VENV="$BACKEND/.venv/bin/activate"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ACIERTOS=0; FALLOS=0
V=$'\033[32m'; R=$'\033[31m'; A=$'\033[33m'; N=$'\033[0m'
[[ -t 1 ]] || { V=""; R=""; A=""; N=""; }

ok()      { printf "  %sOK%s      %s\n" "$V" "$N" "$1"; ACIERTOS=$((ACIERTOS+1)); }
fallo()   { printf "  %sFALLO%s   %s\n" "$R" "$N" "$1"; [[ -n "${2:-}" ]] && printf "          %s\n" "$2"; FALLOS=$((FALLOS+1)); }
seccion() { printf "\n%s\n" "$1"; }

echo "================================================================"
echo " B3 — IptablesBackend"
echo " $(date -Iseconds)  ·  $(hostname)"
echo "================================================================"

if [[ ! -f "$VENV" ]]; then
    echo "ERROR: no existe $VENV. Ejecuta 'make install' primero." >&2
    exit 1
fi
# shellcheck disable=SC1090
cd "$BACKEND" && source "$VENV"

echo " $(python --version)  ·  $(pytest --version 2>&1 | head -1)"

# --------------------------------------------------------------------------- #
seccion "1. La contencion sigue en pie"

# La invariante es que iptables.py no IMPORTA ni USA subprocess. Buscar la
# palabra suelta daria falso positivo cada vez que un comentario cite la nota
# `CommandRunner y subprocess`, que es exactamente lo que paso la primera vez.
USO_SUBPROCESS='(^[[:space:]]*(import|from)[[:space:]]+subprocess)|subprocess\.'
if grep -qE "$USO_SUBPROCESS" app/firewall/iptables.py; then
    fallo "iptables.py usa subprocess: tiene que pasar por el runner" \
          "$(grep -nE "$USO_SUBPROCESS" app/firewall/iptables.py)"
else
    ok "iptables.py no toca subprocess: solo habla por el CommandRunner"
fi

if grep -rn --include='*.py' 'shell=True' app/ >/dev/null 2>&1; then
    fallo "aparece shell=True en app/"
else
    ok "shell=True no aparece en ningun archivo de app/"
fi

# Contraprueba: el MISMO patron encuentra el uso cuando si lo hay.
if grep -qE "$USO_SUBPROCESS" app/firewall/runner.py; then
    ok "contraprueba: el mismo patron si detecta el uso en runner.py"
else
    fallo "el patron no detecta subprocess en runner.py: la comprobacion anterior no probaba nada"
fi

# --------------------------------------------------------------------------- #
seccion "2. La suite de B3"

SALIDA_B3="$(pytest tests/unit/firewall/test_iptables.py -q 2>&1)"
PASADOS="$(echo "$SALIDA_B3" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | head -1)"
PASADOS="${PASADOS:-0}"
if echo "$SALIDA_B3" | grep -qE '[0-9]+ (failed|error)'; then
    fallo "hay tests de B3 en rojo" "$(echo "$SALIDA_B3" | tail -3 | tr -d '\n')"
elif (( PASADOS >= 30 )); then
    ok "$PASADOS tests de IptablesBackend en verde"
else
    fallo "solo $PASADOS tests ejecutados: se esperaban 30 o mas"
fi

# --------------------------------------------------------------------------- #
seccion "3. La suite entera (que B3 no haya roto nada)"

SALIDA_TODO="$(pytest -q 2>&1)"
TOTAL="$(echo "$SALIDA_TODO" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | head -1)"
TOTAL="${TOTAL:-0}"
if echo "$SALIDA_TODO" | grep -qE '[0-9]+ (failed|error)'; then
    fallo "la suite completa tiene rojos" "$(echo "$SALIDA_TODO" | tail -3 | tr -d '\n')"
else
    ok "suite completa en verde: $TOTAL tests"
fi

# --------------------------------------------------------------------------- #
seccion "4. El recorrido completo contra un iptables SIMULADO, fuera de pytest"

# Un iptables de mentira que guarda estado en $TMP/estado.json y registra cada
# argv que recibe en $TMP/argv.log. Se llama 'iptables' porque el runner exige
# que el nombre del binario este en la allowlist.
cat > "$TMP/iptables" <<'FALSO'
#!/usr/bin/env python3
"""iptables simulado. No filtra nada: guarda estado y registra lo que le llega."""
import json, os, shlex, sys
from pathlib import Path

TMP = Path(__file__).resolve().parent
ESTADO = TMP / "estado.json"
LOG = TMP / "argv.log"

with LOG.open("a") as f:
    f.write(shlex.join(sys.argv[1:]) + "\n")
    f.write("ENV " + shlex.join(f"{k}={v}" for k, v in sorted(os.environ.items())) + "\n")

e = json.loads(ESTADO.read_text()) if ESTADO.exists() else {"cadenas": {}, "saltos": []}
a = sys.argv[1:]
orden, codigo, salida = a[0], 0, ""

def guardar():
    ESTADO.write_text(json.dumps(e))

if orden == "-N":
    if a[1] in e["cadenas"]: codigo = 1
    else: e["cadenas"][a[1]] = []; guardar()
elif orden == "-X":
    if a[1] not in e["cadenas"] or any(s[1] == a[1] for s in e["saltos"]): codigo = 1
    else: del e["cadenas"][a[1]]; guardar()
elif orden == "-F":
    if a[1] not in e["cadenas"]: codigo = 1
    else: e["cadenas"][a[1]] = []; guardar()
elif orden == "-A":
    if a[1] not in e["cadenas"]: codigo = 1
    else: e["cadenas"][a[1]].append(a[2:]); guardar()
elif orden == "-C":
    codigo = 0 if [a[1], a[3]] in e["saltos"] else 1
elif orden == "-I":
    e["saltos"].insert(0, [a[1], a[4]]); guardar()
elif orden == "-D":
    par = [a[1], a[3]]
    if par in e["saltos"]: e["saltos"].remove(par); guardar()
    else: codigo = 1
elif orden == "-L" and "-x" in a:
    if a[1] not in e["cadenas"]: codigo = 1
    else:
        salida = f"Chain {a[1]} (1 references)\n"
        salida += "    pkts      bytes target     prot opt in     out     source               destination\n"
        for i, regla in enumerate(e["cadenas"][a[1]]):
            texto = shlex.join(regla)
            com = ""
            if "--comment" in regla:
                com = " /* " + regla[regla.index("--comment") + 1] + " */"
            objetivo = regla[regla.index("-j") + 1] if "-j" in regla else "ACCEPT"
            salida += (f"  {500000 + i:>6} {42000000 + i:>8} {objetivo:<10} all  --  *      *"
                       f"       0.0.0.0/0            0.0.0.0/0           {com}\n")
elif orden == "-L":
    codigo = 0 if a[1] in e["cadenas"] else 1
elif orden == "-S":
    if a[1] not in e["cadenas"]: codigo = 1
    else:
        salida = "".join(f"-A {a[1]} {shlex.join(r)}\n" for r in e["cadenas"][a[1]])
else:
    codigo = 2
    print(f"iptables simulado: subcomando no modelado {a}", file=sys.stderr)

if codigo == 1:
    print("iptables: No chain/target/match by that name.", file=sys.stderr)
sys.stdout.write(salida)
sys.exit(codigo)
FALSO
# El entorno del hijo es minimo (PATH=/usr/sbin:/usr/bin:/sbin:/bin), asi que el
# shebang se fija a la ruta absoluta del python que ya esta en uso en vez de
# confiar en que `/usr/bin/env python3` encuentre alguno.
{ printf '#!%s\n' "$(command -v python3)"; tail -n +2 "$TMP/iptables"; } > "$TMP/iptables.nuevo"
mv "$TMP/iptables.nuevo" "$TMP/iptables"
chmod 755 "$TMP/iptables"

PAYLOAD="; touch $TMP/PWNED; echo"
SALIDA_PY="$(TMP_DIR="$TMP" PAYLOAD="$PAYLOAD" python - <<'PY' 2>&1
import os
from pathlib import Path

from app.api.deps import build_firewall_backend
from app.core.config import Settings
from app.core.exceptions import FirewallCommandError
from app.core.logging import configure_logging
from app.firewall.spec import Action, Chain, Protocol, RuleSpec

tmp = Path(os.environ["TMP_DIR"])
payload = os.environ["PAYLOAD"]

ajustes = Settings(
    app_env="dev",
    firewall_backend="iptables",
    iptables_bin=str(tmp / "iptables"),
    use_sudo=False,
    managed_chain_prefix="FWDASH",
    management_port=8000,
    management_allowed_cidr="192.168.64.0/24",
    command_timeout_seconds=10,
    # WARNING para que la pista de auditoria de cada comando no ahogue la salida
    # del arnes. Lo que se audita aqui es el registro que deja el propio binario
    # simulado, que es una fuente independiente del logger.
    log_level="WARNING",
)
configure_logging(ajustes)
backend = build_firewall_backend(ajustes)
print("TIPO", type(backend).__name__)

# --- montaje ------------------------------------------------------------- #
backend.ensure_scaffold()
backend.ensure_scaffold()          # idempotencia, contra el estado en disco

# --- aplicacion, con el payload de inyeccion dentro del comentario -------- #
reglas = [
    RuleSpec(chain=Chain.INPUT, action=Action.DROP, protocol=Protocol.TCP,
             src_ip="10.0.0.5", dst_port="3306", comment=payload,
             rule_uuid="3f2504e0-4f89-41d3-9a0c-0305e82c3301"),
    RuleSpec(chain=Chain.INPUT, action=Action.ACCEPT, protocol=Protocol.TCP,
             dst_port="443", rule_uuid="9c5b94b1-35ad-49bb-b118-8e8fc24abf80"),
]
resultado = backend.apply_ruleset(Chain.INPUT, reglas)
print("APLICADAS", resultado.applied)

# --- lectura de vuelta: el parser sobre lo que escribio el proceso hijo --- #
leidas = backend.read_ruleset(Chain.INPUT)
print("LEIDAS", len(leidas))
print("GUARDIANES", sum(1 for r in leidas if r.is_guardian))
print("CON_SPEC", sum(1 for r in leidas if r.spec is not None))
print("PUERTOS", [r.spec.dst_port for r in leidas if r.spec is not None])

contadores = backend.read_counters(Chain.INPUT)
print("CONTADORES", sorted(contadores))
print("EXACTOS", all(c.packets >= 500000 for c in contadores.values()))

# --- el desmontaje y su consecuencia -------------------------------------- #
backend.teardown()
try:
    backend.read_ruleset(Chain.INPUT)
except FirewallCommandError as exc:
    print("TRAS_TEARDOWN_FALLA", exc.details)
else:
    print("TRAS_TEARDOWN_FALLA nada: sigue leyendo una cadena que ya no existe")
PY
)"

echo "$SALIDA_PY" | sed 's/^/          /'

# --- contraprueba primero: sin esto, nada de lo que sigue prueba nada ------ #
if [[ -s "$TMP/argv.log" ]]; then
    ok "contraprueba: el iptables simulado SI se ejecuto ($(grep -cv '^ENV ' "$TMP/argv.log") comandos)"
else
    fallo "el iptables simulado no se ejecuto: el resto de la seccion no prueba nada"
fi

if echo "$SALIDA_PY" | grep -q '^TIPO IptablesBackend'; then
    ok "FIREWALL_BACKEND=iptables construye el backend real desde settings"
else
    fallo "build_firewall_backend no devolvio IptablesBackend"
fi

# --- el montaje, comprobado sobre el argv que recibio el hijo -------------- #
for cadena in INPUT OUTPUT FORWARD; do
    if grep -qx -- "-N FWDASH_$cadena" "$TMP/argv.log"; then
        ok "ensure_scaffold creo FWDASH_$cadena"
    else
        fallo "no se creo FWDASH_$cadena"
    fi
done

if grep -qx -- "-I INPUT 1 -j FWDASH_INPUT" "$TMP/argv.log"; then
    ok "el salto se inserta en la posicion 1 de INPUT"
else
    fallo "el salto no se inserto en posicion 1" "$(grep -- '-I ' "$TMP/argv.log" | head -3)"
fi

if [[ "$(grep -cx -- '-N FWDASH_INPUT' "$TMP/argv.log")" == "1" ]]; then
    ok "ensure_scaffold es idempotente: la segunda pasada no volvio a crear nada"
else
    fallo "la segunda llamada volvio a intentar crear la cadena"
fi

# --- el orden dentro de la cadena ----------------------------------------- #
PRIMERO="$(grep -v '^ENV ' "$TMP/argv.log" | grep -n -- '-F FWDASH_INPUT' | head -1 | cut -d: -f1)"
GUARDIANES="$(grep -c -- 'fwdash:guardian' "$TMP/argv.log")"
if [[ -n "$PRIMERO" && "$GUARDIANES" -ge 3 ]]; then
    ok "aplicar empieza vaciando y sigue con $GUARDIANES guardianes"
else
    fallo "no aparece el flush o faltan guardianes" "flush=$PRIMERO guardianes=$GUARDIANES"
fi

SIGUIENTES="$(grep -v '^ENV ' "$TMP/argv.log" | sed -n "$((PRIMERO+1)),$((PRIMERO+3))p")"
if [[ "$(echo "$SIGUIENTES" | grep -c 'fwdash:guardian')" == "3" ]]; then
    ok "los guardianes van INMEDIATAMENTE despues del flush, antes que ninguna regla"
else
    fallo "entre el flush y los guardianes se cuela algo" "$SIGUIENTES"
fi

if echo "$SALIDA_PY" | grep -q '^APLICADAS 2'; then
    ok "apply_ruleset aplico las 2 reglas de usuario"
else
    fallo "apply_ruleset no aplico las reglas"
fi

# --- el round-trip: se lee de vuelta lo que el hijo escribio --------------- #
if echo "$SALIDA_PY" | grep -q '^GUARDIANES 3'; then
    ok "read_ruleset reconoce los 3 guardianes al leer de vuelta"
else
    fallo "los guardianes no sobreviven al round-trip"
fi

if echo "$SALIDA_PY" | grep -qF "PUERTOS ['3306', '443']"; then
    ok "las reglas vuelven con su puerto intacto: renderer -> proceso -> parser"
else
    fallo "el round-trip perdio o cambio las reglas" "$(echo "$SALIDA_PY" | grep '^PUERTOS')"
fi

if echo "$SALIDA_PY" | grep -q "^CONTADORES \['3f2504e0', '9c5b94b1'\]"; then
    ok "los contadores vuelven indexados por uuid corto, sin los guardianes"
else
    fallo "los contadores no cuadran" "$(echo "$SALIDA_PY" | grep '^CONTADORES')"
fi

if grep -q -- '-L FWDASH_INPUT -v -n -x' "$TMP/argv.log" && echo "$SALIDA_PY" | grep -q '^EXACTOS True'; then
    ok "los contadores se piden con -x y llegan sin abreviar"
else
    fallo "los contadores no se pidieron con -x"
fi

# --- la inyeccion --------------------------------------------------------- #
if grep -qF -- "$PAYLOAD" "$TMP/argv.log"; then
    ok "el payload llego LITERAL al proceso hijo, como un argumento mas"
else
    fallo "el payload no llego intacto: la prueba de abajo no vale"
fi

if [[ -e "$TMP/PWNED" ]]; then
    fallo "EL PAYLOAD SE EJECUTO: existe $TMP/PWNED"
else
    ok "el payload no se ejecuto: no hay testigo en disco"
fi

if grep -q '^ENV .*LC_ALL=C' "$TMP/argv.log" && ! grep -q '^ENV .*HOME=' "$TMP/argv.log"; then
    ok "el hijo vio el entorno minimo: LC_ALL=C y sin variables heredadas"
else
    fallo "el entorno del hijo no es el minimo" "$(grep -m1 '^ENV ' "$TMP/argv.log" | cut -c1-160)"
fi

# --- el desmontaje, comprobado sobre el estado del sistema simulado ------- #
CADENAS_VIVAS="$(python -c "import json,sys;e=json.load(open('$TMP/estado.json'));print(len(e['cadenas']),len(e['saltos']))" 2>/dev/null)"
if [[ "$CADENAS_VIVAS" == "0 0" ]]; then
    ok "teardown dejo el sistema simulado sin cadenas ni saltos"
else
    fallo "teardown dejo restos" "cadenas/saltos = $CADENAS_VIVAS"
fi

if echo "$SALIDA_PY" | grep -q "^TRAS_TEARDOWN_FALLA {'chain': 'FWDASH_INPUT'}"; then
    ok "tras teardown, leer la cadena falla con FirewallCommandError tipado"
else
    fallo "leer despues de teardown no fallo como debia" "$(echo "$SALIDA_PY" | grep TRAS_TEARDOWN)"
fi

# --- contraprueba de la allowlist ----------------------------------------- #
ANTES="$(wc -l < "$TMP/argv.log")"
SALIDA_ALLOW="$(TMP_DIR="$TMP" python - <<'PY' 2>&1
import os
from pathlib import Path
from app.core.exceptions import SecurityError
from app.firewall.runner import SubprocessRunner

tmp = Path(os.environ["TMP_DIR"])
try:
    SubprocessRunner(use_sudo=False, iptables_bin=str(tmp / "curl"))
except SecurityError:
    print("BIN_FUERA_DE_ALLOWLIST_OK")
else:
    print("BIN_FUERA_DE_ALLOWLIST_FALLO")

corredor = SubprocessRunner(use_sudo=False, iptables_bin=str(tmp / "iptables"))
try:
    corredor.run(["rm", "-rf", "/"])
except SecurityError:
    print("ARGV_FUERA_DE_ALLOWLIST_OK")
else:
    print("ARGV_FUERA_DE_ALLOWLIST_FALLO")
PY
)"
echo "$SALIDA_ALLOW" | sed 's/^/          /'

if echo "$SALIDA_ALLOW" | grep -q 'BIN_FUERA_DE_ALLOWLIST_OK'; then
    ok "un IPTABLES_BIN fuera de la allowlist no llega ni a construirse"
else
    fallo "la allowlist no bloqueo el binario configurado"
fi

if echo "$SALIDA_ALLOW" | grep -q 'ARGV_FUERA_DE_ALLOWLIST_OK'; then
    ok "un argv fuera de la allowlist lanza SecurityError"
else
    fallo "la allowlist no bloqueo el argv"
fi

if [[ "$(wc -l < "$TMP/argv.log")" == "$ANTES" ]]; then
    ok "contraprueba: lo bloqueado no dejo ni una linea nueva en el registro"
else
    fallo "algo se ejecuto pese al bloqueo"
fi

# --------------------------------------------------------------------------- #
seccion "5. Linters y tipos"

for comprobacion in "ruff check ." "ruff format --check ." "mypy app" "bandit -c pyproject.toml -q -r app"; do
    if SALIDA="$($comprobacion 2>&1)"; then
        ok "$comprobacion"
    else
        # Sin sangrar y sin aplastar los saltos de linea: un error de linter que
        # no se puede leer obliga a volver a ejecutarlo a mano.
        fallo "$comprobacion"
        echo "$SALIDA" | head -40 | sed 's/^/          /'
    fi
done

# --------------------------------------------------------------------------- #
echo
echo "================================================================"
printf " Resultado: %s%d OK%s, %s%d FALLOS%s\n" "$V" "$ACIERTOS" "$N" "$R" "$FALLOS" "$N"
echo "================================================================"
(( FALLOS == 0 )) || exit 1
