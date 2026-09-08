"""Traduce `RuleSpec` a argv de iptables. Funcion pura, sin efectos.

Bloque A3. No ejecuta nada: convierte datos en listas de strings. Por eso se puede
construir y testear entero en el host, y por eso es trivial de verificar.

Aqui viven tambien las REGLAS GUARDIAN (docs/ARCHITECTURE.md §0). No estan en la
base de datos, no se pueden desactivar por API y se emiten siempre en la cabecera
de cada cadena gestionada. Son lo que impide que una regla de usuario te deje sin
acceso a la VM ni a la propia API.

El caso mas traicionero es el de OUTPUT: sin un ACCEPT de ESTABLISHED,RELATED en
salida, una regla que filtre trafico saliente corta las RESPUESTAS de la API. La
peticion entra bien pero nunca vuelve, y desde el navegador parece un timeout
generico.

Dos decisiones sobre la FORMA del argv, tomadas en A3:

1. **Se emite la forma sencilla, no la canonica de iptables.** `-p tcp --dport 22`
   y no `-p tcp -m tcp --dport 22`. iptables reescribe la regla igualmente
   ([[Normalizacion de iptables]]), y replicar sus reescrituras seria acoplarse a
   un detalle no documentado que cambia entre versiones. La comparacion es por
   estructura, asi que la forma del argv no tiene que adivinar nada (ADR-0006).
2. **argv[0] es el nombre logico `iptables`, no una ruta.** El `CommandRunner` es
   quien resuelve el binario real y decide si antepone `sudo`; la allowlist del
   runner se comprueba sobre ese nombre logico.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.core.exceptions import InvalidRuleError
from app.firewall import validators
from app.firewall.spec import COMMENT_TAG, GUARDIAN_TAG_PREFIX, Chain, Protocol, RuleSpec

__all__ = ["IPTABLES", "render_guard_rules", "render_rule", "render_ruleset"]

#: Nombre logico del binario. Lo traduce a ruta el `CommandRunner` (bloque B2).
IPTABLES = "iptables"

#: Estados de conntrack que aceptan los guardianes. El orden es el que devuelve
#: iptables al leerlos de vuelta, no el que suele escribirse.
CTSTATE_ESTABLECIDO = "RELATED,ESTABLISHED"


def _etiqueta(spec: RuleSpec) -> str:
    """Comentario con el que la regla se reconoce al leerla de vuelta.

    Formato: `fwdash:<uuid8>[:<comentario del usuario>]`. Cuando la spec no viene
    de la base de datos (tests, `preview`) el hueco de la identidad se rellena con
    `-`, de modo que la etiqueta siempre tiene la misma forma y el parser no
    necesita dos caminos.
    """
    etiqueta = f"{COMMENT_TAG}:{spec.short_uuid or '-'}"
    return f"{etiqueta}:{spec.comment}" if spec.comment else etiqueta


def _selectores(spec: RuleSpec) -> list[str]:
    """Los flags de seleccion, en el orden en el que iptables los devuelve."""
    argv: list[str] = []
    if spec.src_ip:
        argv += ["-s", spec.src_ip]
    if spec.dst_ip:
        argv += ["-d", spec.dst_ip]
    if spec.in_interface:
        argv += ["-i", spec.in_interface]
    if spec.out_interface:
        argv += ["-o", spec.out_interface]
    if spec.protocol is not Protocol.ALL:
        argv += ["-p", spec.protocol.value]
    if spec.src_port:
        argv += ["--sport", spec.src_port]
    if spec.dst_port:
        argv += ["--dport", spec.dst_port]
    return argv


def render_rule(chain_name: str, spec: RuleSpec) -> list[list[str]]:
    """Devuelve los argv de una spec.

    Devuelve una LISTA de comandos, no uno solo: con `log_enabled=True` (fase 2)
    una spec produce dos reglas, el LOG y la de accion, y el LOG debe ir primero
    o no registra nada. Las dos llevan la misma etiqueta, para que el drift y los
    contadores las reconozcan como una sola regla logica.
    """
    if spec.ip_version != 4:
        raise InvalidRuleError(
            "El MVP solo genera reglas IPv4. El modelo ya guarda `ip_version` para "
            "que añadir ip6tables no exija migrar el esquema.",
            details={"campo": "ip_version", "valor": str(spec.ip_version)},
        )

    cabecera = [IPTABLES, "-A", chain_name, *_selectores(spec)]
    comentario = ["-m", "comment", "--comment", _etiqueta(spec)]

    comandos: list[list[str]] = []
    if spec.log_enabled and spec.log_prefix:
        comandos.append([*cabecera, *comentario, "-j", "LOG", "--log-prefix", spec.log_prefix])
    comandos.append([*cabecera, *comentario, "-j", spec.action.value])
    return comandos


def render_guard_rules(
    chain: Chain,
    chain_name: str,
    *,
    management_port: int,
    management_cidr: str,
    management_ssh_port: int | None = None,
) -> list[list[str]]:
    """Reglas guardian de una cadena. Ver la tabla de docs/ARCHITECTURE.md §0.

    INPUT   : ESTABLISHED,RELATED + lo + puerto de gestion desde management_cidr
    OUTPUT  : ESTABLISHED,RELATED + lo + desde el puerto de gestion hacia management_cidr
    FORWARD : ESTABLISHED,RELATED

    `management_port` y `management_cidr` se validan aqui aunque vengan de la
    configuracion: un `.env` mal escrito no puede acabar en un argv, y estas son
    justo las reglas que no se pueden permitir estar mal.

    EL GUARDIAN DEL CANAL DE RESCATE (ADR-0017, B4->B5)

    `management_ssh_port` es OPCIONAL y no tiene valor por defecto, exactamente
    por el mismo motivo que `management_cidr` (ADR-0016): lo que te puede dejar
    fuera se declara, no se supone. B4 midio que el ancla de recuperacion de esta
    VM no es fuera de banda -- `multipass` entra por SSH --, asi que una regla de
    usuario `DROP tcp --dport 22` se aplica sin queja y se lleva por delante la
    unica via de rescate. Si se declara, esa via queda protegida; si no se
    declara, el firewall filtra el 22 como cualquier otro puerto y no hay ningun
    agujero fijo que defender.

    El guardian se ata al MISMO `management_cidr` que el de la API, no a
    `0.0.0.0/0`: el canal de rescate es el del administrador. Un guardian de SSH
    abierto al mundo seria un agujero permanente escrito por la propia aplicacion.
    """
    cidr = validators.validate_ip_or_cidr(management_cidr, campo="management_allowed_cidr")
    puerto = validators.validate_port_spec(str(management_port), campo="management_port")
    ssh = (
        None
        if management_ssh_port is None
        else validators.validate_port_spec(str(management_ssh_port), campo="management_ssh_port")
    )

    def guardian(nombre: str, *selectores: str) -> list[str]:
        return [
            IPTABLES,
            "-A",
            chain_name,
            *selectores,
            "-m",
            "comment",
            "--comment",
            f"{GUARDIAN_TAG_PREFIX}:{nombre}",
            "-j",
            "ACCEPT",
        ]

    conntrack = guardian("conntrack", "-m", "conntrack", "--ctstate", CTSTATE_ESTABLECIDO)

    if chain is Chain.FORWARD:
        # Nada de loopback ni de gestion: por FORWARD no pasa el trafico dirigido
        # a esta maquina, asi que no hay acceso propio que proteger.
        return [conntrack]

    if chain is Chain.INPUT:
        guardianes = [
            conntrack,
            guardian("loopback", "-i", "lo"),
            guardian("management", "-s", cidr, "-p", "tcp", "--dport", puerto),
        ]
        if ssh is not None:
            guardianes.append(guardian("ssh", "-s", cidr, "-p", "tcp", "--dport", ssh))
        return guardianes

    guardianes = [
        conntrack,
        guardian("loopback", "-o", "lo"),
        guardian("management", "-d", cidr, "-p", "tcp", "--sport", puerto),
    ]
    if ssh is not None:
        # La respuesta a una sesion SSH ya establecida la cubre el guardian de
        # conntrack. Este cubre el caso en el que conntrack no esta: mismo
        # criterio que el guardian de gestion en OUTPUT, que existe por lo mismo.
        guardianes.append(guardian("ssh", "-d", cidr, "-p", "tcp", "--sport", ssh))
    return guardianes


def render_ruleset(
    chain: Chain,
    chain_name: str,
    specs: Sequence[RuleSpec],
    *,
    management_port: int,
    management_cidr: str,
    management_ssh_port: int | None = None,
) -> list[list[str]]:
    """Ruleset completo de una cadena: flush, guardianes y reglas de usuario en orden.

    No emite regla de cierre. La cadena gestionada termina con el RETURN implicito
    de iptables, asi que un paquete que no case con ninguna regla vuelve a la
    cadena del sistema y sigue su curso: la aplicacion filtra, no sustituye la
    politica del host.
    """
    comandos: list[list[str]] = [[IPTABLES, "-F", chain_name]]
    comandos += render_guard_rules(
        chain,
        chain_name,
        management_port=management_port,
        management_cidr=management_cidr,
        management_ssh_port=management_ssh_port,
    )
    for spec in specs:
        if spec.chain is not chain:
            raise InvalidRuleError(
                f"La regla es de la cadena {spec.chain.value} y se esta reconstruyendo "
                f"{chain.value}: aplicarla aqui cambiaria su significado.",
                details={"campo": "chain", "valor": spec.chain.value, "esperado": chain.value},
            )
        comandos += render_rule(chain_name, spec)
    return comandos
