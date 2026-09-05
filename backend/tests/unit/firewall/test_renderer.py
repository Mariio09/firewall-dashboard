"""Tests de `app/firewall/renderer.py`.

Contiene el test canonico numero 2 del proyecto: *el renderer produce el argv
esperado para una spec conocida*. Se escribe con el argv completo, literal, y no
comprobando trozos sueltos: el valor de este test esta en que falla si cambia el
ORDEN de los flags, no solo su presencia.
"""

from __future__ import annotations

import pytest

from app.core.exceptions import InvalidRuleError
from app.firewall.renderer import IPTABLES, render_guard_rules, render_rule, render_ruleset
from app.firewall.spec import Action, Chain, Protocol, RuleSpec

UUID_DE_PRUEBA = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
CIDR = "192.168.64.0/24"


def test_argv_de_una_spec_conocida() -> None:
    spec = RuleSpec(
        chain=Chain.INPUT,
        action=Action.DROP,
        protocol=Protocol.TCP,
        src_ip="1.2.3.4",
        dst_port="22",
        rule_uuid=UUID_DE_PRUEBA,
    )
    assert render_rule("FWDASH_INPUT", spec) == [
        [
            IPTABLES,
            "-A",
            "FWDASH_INPUT",
            "-s",
            "1.2.3.4/32",
            "-p",
            "tcp",
            "--dport",
            "22",
            "-m",
            "comment",
            "--comment",
            "fwdash:3f2504e0",
            "-j",
            "DROP",
        ]
    ]


def test_el_orden_de_los_selectores_es_el_de_iptables() -> None:
    """-s, -d, -i, -o, -p, puertos: el orden en el que iptables los devuelve."""
    spec = RuleSpec(
        chain=Chain.FORWARD,
        action=Action.ACCEPT,
        protocol=Protocol.UDP,
        src_ip="10.0.0.0/8",
        dst_ip="8.8.8.8",
        in_interface="eth0",
        out_interface="eth1",
        src_port="1024:65535",
        dst_port="53",
    )
    (argv,) = render_rule("FWDASH_FORWARD", spec)
    flags = [t for t in argv if t.startswith("-") and t != "-A"]
    assert flags[:6] == ["-s", "-d", "-i", "-o", "-p", "--sport"]


def test_el_protocolo_all_no_se_emite() -> None:
    """`-p all` es ruido: iptables lo omite al devolver la regla."""
    (argv,) = render_rule("FWDASH_INPUT", RuleSpec(chain=Chain.INPUT, action=Action.DROP))
    assert "-p" not in argv


def test_cualquier_origen_no_emite_s() -> None:
    """Con `src_ip="0.0.0.0/0"` el argv sale SIN `-s`, igual que sin origen.

    No es cosmetica: emitirlo hacia que la regla volviera de iptables sin el
    —lo borra, por ser su valor por defecto— y el drift no la reconociera.
    """
    spec = RuleSpec(chain=Chain.INPUT, action=Action.DROP, src_ip="0.0.0.0/0")
    (argv,) = render_rule("FWDASH_INPUT", spec)
    assert "-s" not in argv


def test_la_etiqueta_lleva_uuid_y_comentario() -> None:
    spec = RuleSpec(
        chain=Chain.INPUT, action=Action.DROP, comment="bloqueo temporal", rule_uuid=UUID_DE_PRUEBA
    )
    (argv,) = render_rule("FWDASH_INPUT", spec)
    assert argv[argv.index("--comment") + 1] == "fwdash:3f2504e0:bloqueo temporal"


def test_una_spec_sin_uuid_sigue_llevando_etiqueta() -> None:
    """Un `preview` no tiene fila en la DB, pero la regla debe seguir siendo reconocible."""
    (argv,) = render_rule("FWDASH_INPUT", RuleSpec(chain=Chain.INPUT, action=Action.DROP))
    assert argv[argv.index("--comment") + 1] == "fwdash:-"


def test_una_regla_con_log_emite_dos_reglas_y_el_log_va_primero() -> None:
    spec = RuleSpec(
        chain=Chain.INPUT,
        action=Action.DROP,
        log_enabled=True,
        log_prefix="FWDASH DROP: ",
        rule_uuid=UUID_DE_PRUEBA,
    )
    log, accion = render_rule("FWDASH_INPUT", spec)
    assert log[-3:] == ["LOG", "--log-prefix", "FWDASH DROP: "]
    assert accion[-1] == "DROP"
    # Misma etiqueta: son una sola regla logica, y asi vuelven a juntarse al leerlas.
    assert log[log.index("--comment") + 1] == accion[accion.index("--comment") + 1]


def test_ipv6_todavia_no_se_renderiza() -> None:
    spec = RuleSpec(chain=Chain.INPUT, action=Action.DROP, ip_version=6, src_ip="2001:db8::1")
    with pytest.raises(InvalidRuleError):
        render_rule("FWDASH_INPUT", spec)


# --------------------------------------------------------------------------- #
# Reglas guardian
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("chain", "cuantos"),
    [(Chain.INPUT, 3), (Chain.OUTPUT, 3), (Chain.FORWARD, 1)],
)
def test_cuantos_guardianes_lleva_cada_cadena(chain: Chain, cuantos: int) -> None:
    guardianes = render_guard_rules(
        chain, f"FWDASH_{chain.value}", management_port=8000, management_cidr=CIDR
    )
    assert len(guardianes) == cuantos
    assert all(g[-1] == "ACCEPT" for g in guardianes)
    assert all("fwdash:guardian:" in " ".join(g) for g in guardianes)


def test_el_primer_guardian_es_siempre_conntrack() -> None:
    """Sin el ACCEPT de ESTABLISHED,RELATED, filtrar la salida corta las respuestas
    de la propia API: la peticion entra y nunca vuelve."""
    for chain in Chain:
        primero = render_guard_rules(
            chain, f"FWDASH_{chain.value}", management_port=8000, management_cidr=CIDR
        )[0]
        assert "--ctstate" in primero
        assert primero[primero.index("--ctstate") + 1] == "RELATED,ESTABLISHED"


def test_el_guardian_de_gestion_mira_al_reves_en_input_y_en_output() -> None:
    entrada = render_guard_rules(
        Chain.INPUT, "FWDASH_INPUT", management_port=8000, management_cidr=CIDR
    )[2]
    salida = render_guard_rules(
        Chain.OUTPUT, "FWDASH_OUTPUT", management_port=8000, management_cidr=CIDR
    )[2]
    assert entrada[entrada.index("-s") + 1] == CIDR
    assert "--dport" in entrada
    assert salida[salida.index("-d") + 1] == CIDR
    assert "--sport" in salida


def test_la_configuracion_del_guardian_tambien_se_valida() -> None:
    """Un `.env` mal escrito no puede acabar en la regla que protege el acceso."""
    with pytest.raises(InvalidRuleError):
        render_guard_rules(
            Chain.INPUT, "FWDASH_INPUT", management_port=8000, management_cidr="no-es-una-red"
        )
    with pytest.raises(InvalidRuleError):
        render_guard_rules(Chain.INPUT, "FWDASH_INPUT", management_port=0, management_cidr=CIDR)


# --------------------------------------------------------------------------- #
# Ruleset completo
# --------------------------------------------------------------------------- #


def test_el_ruleset_empieza_por_el_flush_y_luego_los_guardianes() -> None:
    spec = RuleSpec(chain=Chain.INPUT, action=Action.DROP, src_ip="1.2.3.4")
    comandos = render_ruleset(
        Chain.INPUT, "FWDASH_INPUT", [spec], management_port=8000, management_cidr=CIDR
    )
    assert comandos[0] == [IPTABLES, "-F", "FWDASH_INPUT"]
    assert len(comandos) == 1 + 3 + 1
    assert "fwdash:guardian:conntrack" in comandos[1]
    assert comandos[-1][-1] == "DROP"


def test_el_ruleset_respeta_el_orden_de_las_specs() -> None:
    """En iptables el orden ES la semantica: gana la primera que hace match."""
    specs = [
        RuleSpec(chain=Chain.INPUT, action=Action.ACCEPT, src_ip=f"10.0.0.{i}") for i in (1, 2, 3)
    ]
    comandos = render_ruleset(
        Chain.INPUT, "FWDASH_INPUT", specs, management_port=8000, management_cidr=CIDR
    )
    ips = [c[c.index("-s") + 1] for c in comandos if "-s" in c and "guardian" not in " ".join(c)]
    assert ips == ["10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"]


def test_una_spec_de_otra_cadena_no_se_cuela() -> None:
    ajena = RuleSpec(chain=Chain.OUTPUT, action=Action.DROP)
    with pytest.raises(InvalidRuleError):
        render_ruleset(
            Chain.INPUT, "FWDASH_INPUT", [ajena], management_port=8000, management_cidr=CIDR
        )


def test_el_ruleset_no_cierra_la_cadena() -> None:
    """La cadena acaba en el RETURN implicito: la app filtra, no sustituye la
    politica del host. Un `-j DROP` final aqui romperia Docker o ufw."""
    comandos = render_ruleset(
        Chain.INPUT, "FWDASH_INPUT", [], management_port=8000, management_cidr=CIDR
    )
    assert all(c[-1] != "RETURN" for c in comandos)
    assert len(comandos) == 4


# --------------------------------------------------------------------------- #
# El guardian del canal de rescate (ADR-0017)
# --------------------------------------------------------------------------- #

#: Puerto SSH de la VM. Se escribe como constante y no como `22` suelto para que
#: los tests digan de que puerto hablan.
PUERTO_SSH = 22


def _etiquetas(comandos: list[list[str]]) -> list[str]:
    """La etiqueta `--comment` de cada comando que la lleve."""
    return [c[c.index("--comment") + 1] for c in comandos if "--comment" in c]


@pytest.mark.parametrize(
    ("chain", "sin_declarar", "declarado"),
    [(Chain.INPUT, 3, 4), (Chain.OUTPUT, 3, 4), (Chain.FORWARD, 1, 1)],
)
def test_el_guardian_de_ssh_solo_existe_si_se_declara(
    chain: Chain, sin_declarar: int, declarado: int
) -> None:
    """Sin `management_ssh_port` no hay agujero fijo; con el, hay proteccion.

    Las dos mitades van juntas a proposito: comprobar solo la ausencia pasaria
    igual si el guardian no se emitiera NUNCA, que es justo el bug que dejaria
    esta opcion en decorativa.
    """
    nombre = f"FWDASH_{chain.value}"

    ninguno = render_guard_rules(chain, nombre, management_port=8000, management_cidr=CIDR)
    assert len(ninguno) == sin_declarar
    assert "fwdash:guardian:ssh" not in _etiquetas(ninguno)

    con_ssh = render_guard_rules(
        chain, nombre, management_port=8000, management_cidr=CIDR, management_ssh_port=PUERTO_SSH
    )
    assert len(con_ssh) == declarado
    # FORWARD no gana ninguno: por ahi no pasa el trafico dirigido a esta maquina,
    # asi que no hay sesion de rescate que proteger.
    assert ("fwdash:guardian:ssh" in _etiquetas(con_ssh)) is (chain is not Chain.FORWARD)


def test_el_guardian_de_ssh_se_ata_al_cidr_de_gestion_y_no_al_mundo() -> None:
    """Un ACCEPT del 22 desde `0.0.0.0/0` seria un agujero permanente escrito por
    la propia aplicacion. El canal de rescate es el del administrador."""
    entrada = render_guard_rules(
        Chain.INPUT,
        "FWDASH_INPUT",
        management_port=8000,
        management_cidr=CIDR,
        management_ssh_port=PUERTO_SSH,
    )[3]
    salida = render_guard_rules(
        Chain.OUTPUT,
        "FWDASH_OUTPUT",
        management_port=8000,
        management_cidr=CIDR,
        management_ssh_port=PUERTO_SSH,
    )[3]

    assert entrada == [
        IPTABLES,
        "-A",
        "FWDASH_INPUT",
        "-s",
        CIDR,
        "-p",
        "tcp",
        "--dport",
        str(PUERTO_SSH),
        "-m",
        "comment",
        "--comment",
        "fwdash:guardian:ssh",
        "-j",
        "ACCEPT",
    ]
    assert salida[salida.index("-d") + 1] == CIDR
    assert salida[salida.index("--sport") + 1] == str(PUERTO_SSH)


def test_el_puerto_de_rescate_tambien_se_valida() -> None:
    """Es una de las tres reglas que no se pueden permitir estar mal."""
    for puerto in (0, 65536):
        with pytest.raises(InvalidRuleError):
            render_guard_rules(
                Chain.INPUT,
                "FWDASH_INPUT",
                management_port=8000,
                management_cidr=CIDR,
                management_ssh_port=puerto,
            )


def test_una_regla_de_usuario_no_puede_tapar_el_guardian_de_ssh() -> None:
    """El caso que abrio la decision: `DROP tcp --dport 22` desde la UI.

    En iptables el orden ES la semantica, asi que la proteccion no consiste en
    rechazar la regla, sino en que el ACCEPT del guardian se evalue ANTES. El
    test lo comprueba por posicion, que es el efecto, y no por la presencia de la
    etiqueta, que no dice nada sobre quien gana.
    """
    corta_el_rescate = RuleSpec(
        chain=Chain.INPUT, action=Action.DROP, protocol=Protocol.TCP, dst_port=str(PUERTO_SSH)
    )
    comandos = render_ruleset(
        Chain.INPUT,
        "FWDASH_INPUT",
        [corta_el_rescate],
        management_port=8000,
        management_cidr=CIDR,
        management_ssh_port=PUERTO_SSH,
    )
    etiquetas = _etiquetas(comandos)
    posicion_guardian = etiquetas.index("fwdash:guardian:ssh")
    posicion_drop = etiquetas.index("fwdash:-")
    assert posicion_guardian < posicion_drop

    # La contraprueba: sin declarar el puerto, esa misma regla no encuentra
    # ningun ACCEPT delante. Si este bloque tambien pasara, el test de arriba
    # estaria comprobando el orden de una lista que da igual.
    sin_guardian = _etiquetas(
        render_ruleset(
            Chain.INPUT,
            "FWDASH_INPUT",
            [corta_el_rescate],
            management_port=8000,
            management_cidr=CIDR,
        )
    )
    assert "fwdash:guardian:ssh" not in sin_guardian
