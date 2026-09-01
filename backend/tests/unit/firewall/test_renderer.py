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
