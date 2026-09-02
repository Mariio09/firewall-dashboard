"""Tests de `app/firewall/parser.py`, alimentados con las fixtures REALES de A2.

Estos son, probablemente, los tests mas valiosos del repositorio: son el seguro
contra que el `FakeFirewallBackend` se desvie de como se comporta iptables de
verdad. Ninguna de las tres cosas que comprueban -- la reescritura de las reglas,
los contadores abreviados y el espaciado variable -- se habria adivinado
escribiendo el parser de memoria.

Las fixtures NO se editan: se regeneran con `make recon` desde la VM.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.exceptions import FirewallError
from app.firewall.parser import (
    parse_counters,
    parse_human_number,
    parse_list_format,
    parse_save_format,
)
from app.firewall.spec import Action, Chain, Protocol

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "iptables_output"


def leer(nombre: str) -> str:
    return (FIXTURES / nombre).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# `iptables -S`: el test canonico numero 3
# --------------------------------------------------------------------------- #


def test_lee_una_cadena_entera_de_una_salida_real() -> None:
    reglas = parse_save_format(leer("cargado/save.txt"), "FWDASH_INPUT")
    assert len(reglas) == 12
    assert all(r.chain == "FWDASH_INPUT" for r in reglas)
    assert reglas[0].raw.startswith("-A FWDASH_INPUT")


def test_la_cadena_vacia_no_devuelve_nada() -> None:
    assert parse_save_format(leer("limpio/save.txt"), "FWDASH_INPUT") == []


def test_una_salida_de_error_no_revienta_el_parser() -> None:
    """`iptables -S CADENA_QUE_NO_EXISTE` escribe en stderr y no en stdout."""
    assert parse_save_format(leer("error_chain_missing.txt"), "FWDASH_INPUT") == []


def test_las_politicas_y_las_creaciones_de_cadena_se_ignoran() -> None:
    """Las lineas `-P` y `-N` describen la cadena, no su contenido."""
    reglas = parse_save_format(leer("cargado/save.txt"), "INPUT")
    assert len(reglas) == 1
    assert reglas[0].comment == "recon-a2:contador"


def test_una_regla_de_usuario_vuelve_como_spec() -> None:
    reglas = parse_save_format(leer("cargado/save.txt"), "FWDASH_INPUT")
    api = next(r for r in reglas if r.rule_uuid == "1")

    assert api.comment == "fwdash:1:api desde la red host-only"
    assert api.spec is not None
    assert api.spec.chain is Chain.INPUT
    assert api.spec.action is Action.ACCEPT
    assert api.spec.protocol is Protocol.TCP
    assert api.spec.src_ip == "192.168.64.0/24"
    assert api.spec.dst_port == "8000"
    assert api.spec.comment == "api desde la red host-only"  # sin la etiqueta


def test_los_guardianes_se_reconocen_y_no_se_confunden_con_reglas_de_usuario() -> None:
    reglas = parse_save_format(leer("cargado/save.txt"), "FWDASH_INPUT")
    guardianes = [r for r in reglas if r.is_guardian]
    assert len(guardianes) == 3
    assert all(r.spec is None for r in guardianes)
    assert all(r.rule_uuid is None for r in guardianes)
    assert all("guardian" in r.unsupported for r in guardianes)


@pytest.mark.parametrize(
    ("fragmento", "motivo"),
    [
        ("multiport --dports 80,443,8443", "multiport"),
        ("! -s 10.0.0.0/8", "negacion"),
        ("--icmp-type 8", "icmp"),
        ("-m limit", "limit"),
    ],
)
def test_lo_que_el_modelo_no_expresa_se_marca_en_vez_de_descartarse(
    fragmento: str, motivo: str
) -> None:
    """Dentro de una cadena gestionada, una regla asi ES drift (ADR-0007)."""
    reglas = parse_save_format(leer("cargado/save.txt"), "FWDASH_INPUT")
    regla = next(r for r in reglas if fragmento in r.raw)
    assert regla.spec is None
    assert motivo in regla.unsupported


def test_el_reject_with_por_defecto_no_impide_la_spec() -> None:
    """`-j REJECT` vuelve de iptables como `-j REJECT --reject-with icmp-port-unreachable`.

    Tratar ese valor como un match mas convertiria cada REJECT aplicado en drift
    permanente: la regla estaria bien y el sistema diria que no.
    """
    reglas = parse_save_format(leer("cargado/save.txt"), "FWDASH_INPUT")
    reject = next(r for r in reglas if r.target == "REJECT")
    assert reject.spec is not None
    assert reject.spec.action is Action.REJECT
    assert reject.spec.dst_port == "23"


def test_un_salto_a_otra_cadena_no_es_una_regla_de_usuario() -> None:
    reglas = parse_save_format(leer("cargado/save.txt"), "FORWARD")
    salto = next(r for r in reglas if r.target == "FWDASH_FORWARD")
    assert salto.spec is None
    assert "target:FWDASH_FORWARD" in salto.unsupported


def test_un_drop_pelado_si_es_expresable() -> None:
    reglas = parse_save_format(leer("cargado/save.txt"), "FWDASH_INPUT")
    assert reglas[-1].spec is not None
    assert reglas[-1].spec.action is Action.DROP
    assert reglas[-1].spec.src_ip is None


def test_el_formato_de_iptables_save_se_lee_igual() -> None:
    """`iptables-save` trae las mismas lineas `-A`, con cabeceras distintas."""
    guardadas = parse_save_format(leer("cargado/iptables_save.txt"), "FWDASH_OUTPUT")
    dns = next(r for r in guardadas if r.target == "ACCEPT" and "8.8.8.8" in r.raw)
    assert dns.spec is not None
    assert dns.spec.dst_ip == "8.8.8.8/32"
    assert dns.spec.protocol is Protocol.UDP


def test_la_pareja_log_mas_accion_vuelve_como_una_sola_spec() -> None:
    """Es lo que el propio renderer emite para `log_enabled=True`."""
    salida = "\n".join(
        [
            '-A FWDASH_INPUT -p tcp --dport 23 -m comment --comment "fwdash:ab12cd34:telnet"'
            ' -j LOG --log-prefix "FWDASH DROP: "',
            '-A FWDASH_INPUT -p tcp --dport 23 -m comment --comment "fwdash:ab12cd34:telnet"'
            " -j DROP",
        ]
    )
    log, accion = parse_save_format(salida, "FWDASH_INPUT")

    assert log.target == "LOG"
    assert log.log_prefix == "FWDASH DROP: "
    assert accion.spec is not None
    assert accion.spec.log_enabled is True
    assert accion.spec.log_prefix == "FWDASH DROP: "
    # Y la mitad LOG queda marcada. Sin la marca llega a la deteccion de drift
    # con el mismo perfil que una regla ajena -- sin spec y sin etiqueta de
    # guardian -- y el banner acusa de tocar el firewall por fuera a quien solo
    # activo el log.
    assert log.is_log_half is True
    assert accion.is_log_half is False


def test_un_log_suelto_no_se_marca_como_mitad_de_pareja() -> None:
    """Un `-j LOG` sin su accion detras SI es una linea sobrante.

    La marca dice "esta linea la escribio el renderer y su spec esta en la
    siguiente". Ponerla por el mero hecho de ser un LOG escondería una regla
    ajena que alguien dejo suelta en una cadena gestionada.
    """
    salida = (
        '-A FWDASH_INPUT -p tcp --dport 23 -m comment --comment "fwdash:ab12cd34:suelto"'
        ' -j LOG --log-prefix "SUELTO: "'
    )
    (log,) = parse_save_format(salida, "FWDASH_INPUT")

    assert log.target == "LOG"
    assert log.spec is None
    assert log.is_log_half is False


# --------------------------------------------------------------------------- #
# `iptables -L -v -n`: contadores y espaciado
# --------------------------------------------------------------------------- #


def test_lee_la_salida_tabular_con_contadores_exactos() -> None:
    reglas = parse_list_format(leer("cargado/list_verbose_exact.txt"), "INPUT")
    assert len(reglas) == 1
    assert reglas[0].counters.packets == 500_000
    assert reglas[0].counters.bytes == 42_000_000


def test_la_salida_abreviada_da_el_mismo_numero_que_la_exacta() -> None:
    """`500K` y `500000` son la misma regla contada dos veces. Un parser que hiciera
    `int('500K')` funcionaria mil paquetes y reventaria despues, en produccion."""
    abreviada = parse_list_format(leer("cargado/list_verbose.txt"), "INPUT")[0]
    exacta = parse_list_format(leer("cargado/list_verbose_exact.txt"), "INPUT")[0]
    assert abreviada.counters == exacta.counters


def test_un_target_largo_no_descoloca_las_columnas() -> None:
    """`FWDASH_FORWARD  all  --` deja dos espacios donde otras filas dejan cinco:
    por eso el parser usa split() y no indices de caracter."""
    (salto,) = parse_list_format(leer("cargado/list_verbose_exact.txt"), "FORWARD")
    assert salto.target == "FWDASH_FORWARD"
    assert salto.counters.packets == 0


def test_la_cabecera_de_cadena_tiene_dos_formas() -> None:
    """`Chain INPUT (policy ACCEPT ...)` frente a `Chain FWDASH_INPUT (0 references)`."""
    salida = leer("cargado/list_verbose_exact.txt")
    assert len(parse_list_format(salida, "INPUT")) == 1
    assert len(parse_list_format(salida, "FWDASH_INPUT")) == 12


def test_la_salida_tabular_tambien_produce_specs() -> None:
    reglas = parse_list_format(leer("cargado/list_verbose_exact.txt"), "FWDASH_INPUT")
    rangos = next(r for r in reglas if r.spec is not None and r.spec.dst_port == "30000:30010")
    assert rangos.spec is not None
    assert rangos.spec.protocol is Protocol.TCP

    dns = next(r for r in reglas if r.spec is not None and r.spec.protocol is Protocol.UDP)
    assert dns.spec is not None
    assert dns.spec.src_port == "1024:65535"
    assert dns.spec.dst_port == "53"


def test_la_negacion_en_la_columna_de_origen_se_detecta() -> None:
    """En la salida tabular la negacion viene pegada: `!10.0.0.0/8`."""
    reglas = parse_list_format(leer("cargado/list_verbose_exact.txt"), "FWDASH_INPUT")
    negada = next(r for r in reglas if "!10.0.0.0/8" in r.raw)
    assert negada.spec is None
    assert "negacion" in negada.unsupported


def test_las_cadenas_vacias_no_dan_falsos_positivos() -> None:
    assert parse_list_format(leer("limpio/list_verbose.txt"), "INPUT") == []


def test_los_contadores_se_indexan_por_uuid() -> None:
    contadores = parse_counters(leer("cargado/list_verbose_exact.txt"))
    assert set(contadores) == {"1"}  # la unica regla con etiqueta de identidad


def test_los_contadores_ignoran_guardianes_y_reglas_ajenas() -> None:
    contadores = parse_counters(leer("cargado/list_verbose_exact.txt"))
    assert "guardian" not in contadores
    assert "recon-a2" not in contadores


def test_de_una_pareja_log_y_accion_se_queda_la_accion() -> None:
    """Los dos cuentan los MISMOS paquetes: sumarlos los contaria dos veces."""
    salida = "\n".join(
        [
            "Chain FWDASH_INPUT (0 references)",
            "    pkts      bytes target     prot opt in     out     source        destination",
            "      10       800 LOG        tcp  --  *      *       0.0.0.0/0     0.0.0.0/0"
            '            /* fwdash:ab12cd34 */ LOG flags 0 level 4 prefix "FWDASH DROP: "',
            "      10       800 DROP       tcp  --  *      *       0.0.0.0/0     0.0.0.0/0"
            "            /* fwdash:ab12cd34 */",
        ]
    )
    assert parse_counters(salida)["ab12cd34"].packets == 10


# --------------------------------------------------------------------------- #
# Numeros abreviados
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("entrada", "esperado"),
    [
        ("0", 0),
        ("500000", 500_000),
        ("500K", 500_000),
        ("42M", 42_000_000),
        ("1543K", 1_543_000),
        ("2G", 2_000_000_000),
        ("1.5M", 1_500_000),
        (" 35 ", 35),
    ],
)
def test_parse_human_number(entrada: str, esperado: int) -> None:
    assert parse_human_number(entrada) == esperado


@pytest.mark.parametrize("valor", ["", "   ", "no-es-un-numero", "500X"])
def test_parse_human_number_rechaza(valor: str) -> None:
    with pytest.raises(FirewallError):
        parse_human_number(valor)
