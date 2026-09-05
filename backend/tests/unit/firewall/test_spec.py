"""Tests de `app/firewall/spec.py`.

Lo que se prueba aqui es una sola afirmacion, la que sostiene el diseño entero:
**no existe ninguna forma de construir una `RuleSpec` invalida**. Si alguno de
estos tests falla, la validacion ha dejado de ser una propiedad del tipo y ha
vuelto a ser una convencion que alguien tiene que recordar.
"""

from __future__ import annotations

import dataclasses

import pytest

from app.core.exceptions import InvalidRuleError
from app.firewall.spec import (
    Action,
    Chain,
    Counters,
    NativeRule,
    Protocol,
    RuleSpec,
)

UUID_DE_PRUEBA = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"


def spec_minima(**kwargs: object) -> RuleSpec:
    base: dict[str, object] = {"chain": Chain.INPUT, "action": Action.DROP}
    base.update(kwargs)
    return RuleSpec(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Normalizacion en construccion
# --------------------------------------------------------------------------- #


def test_la_spec_se_construye_canonica() -> None:
    spec = spec_minima(protocol="tcp", src_ip="1.2.3.4", dst_port="0080", in_interface=" eth0 ")
    assert spec.src_ip == "1.2.3.4/32"
    assert spec.dst_port == "80"
    assert spec.in_interface == "eth0"
    assert spec.protocol is Protocol.TCP


def test_los_enums_se_aceptan_como_texto() -> None:
    """El servicio construye specs desde filas de SQLAlchemy: llegan como texto."""
    spec = RuleSpec(chain="INPUT", action="ACCEPT")  # type: ignore[arg-type]
    assert spec.chain is Chain.INPUT
    assert spec.action is Action.ACCEPT


def test_dos_formas_de_escribir_la_misma_regla_son_la_misma_spec() -> None:
    """La premisa del ADR-0006: el drift se calcula comparando estructuras."""
    a = spec_minima(protocol="tcp", src_ip="1.2.3.4", dst_port="22")
    b = spec_minima(protocol=Protocol.TCP, src_ip="1.2.3.4/32", dst_port="0022")
    assert a == b
    assert len({a, b}) == 1  # hashable: el drift se puede calcular con conjuntos


def test_cualquier_direccion_se_guarda_como_ausencia_de_selector() -> None:
    """`0.0.0.0/0` no es un selector: es no tener ninguno, y asi lo guarda iptables.

    iptables ACEPTA `-s 0.0.0.0/0` y despues NO lo imprime en `iptables -S`,
    porque es su valor por defecto. Mientras la spec lo guardo como texto, la de
    la base de datos nunca coincidia con la leida del sistema y la deteccion de
    drift daba por FALTANTE una regla que estaba puesta -- con un apply que no
    arreglaba nada, porque volvia a escribir exactamente lo mismo. Lo destapo una
    regla de verdad ("Drop scan 22") en el bloque C.
    """
    assert spec_minima(protocol="tcp", src_ip="0.0.0.0/0", dst_port="22") == spec_minima(
        protocol="tcp", dst_port="22"
    )
    assert spec_minima(dst_ip="0.0.0.0/0").dst_ip is None

    # Y la contraprueba, porque "todo se vuelve None" seria igual de malo: una
    # red de verdad, aunque sea enorme, SI es un selector y se conserva.
    assert spec_minima(src_ip="10.0.0.0/8").src_ip == "10.0.0.0/8"
    assert spec_minima(src_ip="0.0.0.0/1").src_ip == "0.0.0.0/1"


def test_la_spec_es_inmutable() -> None:
    spec = spec_minima()
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.action = Action.ACCEPT  # type: ignore[misc]


def test_la_spec_no_admite_atributos_nuevos() -> None:
    """`slots=True`: no hay `__dict__`, asi que un typo al asignar no crea un campo fantasma.

    Se comprueba la propiedad y no una excepcion concreta a proposito: en un
    dataclass `frozen=True, slots=True`, asignar un nombre DESCONOCIDO no lanza
    `FrozenInstanceError` sino `TypeError`, porque el `__setattr__` generado
    quedo ligado a la clase anterior a la recreacion que hace `slots`. Fijar esa
    excepcion en el test seria atarse a un detalle de CPython.
    """
    spec = spec_minima()
    assert not hasattr(spec, "__dict__")
    with pytest.raises((TypeError, AttributeError)):
        spec.dts_port = "22"  # type: ignore[attr-defined]


def test_short_uuid() -> None:
    assert spec_minima(rule_uuid=UUID_DE_PRUEBA).short_uuid == "3f2504e0"
    assert spec_minima().short_uuid is None


# --------------------------------------------------------------------------- #
# Lo que no se puede construir
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("campos", "motivo"),
    [
        ({"src_ip": "999.1.1.1"}, "ip invalida"),
        ({"dst_port": "0"}, "puerto invalido"),
        ({"in_interface": "eth0 -j ACCEPT"}, "interfaz invalida"),
        ({"rule_uuid": "no-es-un-uuid"}, "uuid invalido"),
        ({"comment": 'rompe "el" parser'}, "comentario con comillas"),
        ({"protocol": "sctp"}, "protocolo no soportado"),
        ({"ip_version": 5}, "familia inexistente"),
    ],
)
def test_un_campo_invalido_impide_construir_la_spec(campos: dict[str, object], motivo: str) -> None:
    assert motivo  # solo documenta el caso en la salida de pytest
    with pytest.raises(InvalidRuleError):
        spec_minima(**campos)


def test_un_puerto_exige_tcp_o_udp() -> None:
    """iptables rechaza `-p icmp --dport 80`: mejor un 422 que un 502."""
    with pytest.raises(InvalidRuleError):
        spec_minima(protocol=Protocol.ICMP, dst_port="80")
    with pytest.raises(InvalidRuleError):
        spec_minima(protocol=Protocol.ALL, src_port="1024:65535")


def test_input_no_admite_interfaz_de_salida() -> None:
    with pytest.raises(InvalidRuleError):
        RuleSpec(chain=Chain.INPUT, action=Action.DROP, out_interface="eth0")


def test_output_no_admite_interfaz_de_entrada() -> None:
    with pytest.raises(InvalidRuleError):
        RuleSpec(chain=Chain.OUTPUT, action=Action.DROP, in_interface="eth0")


def test_forward_admite_las_dos_interfaces() -> None:
    spec = RuleSpec(
        chain=Chain.FORWARD, action=Action.ACCEPT, in_interface="eth0", out_interface="eth1"
    )
    assert (spec.in_interface, spec.out_interface) == ("eth0", "eth1")


def test_el_log_exige_prefijo() -> None:
    with pytest.raises(InvalidRuleError):
        spec_minima(log_enabled=True)
    assert spec_minima(log_enabled=True, log_prefix="FWDASH DROP: ").log_prefix is not None


# --------------------------------------------------------------------------- #
# NativeRule: lo que el parser devolvera
# --------------------------------------------------------------------------- #


def test_native_rule_distingue_guardian_de_regla_de_usuario() -> None:
    guardian = NativeRule(
        raw="-A FWDASH_INPUT -i lo -m comment --comment fwdash:guardian:loopback -j ACCEPT",
        chain="FWDASH_INPUT",
        target="ACCEPT",
        comment="fwdash:guardian:loopback",
    )
    usuario = NativeRule(
        raw="-A FWDASH_INPUT -s 1.2.3.4/32 -m comment --comment fwdash:3f2504e0 -j DROP",
        chain="FWDASH_INPUT",
        target="DROP",
        comment="fwdash:3f2504e0",
        rule_uuid="3f2504e0",
        spec=spec_minima(src_ip="1.2.3.4"),
    )
    ajena = NativeRule(raw="-A FWDASH_INPUT -j DROP", chain="FWDASH_INPUT", target="DROP")

    assert guardian.is_guardian and guardian.is_managed
    assert not usuario.is_guardian and usuario.is_managed
    assert not ajena.is_guardian and not ajena.is_managed


def test_native_rule_sin_contadores_no_miente() -> None:
    """Por defecto cero, nunca `None`: la UI suma contadores sin comprobar nada."""
    assert NativeRule(raw="-A FWDASH_INPUT -j DROP", chain="FWDASH_INPUT").counters == Counters(
        packets=0, bytes=0
    )
