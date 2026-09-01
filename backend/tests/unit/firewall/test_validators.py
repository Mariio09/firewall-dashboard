"""Tests de `app/firewall/validators.py`.

Aqui esta el PRIMER test del proyecto por decision de diseño: el que comprueba
que `validate_port_spec` rechaza `0`, `65536`, `'80; rm -rf /'` y `'8000:80'`.
No porque el `;` pudiera ejecutarse -- no puede, el runner usa `shell=False` --
sino porque esta capa existe para que la basura semantica no llegue nunca a
iptables aunque nunca pudiera ejecutarse como comando.
"""

from __future__ import annotations

import pytest

from app.core.exceptions import InvalidRuleError
from app.firewall import validators
from app.firewall.spec import Action, Chain, Protocol

# --------------------------------------------------------------------------- #
# Puertos: el test canonico numero 1
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "valor",
    [
        "0",  # iptables no tiene puerto 0
        "65536",  # un mas alla del maximo
        "80; rm -rf /",  # basura con forma de comando
        "8000:80",  # rango invertido
        "",
        "   ",
        "-1",
        "80,443",  # multiport no esta soportado por el modelo
        "http",
        "8000:8010:8020",
        "1e3",
        "999999",
    ],
)
def test_validate_port_spec_rechaza(valor: str) -> None:
    with pytest.raises(InvalidRuleError):
        validators.validate_port_spec(valor)


@pytest.mark.parametrize(
    ("entrada", "esperado"),
    [
        ("80", "80"),
        ("1", "1"),
        ("65535", "65535"),
        ("0080", "80"),  # se normalizan los ceros a la izquierda
        (" 443 ", "443"),
        ("8000:8010", "8000:8010"),
        ("30000:30010", "30000:30010"),
    ],
)
def test_validate_port_spec_acepta_y_normaliza(entrada: str, esperado: str) -> None:
    assert validators.validate_port_spec(entrada) == esperado


def test_un_rango_de_un_solo_puerto_se_rechaza_con_una_pista() -> None:
    """`'80:80'` no es util y confunde al comparar: se rechaza explicando como se escribe."""
    with pytest.raises(InvalidRuleError) as error:
        validators.validate_port_spec("80:80")
    assert "':'" in error.value.message


def test_un_puerto_que_no_es_texto_se_rechaza() -> None:
    with pytest.raises(InvalidRuleError):
        validators.validate_port_spec(80)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# IPs
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("entrada", "esperado"),
    [
        ("1.2.3.4", "1.2.3.4/32"),  # toda IP sale en CIDR
        ("1.2.3.4/32", "1.2.3.4/32"),
        ("192.168.64.0/24", "192.168.64.0/24"),
        (" 10.0.0.0/8 ", "10.0.0.0/8"),
        ("10.0.0.1/8", "10.0.0.0/8"),  # los bits de host se ponen a cero, como en iptables
        ("0.0.0.0/0", "0.0.0.0/0"),
    ],
)
def test_validate_ip_or_cidr_normaliza_a_cidr(entrada: str, esperado: str) -> None:
    assert validators.validate_ip_or_cidr(entrada) == esperado


@pytest.mark.parametrize(
    "valor",
    [
        "999.1.1.1",
        "1.2.3.4/33",
        "1.2.3.4 -j ACCEPT",
        "no-soy-una-ip",
        "",
        "1.2.3.4;DROP",
        "010.1.1.1",  # ceros a la izquierda: ambiguo (octal), Python lo rechaza
    ],
)
def test_validate_ip_or_cidr_rechaza(valor: str) -> None:
    with pytest.raises(InvalidRuleError):
        validators.validate_ip_or_cidr(valor)


def test_una_ip_v6_no_cuela_en_una_regla_v4() -> None:
    with pytest.raises(InvalidRuleError) as error:
        validators.validate_ip_or_cidr("2001:db8::1", ip_version=4)
    assert "IPv6" in error.value.message


def test_una_ip_v6_es_valida_si_la_regla_es_v6() -> None:
    assert validators.validate_ip_or_cidr("2001:db8::1", ip_version=6) == "2001:db8::1/128"


def test_un_entero_no_se_interpreta_como_ip() -> None:
    """`ip_network(5)` devuelve `0.0.0.5/32` sin protestar: por eso se rechaza antes."""
    with pytest.raises(InvalidRuleError):
        validators.validate_ip_or_cidr(5)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Interfaces
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("valor", ["eth0", "lo", "enp0s1", "br-1a2b3c", "eth0.100", "vlan@if2"])
def test_validate_interface_acepta(valor: str) -> None:
    assert validators.validate_interface(valor) == valor


@pytest.mark.parametrize(
    "valor",
    [
        "eth0 -j ACCEPT",
        "eth+",  # el comodin de iptables no se admite desde la UI
        "a" * 16,  # IFNAMSIZ - 1 = 15
        "",
        "eth0/1",
        "eth0;ls",
    ],
)
def test_validate_interface_rechaza(valor: str) -> None:
    with pytest.raises(InvalidRuleError):
        validators.validate_interface(valor)


# --------------------------------------------------------------------------- #
# Textos libres que acaban dentro de un argv
# --------------------------------------------------------------------------- #


def test_log_prefix_admite_29_caracteres_y_no_30() -> None:
    assert validators.validate_log_prefix("a" * 29) == "a" * 29
    with pytest.raises(InvalidRuleError):
        validators.validate_log_prefix("a" * 30)


def test_log_prefix_conserva_el_espacio_final() -> None:
    """El espacio final es la convencion para que el prefijo no se pegue al log."""
    assert validators.validate_log_prefix("FWDASH DROP: ") == "FWDASH DROP: "


@pytest.mark.parametrize("valor", ['con "comillas"', "con\\barra", "salto\nde linea", "", "   "])
def test_log_prefix_rechaza(valor: str) -> None:
    with pytest.raises(InvalidRuleError):
        validators.validate_log_prefix(valor)


def test_comment_acepta_texto_normal_y_lo_recorta() -> None:
    assert validators.validate_comment("  api desde la red host-only  ") == (
        "api desde la red host-only"
    )


@pytest.mark.parametrize("valor", ['rompe "el" parser', "a" * 201, "", "control\x00"])
def test_comment_rechaza(valor: str) -> None:
    with pytest.raises(InvalidRuleError):
        validators.validate_comment(valor)


def test_comment_admite_acentos() -> None:
    """El comentario es el POR QUE de la regla: prohibir acentos seria absurdo."""
    assert validators.validate_comment("bloqueo del rango de la oficina") is not None
    assert validators.validate_comment("conexión saliente al DNS") == "conexión saliente al DNS"


# --------------------------------------------------------------------------- #
# uuid, enums y nombre de cadena gestionada
# --------------------------------------------------------------------------- #


def test_validate_rule_uuid() -> None:
    valido = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
    assert validators.validate_rule_uuid(valido) == valido
    with pytest.raises(InvalidRuleError):
        validators.validate_rule_uuid("no-es-un-uuid")


def test_los_enums_aceptan_su_texto_y_rechazan_lo_demas() -> None:
    assert validators.validate_chain("INPUT") is Chain.INPUT
    assert validators.validate_action("DROP") is Action.DROP
    assert validators.validate_protocol("tcp") is Protocol.TCP
    assert validators.validate_ip_version(6) == 6

    with pytest.raises(InvalidRuleError):
        validators.validate_chain("PREROUTING")  # existe en iptables, no en esta app
    with pytest.raises(InvalidRuleError):
        validators.validate_action("LOG")  # LOG no es una accion de usuario
    with pytest.raises(InvalidRuleError):
        validators.validate_ip_version(5)


def test_el_error_de_un_enum_dice_que_valores_hay() -> None:
    with pytest.raises(InvalidRuleError) as error:
        validators.validate_protocol("sctp")
    assert set(error.value.details["permitidos"]) == {"tcp", "udp", "icmp", "all"}


def test_validate_managed_chain_name() -> None:
    assert validators.validate_managed_chain_name("FWDASH", Chain.INPUT) == "FWDASH_INPUT"
    assert validators.validate_managed_chain_name("FWDASH", Chain.FORWARD) == "FWDASH_FORWARD"


@pytest.mark.parametrize("prefijo", ["fwdash", "1FW", "FW DASH", "FW-DASH", "F", ""])
def test_validate_managed_chain_name_rechaza_el_prefijo(prefijo: str) -> None:
    with pytest.raises(InvalidRuleError):
        validators.validate_managed_chain_name(prefijo, Chain.INPUT)


def test_un_prefijo_valido_puede_dar_un_nombre_demasiado_largo() -> None:
    """21 caracteres pasan el patron, pero '_FORWARD' se sale del limite de xtables."""
    with pytest.raises(InvalidRuleError) as error:
        validators.validate_managed_chain_name("A" * 21, Chain.FORWARD)
    assert "28" in error.value.message
