"""El log no puede filtrar secretos. Se comprueba, no se confia."""

from __future__ import annotations

import time

import pytest

from app.core.logging import REDACTED, censor_sensitive, new_request_id


@pytest.mark.parametrize(
    "clave",
    [
        "password",
        "Password",
        "admin_password",
        "hashed_password",
        "jwt_secret_key",
        "access_token",
        "refresh_token",
        "authorization",
        "x_api_key",
        "cookie",
    ],
)
def test_se_censura_por_nombre_de_clave(clave: str) -> None:
    """La comprobacion es por subcadena y sin distinguir mayusculas.

    Enumerar claves exactas obligaria a acordarse de añadir cada variante nueva,
    y ese es justo el dia en que se filtra una.
    """
    resultado = censor_sensitive(None, "info", {"event": "login", clave: "valor-real"})
    assert resultado[clave] == REDACTED


def test_se_censura_dentro_de_estructuras_anidadas() -> None:
    """El caso real no es `log.info(password=...)`, es `log.info(payload={...})`."""
    evento = {
        "event": "peticion",
        "payload": {"username": "mario", "password": "hunter2"},
        "cabeceras": [{"authorization": "Bearer abc"}],
    }
    resultado = censor_sensitive(None, "info", evento)
    assert resultado["payload"]["password"] == REDACTED
    assert resultado["payload"]["username"] == "mario"
    assert resultado["cabeceras"][0]["authorization"] == REDACTED


def test_no_se_censura_lo_que_no_es_secreto() -> None:
    """Un censor demasiado agresivo deja el log inservible."""
    evento = {"event": "regla_creada", "chain": "INPUT", "src_ip": "1.2.3.4/32", "position": 10}
    assert censor_sensitive(None, "info", evento) == evento


def test_el_evento_original_no_se_modifica() -> None:
    """Censurar construye un diccionario nuevo: el objeto del llamante no se toca."""
    original = {"password": "hunter2"}
    censor_sensitive(None, "info", original)
    assert original["password"] == "hunter2"


def test_los_request_id_son_unicos() -> None:
    ids = [new_request_id() for _ in range(1000)]
    assert all(len(valor) == 26 for valor in ids)
    assert len(set(ids)) == 1000


def test_los_request_id_se_ordenan_por_tiempo() -> None:
    """Ordenar identificadores alfabeticamente los ordena cronologicamente.

    La resolucion es el milisegundo: dos identificadores generados dentro del
    mismo milisegundo NO tienen orden garantizado entre si, porque los 80 bits
    bajos son aleatorios. Para ordenar dentro del milisegundo haria falta un
    contador monotono, y eso no aporta nada a la unica finalidad de esto, que es
    encontrar una peticion en el log.
    """
    ids = []
    for _ in range(5):
        ids.append(new_request_id())
        time.sleep(0.002)
    assert ids == sorted(ids)
