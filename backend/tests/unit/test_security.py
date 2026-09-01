"""`core/security.py`: hash de contraseñas y ciclo de vida de los tokens.

Son tests sin base de datos ni HTTP a proposito: la parte de la autenticacion
que puede fallar en silencio es la cripto, y aqui se prueba sola.

Tres de estos tests no comprueban una funcionalidad sino un ataque conocido:
token con `alg: none`, token firmado con otra clave y refresh usado como access.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import Settings
from app.core.exceptions import AuthError
from app.core.security import (
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
    waste_time_like_a_verification,
)

PASSWORD = "una-contrasena-cualquiera"


def _firmar(payload: dict[str, object], settings: Settings, clave: str | None = None) -> str:
    return jwt.encode(
        payload,
        clave if clave is not None else settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def _claims_validos(settings: Settings, **extra: object) -> dict[str, object]:
    ahora = datetime.now(UTC)
    base: dict[str, object] = {
        "sub": "1",
        "username": "admin",
        "role": "admin",
        "type": "access",
        "jti": "abc",
        "iat": ahora,
        "exp": ahora + timedelta(minutes=5),
    }
    base.update(extra)
    return base


# --------------------------------------------------------------------------- #
# Contraseñas
# --------------------------------------------------------------------------- #


def test_el_hash_no_contiene_la_contrasena() -> None:
    hashed = hash_password(PASSWORD)
    assert PASSWORD not in hashed
    assert hashed.startswith("$argon2id$")


def test_dos_hashes_de_la_misma_contrasena_son_distintos() -> None:
    """Si dos hashes iguales dieran la misma cadena, faltaria el salt.

    Y sin salt, una tabla precalculada rompe todas las cuentas a la vez.
    """
    assert hash_password(PASSWORD) != hash_password(PASSWORD)


def test_verify_acepta_la_correcta_y_rechaza_las_demas() -> None:
    hashed = hash_password(PASSWORD)
    assert verify_password(PASSWORD, hashed) is True
    assert verify_password(PASSWORD.upper(), hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(PASSWORD + " ", hashed) is False


def test_verify_devuelve_false_con_un_hash_corrupto() -> None:
    """Un hash ilegible no puede reventar el login con una excepcion."""
    assert verify_password(PASSWORD, "esto-no-es-un-hash") is False
    assert verify_password(PASSWORD, "") is False


def test_un_hash_recien_creado_no_necesita_rehash() -> None:
    assert needs_rehash(hash_password(PASSWORD)) is False


def test_un_hash_ilegible_si_necesita_rehash() -> None:
    assert needs_rehash("$argon2id$roto") is True


def test_gastar_tiempo_no_revienta() -> None:
    """Se llama en la ruta del usuario inexistente: no puede lanzar nada."""
    waste_time_like_a_verification()


# --------------------------------------------------------------------------- #
# Tokens: el camino feliz
# --------------------------------------------------------------------------- #


def test_el_access_token_lleva_lo_que_se_le_puso(settings: Settings) -> None:
    token = create_access_token(user_id=7, username="admin", role="admin", settings=settings)
    payload = decode_token(token, settings=settings)

    assert payload.user_id == 7
    assert payload.username == "admin"
    assert payload.role == "admin"
    assert payload.token_type is TokenType.ACCESS
    assert payload.jti


def test_dos_tokens_seguidos_no_son_el_mismo(settings: Settings) -> None:
    """El `jti` los distingue. Hara falta el dia que se revoquen de uno en uno."""
    primero = create_access_token(user_id=1, username="a", role="viewer", settings=settings)
    segundo = create_access_token(user_id=1, username="a", role="viewer", settings=settings)
    assert primero != segundo


def test_la_caducidad_sale_de_la_configuracion(settings: Settings) -> None:
    token = create_access_token(user_id=1, username="a", role="viewer", settings=settings)
    payload = decode_token(token, settings=settings)
    esperado = datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes)

    assert abs((payload.expires_at - esperado).total_seconds()) < 5


def test_el_refresh_dura_dias_y_el_access_minutos(settings: Settings) -> None:
    access = decode_token(
        create_access_token(user_id=1, username="a", role="viewer", settings=settings),
        settings=settings,
    )
    refresh = decode_token(
        create_refresh_token(user_id=1, username="a", role="viewer", settings=settings),
        settings=settings,
        expected_type=TokenType.REFRESH,
    )
    assert refresh.expires_at > access.expires_at


# --------------------------------------------------------------------------- #
# Tokens: lo que hay que rechazar
# --------------------------------------------------------------------------- #


def test_un_refresh_no_vale_como_access(settings: Settings) -> None:
    """El fallo que hace inutil el ACCESS_TOKEN_EXPIRE_MINUTES si no se comprueba."""
    refresh = create_refresh_token(user_id=1, username="a", role="admin", settings=settings)

    with pytest.raises(AuthError) as excinfo:
        decode_token(refresh, settings=settings)

    assert excinfo.value.code == "token_wrong_type"


def test_un_access_no_vale_como_refresh(settings: Settings) -> None:
    access = create_access_token(user_id=1, username="a", role="admin", settings=settings)

    with pytest.raises(AuthError) as excinfo:
        decode_token(access, settings=settings, expected_type=TokenType.REFRESH)

    assert excinfo.value.code == "token_wrong_type"


def test_un_token_caducado_se_distingue_de_uno_invalido(settings: Settings) -> None:
    """La diferencia le sirve al cliente: uno se arregla refrescando, el otro no."""
    ayer = datetime.now(UTC) - timedelta(days=1)
    token = _firmar(_claims_validos(settings, iat=ayer, exp=ayer + timedelta(minutes=1)), settings)

    with pytest.raises(AuthError) as excinfo:
        decode_token(token, settings=settings)

    assert excinfo.value.code == "token_expired"


def test_un_token_firmado_con_otra_clave_no_pasa(settings: Settings) -> None:
    token = _firmar(_claims_validos(settings), settings, clave="otra-clave-distinta")

    with pytest.raises(AuthError) as excinfo:
        decode_token(token, settings=settings)

    assert excinfo.value.code == "token_invalid"


def test_un_token_manipulado_no_pasa(settings: Settings) -> None:
    """Cambiar un caracter del payload invalida la firma."""
    token = create_access_token(user_id=1, username="a", role="viewer", settings=settings)
    cabecera, payload, firma = token.split(".")
    manipulado = f"{cabecera}.{payload[:-2]}XY.{firma}"

    with pytest.raises(AuthError):
        decode_token(manipulado, settings=settings)


def test_un_token_sin_firma_no_pasa(settings: Settings) -> None:
    """`alg: none`, el ataque de manual.

    Se construye a mano y no con PyJWT para que el test siga probando el ataque
    aunque la libreria decida un dia negarse a generarlo.
    """

    def b64(datos: dict[str, object]) -> str:
        crudo = json.dumps(datos).encode()
        return base64.urlsafe_b64encode(crudo).decode().rstrip("=")

    claims = _claims_validos(settings)
    claims["exp"] = int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())
    claims["iat"] = int(datetime.now(UTC).timestamp())
    token = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(claims)}."

    with pytest.raises(AuthError) as excinfo:
        decode_token(token, settings=settings)

    assert excinfo.value.code == "token_invalid"


def test_un_token_sin_caducidad_no_pasa(settings: Settings) -> None:
    """Un JWT sin `exp` es una llave que no caduca nunca."""
    claims = _claims_validos(settings)
    del claims["exp"]

    with pytest.raises(AuthError) as excinfo:
        decode_token(_firmar(claims, settings), settings=settings)

    assert excinfo.value.code == "token_invalid"


@pytest.mark.parametrize("sub", ["no-soy-un-numero", "", None])
def test_un_sub_que_no_es_un_id_no_pasa(settings: Settings, sub: object) -> None:
    token = _firmar(_claims_validos(settings, sub=sub), settings)

    with pytest.raises(AuthError) as excinfo:
        decode_token(token, settings=settings)

    assert excinfo.value.code == "token_invalid"


def test_basura_en_vez_de_un_token(settings: Settings) -> None:
    for basura in ("", "abc", "a.b.c", "Bearer algo"):
        with pytest.raises(AuthError):
            decode_token(basura, settings=settings)
