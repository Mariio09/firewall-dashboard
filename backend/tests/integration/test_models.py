"""Los modelos, contra una SQLite de verdad.

Las constraints que no se prueban no existen: un CHECK mal escrito no se nota
hasta que alguien guarda basura, y entonces ya esta guardada.
"""

from __future__ import annotations

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from app.firewall.spec import Action, Chain, Protocol, SyncState, Table
from app.models import Rule, User
from app.models.user import Role


def _regla(**kwargs: object) -> Rule:
    valores: dict[str, object] = {
        "name": "Bloquear escaner",
        "chain": Chain.INPUT,
        "action": Action.DROP,
        "position": 10,
    }
    valores.update(kwargs)
    return Rule(**valores)


def test_una_regla_nace_pendiente_de_aplicar(db_session: Session) -> None:
    """El estado por defecto es `pending`, no `applied`.

    Es la distincion central del diseño: existir en la base de datos y estar
    aplicada en iptables son dos cosas distintas (ADR-0001).
    """
    regla = _regla()
    db_session.add(regla)
    db_session.commit()

    assert regla.sync_state is SyncState.PENDING
    assert regla.enabled is True
    assert regla.protocol is Protocol.ALL
    assert regla.table_name is Table.FILTER
    assert regla.ip_version == 4
    assert regla.hit_count == 0
    assert regla.created_at.tzinfo is not None, "los datetime deben llevar zona horaria"


def test_el_uuid_se_genera_solo_y_es_unico(db_session: Session) -> None:
    """Es el identificador publico y la etiqueta de la regla dentro de iptables."""
    primera, segunda = _regla(position=10), _regla(position=20)
    db_session.add_all([primera, segunda])
    db_session.commit()

    assert len(primera.uuid) == 36
    assert primera.uuid != segunda.uuid


def test_dos_reglas_no_pueden_ocupar_la_misma_posicion(db_session: Session) -> None:
    """En iptables el orden ES la semantica: gana la primera que hace match."""
    db_session.add_all([_regla(position=10), _regla(position=10)])
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_la_misma_posicion_en_otra_cadena_si_vale(db_session: Session) -> None:
    """Cada cadena tiene su propio orden; INPUT y OUTPUT no compiten."""
    db_session.add_all([_regla(position=10), _regla(chain=Chain.OUTPUT, position=10)])
    db_session.commit()
    assert len(db_session.scalars(select(Rule)).all()) == 2


def test_se_rechaza_una_accion_inventada(db_session: Session) -> None:
    """Por el ORM la basura no llega ni a salir del proceso.

    `validate_strings=True` en `str_enum` corta al preparar el bind, asi que lo
    que sube es un `StatementError` envolviendo un `LookupError`, nunca el
    `IntegrityError` de la base. El CHECK se prueba en el test siguiente.
    """
    db_session.add(_regla(action="DESTROY"))
    with pytest.raises(StatementError):
        db_session.commit()


def test_el_check_de_la_accion_existe_en_la_base(db_session: Session) -> None:
    """Y si alguien esquiva el ORM, el CHECK sigue estando.

    Entrar por SQL crudo es la unica forma de comprobar que el
    `create_constraint=True` de `str_enum` produjo un CHECK de verdad; con el
    ORM delante nunca se llega a ejecutar.
    """
    db_session.add(_regla())
    db_session.commit()
    with pytest.raises(IntegrityError):
        db_session.execute(text("UPDATE rules SET action = 'DESTROY'"))


def test_se_rechaza_una_version_de_ip_imposible(db_session: Session) -> None:
    db_session.add(_regla(ip_version=5))
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_pedir_log_sin_prefijo_es_incoherente(db_session: Session) -> None:
    """Sin prefijo no habria forma de atar la linea de syslog a esta regla."""
    db_session.add(_regla(log_enabled=True))
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_borrar_un_usuario_no_borra_sus_reglas(db_session: Session) -> None:
    """`ON DELETE SET NULL`: la politica de firewall sobrevive a su autor.

    Este test comprueba de paso que `PRAGMA foreign_keys=ON` esta activo: sin
    el, SQLite ignoraria la clausula entera y el campo se quedaria apuntando a
    un usuario inexistente.
    """
    usuario = User(username="mario", hashed_password="x", role=Role.ADMIN)
    db_session.add(usuario)
    db_session.commit()

    regla = _regla(created_by_id=usuario.id)
    db_session.add(regla)
    db_session.commit()

    # DELETE por SQL directo y no `session.delete()`: el ORM nulificaria la
    # clave por su cuenta y el test pasaria aunque la base de datos no estuviera
    # aplicando nada. Asi se comprueba la constraint de verdad.
    db_session.execute(delete(User).where(User.id == usuario.id))
    db_session.commit()
    db_session.expire_all()

    superviviente = db_session.scalars(select(Rule)).one()
    assert superviviente.created_by_id is None


def test_el_username_es_unico(db_session: Session) -> None:
    db_session.add_all(
        [
            User(username="mario", hashed_password="x"),
            User(username="mario", hashed_password="y"),
        ]
    )
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_un_usuario_nuevo_solo_puede_mirar(db_session: Session) -> None:
    """El rol por defecto es el menos privilegiado."""
    usuario = User(username="invitado", hashed_password="x")
    db_session.add(usuario)
    db_session.commit()
    assert usuario.role is Role.VIEWER
    assert usuario.is_active is True
