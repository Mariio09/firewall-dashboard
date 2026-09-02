"""Schemas de reglas: RuleCreate / RuleUpdate / RuleRead / RuleListItem.

Bloque A5. Nunca reutilizar un schema para entrada y salida: acaba filtrando
campos internos. Ver docs/ARCHITECTURE.md §5.1.

Estos modelos son la PRIMERA de las tres validaciones que atraviesa una regla, y
la mas superficial a proposito (ver `firewall/spec.py`):

    RuleCreate (aqui)  -> protege el CONTRATO de la API
      -> Rule (SQLAlchemy) -> protege la INTEGRIDAD de los datos
        -> RuleSpec        -> protege el SISTEMA

Aqui se comprueban forma y longitud; que una IP sea una IP y que un puerto exista
lo decide `firewall/validators.py`, que es el unico modulo con permiso para
interpretar esos campos. Duplicar aqui esa logica seria garantizar que un dia las
dos copias digan cosas distintas.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.firewall.spec import Action, Chain, Protocol, SyncState, Table

__all__ = [
    # `Chain` se reexporta aqui a proposito. Los routers necesitan el enum para
    # tipar el filtro `?chain=` y que salga en el OpenAPI, pero `api/` tiene
    # prohibido importar `app.firewall` —lo verifica
    # `tests/unit/test_architecture.py`— para que ningun endpoint pueda hablar
    # con el firewall saltandose `services/`. La capa de schemas si puede, que es
    # exactamente su trabajo: traducir el dominio al contrato HTTP.
    "Chain",
    "ReorderRequest",
    "RuleCreate",
    "RuleListItem",
    "RuleRead",
    "RuleUpdate",
]

#: El nombre viaja dentro del `--comment` de la regla, asi que se recorta antes
#: de nada: un nombre con espacios al final produciria una etiqueta distinta de
#: la que el usuario cree haber escrito, y el drift se calcula sobre esa etiqueta.
Nombre = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]

#: Texto libre de un selector (IP, puerto, interfaz). El limite es el de la
#: columna; la forma la valida `firewall/validators.py`.
Direccion = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=45)]
Puerto = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=11)]
Interfaz = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=16)]
PrefijoDeLog = Annotated[str, StringConstraints(min_length=1, max_length=29)]


class _CamposDeRegla(BaseModel):
    """Los campos que el usuario controla. No se usa como entrada ni como salida.

    Existe para que `RuleCreate` no repita los limites que ya estan escritos
    arriba, y para que se lea de una vez que es lo que el usuario decide de una
    regla y que le viene dado.
    """

    name: Nombre
    description: str | None = None

    chain: Chain
    action: Action
    protocol: Protocol = Protocol.ALL

    src_ip: Direccion | None = None
    dst_ip: Direccion | None = None
    src_port: Puerto | None = None
    dst_port: Puerto | None = None
    in_interface: Interfaz | None = None
    out_interface: Interfaz | None = None

    enabled: bool = True
    log_enabled: bool = False
    #: Si se activa el log y no se manda prefijo, el servicio genera
    #: `FWD:<uuid8>`. Mandarlo es para quien ya tiene una convencion en syslog.
    log_prefix: PrefijoDeLog | None = None

    #: Bloqueos temporales. `AwareDatetime` y no `datetime`: un instante sin
    #: offset no significa nada —"las 22:00" son dos horas distintas segun quien
    #: lo escriba— y rechazarlo aqui da un 422 con una explicacion, en vez del
    #: 500 que daria la columna `UtcDateTime`.
    expires_at: AwareDatetime | None = None


class RuleCreate(_CamposDeRegla):
    """Alta de una regla.

    No lleva `position`: las reglas se añaden al final de su cadena y el orden se
    cambia con `POST /rules/reorder`. Dejar elegir la posicion en el alta
    obligaria a resolver colisiones con `UniqueConstraint(chain, position)` en
    cada insercion, y la UI arrastra filas, no escribe numeros.

    Tampoco lleva `table_name` ni `ip_version`: el MVP solo genera IPv4 en la
    tabla `filter`. Ambas columnas existen en el modelo para que añadir `nat` o
    ip6tables no exija migrar el esquema, pero aceptarlas hoy dejaria crear
    reglas que el renderer rechaza al aplicarlas: un error a destiempo y en el
    sitio equivocado.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Bloquear escaner del puerto 22",
                "description": "Rafagas de SSH desde este /24 desde el 28 de agosto.",
                "chain": "INPUT",
                "action": "DROP",
                "protocol": "tcp",
                "src_ip": "203.0.113.0/24",
                "dst_port": "22",
            }
        }
    )


class RuleUpdate(BaseModel):
    """Modificacion parcial: solo se toca lo que venga en el cuerpo.

    Todos los campos son opcionales y valen `None` por defecto, asi que "no lo
    mandes" y "ponlo a null" se escriben igual en JSON. El servicio los distingue
    con `model_dump(exclude_unset=True)`, que es la razon de que este schema no
    herede de `_CamposDeRegla`: alli `name`, `chain` y `action` son obligatorios,
    y aqui no puede serlo ninguno.
    """

    name: Nombre | None = None
    description: str | None = None

    chain: Chain | None = None
    action: Action | None = None
    protocol: Protocol | None = None

    src_ip: Direccion | None = None
    dst_ip: Direccion | None = None
    src_port: Puerto | None = None
    dst_port: Puerto | None = None
    in_interface: Interfaz | None = None
    out_interface: Interfaz | None = None

    enabled: bool | None = None
    log_enabled: bool | None = None
    log_prefix: PrefijoDeLog | None = None
    expires_at: AwareDatetime | None = None


class RuleListItem(BaseModel):
    """Una fila de la tabla del dashboard.

    Deliberadamente mas corta que `RuleRead`: `description` es donde se explica
    el porque de la regla y puede ser largo, y multiplicado por las filas de una
    pagina es la mayor parte de la respuesta sin que se vea en pantalla.
    """

    model_config = ConfigDict(from_attributes=True)

    uuid: str
    name: str
    chain: Chain
    action: Action
    protocol: Protocol
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: str | None = None
    dst_port: str | None = None
    position: int
    enabled: bool
    sync_state: SyncState
    hit_count: int
    bytes_count: int
    updated_at: datetime


class RuleRead(BaseModel):
    """Una regla completa, tal y como la ve la API.

    Incluye lo que el usuario no escribe pero necesita ver: en que estado de
    sincronizacion esta, cuando se aplico por ultima vez y por que fallo.
    """

    model_config = ConfigDict(from_attributes=True)

    uuid: str
    name: str
    description: str | None = None

    chain: Chain
    table_name: Table
    ip_version: int
    action: Action
    protocol: Protocol

    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: str | None = None
    dst_port: str | None = None
    in_interface: str | None = None
    out_interface: str | None = None

    position: int
    enabled: bool
    log_enabled: bool
    log_prefix: str | None = None
    expires_at: datetime | None = None

    sync_state: SyncState
    #: `stderr` ya saneado por el backend. El crudo se queda en el log.
    last_error: str | None = None
    applied_at: datetime | None = None

    hit_count: int
    bytes_count: int

    created_at: datetime
    updated_at: datetime
    #: El nombre, no el id: quien mira la tabla quiere leer "admin", y el id
    #: interno no significa nada fuera de la base de datos.
    created_by: str | None = None

    @field_validator("created_by", mode="before")
    @classmethod
    def _quedarse_con_el_nombre(cls, value: object) -> str | None:
        """La relacion trae un `User`; de el solo sale el nombre.

        Devolver el objeto entero seria filtrar `hashed_password` en cuanto
        alguien añadiera un schema anidado sin pensarlo dos veces.
        """
        if value is None or isinstance(value, str):
            return value
        nombre = getattr(value, "username", None)
        return nombre if isinstance(nombre, str) else None


class ReorderRequest(BaseModel):
    """Nuevo orden de una cadena, de la primera regla a la ultima.

    La lista tiene que contener TODAS las reglas de la cadena, no un
    subconjunto: un reorden parcial dejaria a las que faltan con posiciones
    antiguas que pueden chocar con las nuevas, y `UniqueConstraint(chain,
    position)` lo rechazaria a mitad de la operacion.

    La cadena no se manda en el cuerpo: se deduce de las reglas, y que todas
    sean de la misma cadena es parte de la validacion. Pedirla ademas solo
    añadiria una forma nueva de equivocarse —mandar una cadena que no es la de
    las reglas— sin aportar nada.
    """

    uuids: list[str] = Field(min_length=1, description="Uuids en el orden deseado.")
