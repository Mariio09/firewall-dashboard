"""firewall-dashboard — backend.

Gestion de reglas de iptables con dashboard web. Proyecto de portfolio de
ciberseguridad defensiva.

Las dependencias entre paquetes van en UNA sola direccion:

    api/  ->  services/  ->  firewall/  +  models/
                  |
                 db/                       core/  (accesible desde todos)

Es decir: un router nunca importa `firewall/`, un servicio nunca importa
`fastapi`, y el paquete `firewall/` no sabe que existe una base de datos ni una
API. Romper esa regla rompe la testabilidad del proyecto entero, asi que
`tests/unit/test_architecture.py` la verifica automaticamente.
"""

__version__ = "0.0.1"
