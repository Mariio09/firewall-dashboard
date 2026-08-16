"""Dependencias compartidas de FastAPI.

Bloque A1+. Aqui vive `get_firewall_backend()`, que devuelve `FakeFirewallBackend`
o `IptablesBackend` segun `settings.firewall_backend`. Esa unica funcion es lo que
permite correr el MVP completo en el Mac y lo que hace el bloque C casi trivial."""
