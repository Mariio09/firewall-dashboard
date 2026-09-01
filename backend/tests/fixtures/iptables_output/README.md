# Fixtures de iptables

Salidas **literales** capturadas de la VM `firewall-lab` el 2026-09-01, paso A2.
No se editan a mano: se regeneran con `make recon` desde la raíz del repo.

Entorno de captura: Ubuntu sobre Multipass, `iptables v1.8.11 (nf_tables)`,
todos los comandos con `LC_ALL=C`.

| Archivo | Comando | Notas |
|---|---|---|
| `version.txt` | `iptables --version` | Fija la versión contra la que se diseñó el parser |
| `error_chain_missing.txt` | `iptables -S FWDASH_NOEXISTE` | **stderr**, stdout vacío, **exit code 1** |
| `limpio/save.txt` | `iptables -S` | VM virgen: tres políticas, cero reglas |
| `limpio/list_verbose.txt` | `iptables -L -v -n` | Cabeceras de cadena vacías |
| `cargado/save.txt` | `iptables -S` | Con el ruleset de `infra/scripts/recon_seed.sh` |
| `cargado/list_verbose.txt` | `iptables -L -v -n` | Contadores **abreviados** (`500K`, `42M`) |
| `cargado/list_verbose_exact.txt` | `iptables -L -v -n -x` | Contadores exactos. Es la forma que usa la app |
| `cargado/iptables_save.txt` | `iptables-save` | Contadores por cadena en `[pkts:bytes]` |

## Lo que estas fixtures existen para demostrar

- iptables **reescribe** la regla al guardarla: comparar `cargado/save.txt` con el argv de
  `recon_seed.sh` es el test de que el parser no puede comparar texto.
- Los contadores se abrevian sin `-x`.
- Las columnas de `-L -v -n` no son de ancho fijo.
- El error de cadena inexistente dice `No chain/target/match by that name`, que es el
  **mismo** mensaje que para un match inexistente: no se puede distinguir por el texto.

## Sobre las IPs

No hay nada que anonimizar y **no se deben tocar**: la VM se capturó virgen, así que todas
las reglas salieron de `recon_seed.sh`. `8.8.8.8`, `10.0.0.0/8` y `192.168.64.0/24` son
literales inventados (la última es la subred host-only por defecto de Multipass en macOS,
igual en cualquier Mac). Editarlas solo serviría para que las fixtures dejaran de ser
literales, que es justo lo que las hace valer.
