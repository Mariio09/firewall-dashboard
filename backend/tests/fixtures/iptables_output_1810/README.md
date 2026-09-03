# Fixtures de `iptables 1.8.10` — capturadas en B0

Segundo juego de capturas reales, hermano de `iptables_output/` (que es de
**1.8.11**, capturado en A2). Mismo `recon_seed.sh`, misma VM `firewall-lab`,
distinta version de iptables.

## Por que existe

`iptables -L` **no imprime la columna `prot` igual en todas las versiones**:

```
1.8.11:   500K   42M ACCEPT     icmp --  lo     *   ...
1.8.10:   500K   42M ACCEPT     1    --  lo     *   ...
```

`icmp`→`1`, `tcp`→`6`, `udp`→`17`, `all`→`0`. Es una **regresion de la 1.8.10**
que la 1.8.11 arreglo, pero la arrastra **Ubuntu 24.04 LTS**, que es la imagen por
defecto de la VM. Sin traducir esos numeros, `parse_list_format` no lee mal:
lanza `ValueError: '6' is not a valid Protocol` y se lleva por delante la lectura
de la cadena entera.

`iptables -S` es **identico** en las dos versiones. Por eso `save.txt` esta aqui
solo para poder demostrarlo, y `parse_save_format` no necesito ningun cambio.

## Como se usan

`test_parser.py` compara los dos juegos y exige que produzcan **las mismas specs
y los mismos motivos**. El requisito no es "1.8.10 se lee", es "se lee igual".

Los contadores y las marcas de tiempo difieren entre juegos por fuerza: son dos
capturas distintas. Por eso la comparacion es de specs, no de `NativeRule`.

## Igual que el juego de A2

Son **datos, no codigo**: no se editan a mano y los formateadores no los tocan.
Para regenerarlos, `make recon FIXTURES=<destino>`; para compararlos sin
machacar nada, `make recon-diff`.
