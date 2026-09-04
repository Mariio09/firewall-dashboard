"""Backend real. Es el unico modulo que habla con el sistema, via `CommandRunner`.

Bloque B3. Todo lo demas de este paquete ya esta construido y testeado cuando se
llega aqui: este archivo solo pega `renderer` (que produce argv), `runner` (que los
ejecuta) y `parser` (que lee la respuesta).

No contiene logica de validacion: cuando una `RuleSpec` llega hasta aqui, ya es
valida por construccion.

Estrategia de aplicacion (ADR-0002): flush de la cadena gestionada + append de
todas las reglas en orden. La evolucion natural, si el rendimiento llegara a
importar, es construir el ruleset completo y aplicarlo de una vez con
`iptables-restore -n`, que ademas es atomico.

TRES DECISIONES QUE SE TOMARON AL IMPLEMENTARLO (B3)

1. **La existencia de una cadena se PREGUNTA, no se deduce.** iptables da el mismo
   texto (`No chain/target/match by that name.`) y el mismo exit code generico
   para una cadena inexistente, un target inexistente y un match inexistente
   (medido en A2, ver la nota `CommandRunner y subprocess`). Ramificar sobre ese
   string seria adivinar. Por eso todo lo que necesita una cadena empieza por
   `_exigir_cadena`, que sondea con `-L <cadena> -n` y `check=False` -- que es
   exactamente para lo que B2 dejo ese parametro.

2. **Este backend no emite `-t`.** El renderer tampoco, porque `filter` es la
   tabla por defecto de iptables y el MVP no usa otra. Emitirlo aqui y no alli
   haria que el argv del preview dejara de ser el argv que se ejecuta. En vez de
   eso el constructor RECHAZA cualquier tabla que no sea `filter`: un parametro
   que se acepta y se ignora es peor que uno que no existe, porque el dia que
   alguien escriba `IPTABLES_TABLE=nat` creera que ha configurado algo.

3. **Ni `-w` ni reintentos.** Con el lock de xtables ocupado (ufw, Docker),
   iptables falla en el acto con exit 4 en vez de colgarse; y como `apply_ruleset`
   es idempotente, reintentar es gratis y no hay estado a medias que reparar.
   Añadir `-w` obligaria a emitirlo tambien en el renderer para que el fake y el
   preview no mintieran, y eso es tocar A3 para resolver un problema que aqui no
   existe -> queda anotado como deuda.

QUE PASA SI UN COMANDO FALLA A MITAD

No hay transaccion: los comandos se ejecutan en orden y el primero que falla
aborta el resto. La cadena queda a medias, y eso es deliberado y seguro, no un
descuido: el renderer emite `-F` y **acto seguido los guardianes**, asi que
cualquier corte posterior deja una cadena con menos reglas de usuario de las
pedidas pero con el acceso a la VM y a la API intactos. El caso contrario --
guardianes a medias -- solo puede darse si falla el propio `-F` o el primer
guardian, y entonces no se ha llegado a vaciar nada. La reparacion es volver a
llamar a `apply_ruleset` con las mismas specs.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.core.exceptions import FirewallCommandError, InvalidRuleError
from app.firewall import validators
from app.firewall.parser import parse_counters, parse_save_format
from app.firewall.renderer import IPTABLES, render_ruleset
from app.firewall.runner import DEFAULT_TIMEOUT_SECONDS, CommandResult, CommandRunner
from app.firewall.spec import ApplyResult, Chain, Counters, NativeRule, RuleSpec, Table

__all__ = ["MAX_SALTOS_DUPLICADOS", "IptablesBackend"]

#: Numero maximo de saltos duplicados que `teardown` intenta borrar de una cadena
#: del sistema. `ensure_scaffold` no crea duplicados -- pregunta con `-C` antes de
#: insertar --, pero una mano ajena si puede, y un bucle sin tope sobre un comando
#: que siempre devuelve 0 seria un cuelgue.
MAX_SALTOS_DUPLICADOS = 16


class IptablesBackend:
    """Implementacion de `FirewallBackend` sobre iptables real.

    El `CommandRunner` se inyecta por constructor: esa es la costura que permite
    testear la construccion del argv y el parseo sin ejecutar iptables.

    Es APATRIDA. No guarda ni una regla: el estado vive en el kernel. Por eso
    compartir una sola instancia entre peticiones (`app.state`) no le cambia nada,
    al contrario que al fake.
    """

    def __init__(
        self,
        runner: CommandRunner,
        *,
        chain_prefix: str = "FWDASH",
        table: str = "filter",
        management_port: int = 8000,
        # 127.0.0.0/8 y no una red plausible: este default solo lo usan los tests
        # y quien construya el backend a mano —`deps` siempre pasa el valor de
        # `Settings`, que desde el ADR-0016 es obligatorio con backend real—. Un
        # CIDR de gestion que parece bueno y no lo es escribe la regla guardian
        # que te bloquea, asi que aqui tampoco se deja uno que engañe.
        management_cidr: str = "127.0.0.0/8",
        # Opcional y sin default (ADR-0017): protege el canal de rescate SOLO si
        # se declara. `None` = el 22 se filtra como cualquier otro puerto.
        management_ssh_port: int | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if table != Table.FILTER.value:
            # Ver la decision 2 de la cabecera: aqui no se emite `-t`, asi que
            # aceptar otra tabla seria prometer algo que no se cumple.
            raise InvalidRuleError(
                f"El MVP solo gestiona la tabla '{Table.FILTER.value}', no '{table}'.",
                details={"campo": "iptables_table", "valor": table},
            )
        self._runner = runner
        self._chain_prefix = chain_prefix
        self._table = table
        self._management_port = management_port
        self._management_cidr = management_cidr
        self._management_ssh_port = management_ssh_port
        self._timeout = timeout

    # ----------------------------------------------------------------------- #
    # Interno
    # ----------------------------------------------------------------------- #

    def _ejecutar(self, argv: list[str], *, check: bool = True) -> CommandResult:
        """Unica puerta al runner, para que el timeout configurado no se olvide.

        El `CommandRunner` recibe el timeout POR LLAMADA y no en su constructor
        (B2), asi que sin un sitio unico que lo inyecte bastaria con escribir una
        llamada suelta al runner para que ese comando corriese con el valor por
        defecto y no con el del `.env`. Es la clase de bug que solo se nota el dia
        que iptables se queda esperando el lock.
        """
        return self._runner.run(argv, timeout=self._timeout, check=check)

    def _nombre_cadena(self, chain: Chain) -> str:
        """'FWDASH' + INPUT -> 'FWDASH_INPUT', validado.

        Se valida en cada llamada y no una sola vez en el constructor a proposito:
        es lo mismo que hace el fake, y asi los dos backends fallan igual ante un
        prefijo invalido en vez de hacerlo en momentos distintos del arranque.
        """
        return validators.validate_managed_chain_name(self._chain_prefix, chain)

    def _existe_cadena(self, nombre: str) -> bool:
        """Sondeo de existencia. `check=False`: aqui el fallo es la respuesta.

        `-L <cadena> -n` es la pregunta mas barata que responde exactamente esto:
        `-n` evita la resolucion inversa de DNS, que es lo que hace lento a
        `iptables -L`, y no imprime contadores que nadie va a leer.
        """
        return self._ejecutar([IPTABLES, "-L", nombre, "-n"], check=False).ok

    def _exigir_cadena(self, chain: Chain) -> str:
        """Devuelve el nombre de la cadena gestionada, o falla si no existe.

        El mensaje NO copia el de iptables. El suyo es ambiguo por diseño y no
        distingue una cadena inexistente de un match inexistente; este sondeo si
        ha preguntado por la cadena, asi que puede decir lo que iptables no puede.
        `details` lleva solo el nombre de la cadena: viaja al cliente.
        """
        nombre = self._nombre_cadena(chain)
        if not self._existe_cadena(nombre):
            raise FirewallCommandError(
                f"La cadena gestionada '{nombre}' no existe. Falta ensure_scaffold().",
                details={"chain": nombre},
            )
        return nombre

    def _comandos(self, chain: Chain, nombre: str, specs: Sequence[RuleSpec]) -> list[list[str]]:
        """El nombre de la cadena se PASA, no se recalcula.

        Quien llama ya lo ha obtenido de `_exigir_cadena`, y volver a construirlo
        aqui abriria la puerta a que el nombre comprobado y el nombre escrito
        fueran dos cosas distintas.
        """
        return render_ruleset(
            chain,
            nombre,
            specs,
            management_port=self._management_port,
            management_cidr=self._management_cidr,
            management_ssh_port=self._management_ssh_port,
        )

    # ----------------------------------------------------------------------- #
    # FirewallBackend
    # ----------------------------------------------------------------------- #

    def ensure_scaffold(self) -> None:
        """Crea las cadenas `FWDASH_*` y el salto desde INPUT/OUTPUT/FORWARD.

        Idempotente por PREGUNTA, no por tolerancia al error: se sondea si la
        cadena existe y si el salto existe, y solo se escribe lo que falta. La
        alternativa -- lanzar `-N` y tragarse el fallo -- no distinguiria "ya
        estaba" de "no tengo privilegios", que es justo el fallo que hay que ver.

        El salto se inserta en la POSICION 1 (`-I <cadena> 1`) para que la politica
        de la aplicacion se evalue antes que lo que hubiera en la cadena del
        sistema. La cadena gestionada termina con el RETURN implicito de iptables,
        asi que un paquete sin match vuelve y sigue su curso: se filtra, no se
        sustituye la politica del host (ADR-0002).
        """
        for chain in Chain:
            nombre = self._nombre_cadena(chain)

            if not self._existe_cadena(nombre):
                self._ejecutar([IPTABLES, "-N", nombre])

            # `-C` pregunta si la regla existe: 0 si esta, distinto de 0 si no.
            # Sin este sondeo, cada arranque del servicio añadiria otro salto.
            salto = [IPTABLES, "-C", chain.value, "-j", nombre]
            if not self._ejecutar(salto, check=False).ok:
                self._ejecutar([IPTABLES, "-I", chain.value, "1", "-j", nombre])

    def apply_ruleset(
        self,
        chain: Chain,
        specs: Sequence[RuleSpec],
        *,
        dry_run: bool = False,
    ) -> ApplyResult:
        """Reconstruye la cadena gestionada para que contenga exactamente `specs`.

        Primero se renderiza ENTERO y solo despues se ejecuta nada. Una spec de
        otra cadena hace fallar al renderer, y entonces no se ha tocado el sistema:
        la cadena sigue como estaba en vez de quedarse vaciada a medias.

        `dry_run` tambien exige que la cadena exista, aunque no vaya a ejecutar
        nada. Un preview de comandos que no se podrian ejecutar es una mentira
        barata de evitar, y es ademas lo que hace el fake: dos backends que
        responden distinto a lo mismo es justo el riesgo del que avisa
        docs/ARCHITECTURE.md §8.
        """
        nombre = self._exigir_cadena(chain)
        comandos = self._comandos(chain, nombre, specs)

        if not dry_run:
            for comando in comandos:
                # `check=True`: el primer fallo aborta. Ver la cabecera del modulo
                # sobre por que la cadena a medias es segura y como se repara.
                self._ejecutar(comando)

        return ApplyResult(
            chain=chain,
            applied=len(specs),
            commands=tuple(tuple(comando) for comando in comandos),
            dry_run=dry_run,
        )

    def read_ruleset(self, chain: Chain) -> list[NativeRule]:
        """Lee el estado real de la cadena gestionada, para detectar drift.

        Se lee con `-S` y no con `-L -v -n`: `iptables -S` imprime igual en todas
        las versiones probadas, mientras que el formato tabular cambio entre la
        1.8.10 y la 1.8.11 (la columna `prot` pasa de numero a nombre). Los
        contadores, que solo estan en el tabular, se piden aparte -> nota
        `Normalizacion de iptables`.
        """
        nombre = self._exigir_cadena(chain)
        salida = self._ejecutar([IPTABLES, "-S", nombre]).stdout
        return parse_save_format(salida, nombre)

    def read_counters(self, chain: Chain) -> dict[str, Counters]:
        """Contadores de paquetes/bytes indexados por el uuid corto de cada regla.

        `-x` NO es opcional (hallazgo de A2): sin el, iptables abrevia los numeros
        a `500K` y un parser que haga `int()` funciona los primeros mil paquetes y
        revienta despues, con trafico real. Es el fallo perfecto: invisible en
        desarrollo -> nota `Contadores de reglas`.

        Los guardianes no aparecen en el resultado: su etiqueta es
        `fwdash:guardian:*` y el parser no le saca uuid, porque no salen de la
        tabla `rules` y no hay fila a la que devolverles el contador.
        """
        nombre = self._exigir_cadena(chain)
        salida = self._ejecutar([IPTABLES, "-L", nombre, "-v", "-n", "-x"]).stdout
        return parse_counters(salida)

    def teardown(self) -> None:
        """Elimina saltos y cadenas. Deja el sistema como estaba antes de la app.

        Todo con `check=False`: desmontar tiene que funcionar sobre un montaje
        COMPLETO, sobre uno a medias y sobre uno que no existe, y en los tres casos
        terminar sin ruido. Un `teardown` que falla porque algo ya no estaba es un
        `teardown` que no se puede llamar dos veces, y esto es exactamente lo que
        se llama cuando algo ha ido mal.

        El orden no es negociable: iptables se niega a borrar (`-X`) una cadena con
        referencias, asi que primero el salto, luego el vaciado y al final la
        cadena.
        """
        for chain in Chain:
            nombre = self._nombre_cadena(chain)

            # Se borran TODOS los saltos, no uno: `-D` quita solo la primera
            # coincidencia, y un duplicado que quedara vivo dejaria la cadena con
            # referencias y el `-X` de abajo fallaria en silencio.
            salto = [IPTABLES, "-D", chain.value, "-j", nombre]
            for _ in range(MAX_SALTOS_DUPLICADOS):
                if not self._ejecutar(salto, check=False).ok:
                    break

            self._ejecutar([IPTABLES, "-F", nombre], check=False)
            self._ejecutar([IPTABLES, "-X", nombre], check=False)
