/**
 * Banner de drift. Bloque A6.
 *
 * `missing` y `pending` son las dos mitades de "esta en la DB y no en
 * iptables", y solo la primera es drift: una regla recien creada aun no se ha
 * aplicado, y eso es normal. Por eso aqui solo se pintan las cadenas con
 * `has_drift`, y se enseña la linea original de `iptables -S` sin interpretarla:
 * cuando toca explicar por que una cadena no cuadra, la interpretacion sobra.
 */
import type { ChainDrift } from "@/api/types";
import { useEstadoDelFirewall } from "@/features/firewall/useFirewall";

function Cadena({ cadena }: { cadena: ChainDrift }) {
  // Las listas llevan `default_factory` en el backend, asi que el OpenAPI las
  // marca como opcionales: no vienen cuando estan vacias.
  const faltan = cadena.missing ?? [];
  const sobran = cadena.unexpected ?? [];

  return (
    <li className="drift__cadena">
      <strong>{cadena.chain}</strong>
      {faltan.length > 0 && (
        <span> — {faltan.length} regla(s) que se creian aplicadas no estan en la cadena</span>
      )}
      {cadena.out_of_order === true && <span> — estan todas, pero en otro orden</span>}
      {sobran.length > 0 && (
        <ul className="drift__lineas">
          {sobran.map((linea) => (
            <li key={linea}>
              <code>{linea}</code>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

export function BannerDeDrift() {
  const { data } = useEstadoDelFirewall();

  if (data === undefined) return null;

  if (!data.scaffold_ok) {
    return (
      <div className="aviso aviso--error" role="alert">
        Las cadenas gestionadas <code>FWDASH_*</code> no existen. Nada de lo que hay en la
        base de datos esta aplicado al sistema.
      </div>
    );
  }

  if (!data.has_drift) return null;

  const conDrift = data.chains.filter((cadena) => cadena.has_drift);

  return (
    <div className="aviso aviso--drift" role="alert">
      <p className="aviso__titulo">
        El firewall no coincide con la base de datos. Alguien lo ha tocado por fuera.
      </p>
      <ul className="drift__lista">
        {conDrift.map((cadena) => (
          <Cadena key={cadena.chain} cadena={cadena} />
        ))}
      </ul>
      <p className="aviso__pie">
        La base de datos manda (ADR-0001): «Aplicar» reconstruye las tres cadenas y borra lo
        que no salga de ella.
      </p>
    </div>
  );
}
