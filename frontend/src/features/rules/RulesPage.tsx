/**
 * La pantalla principal: una cadena, sus reglas y lo que se puede hacer con
 * ellas. Bloque A6.
 *
 * Se navega por cadenas y no por una lista unica porque el orden solo significa
 * algo dentro de una cadena, y porque `/rules/reorder` exige mandar la cadena
 * entera. Por lo mismo se piden hasta 500 reglas de golpe: paginar dentro de
 * una cadena impediria reordenarla. Una cadena con mas de 500 reglas queda
 * fuera del MVP y el aviso lo dice en pantalla en vez de mentir.
 */
import { useEffect, useState } from "react";

import { CADENAS, tieneRol, type Chain } from "@/api/types";
import { AvisoDeError } from "@/components/ui/AvisoDeError";
import { useAuth } from "@/features/auth/useAuth";
import { BannerDeDrift } from "@/features/firewall/BannerDeDrift";
import { DialogoDeAplicar } from "@/features/firewall/DialogoDeAplicar";
import { FormularioDeRegla } from "@/features/rules/FormularioDeRegla";
import { TablaDeReglas } from "@/features/rules/TablaDeReglas";
import { useReglas } from "@/features/rules/useRules";

const TAMANO = 500;

type Edicion = { abierta: false } | { abierta: true; uuid: string | null };

export function RulesPage() {
  const { usuario } = useAuth();
  const puedeMutar = tieneRol(usuario?.role, "operator");

  const [chain, setChain] = useState<Chain>("INPUT");
  const [busqueda, setBusqueda] = useState("");
  const [q, setQ] = useState("");
  const [soloActivas, setSoloActivas] = useState<"todas" | "si" | "no">("todas");
  const [edicion, setEdicion] = useState<Edicion>({ abierta: false });
  const [aplicando, setAplicando] = useState(false);

  // Un `fetch` por tecla convertiria el buscador en un ataque a tu propio
  // backend.
  useEffect(() => {
    const temporizador = setTimeout(() => setQ(busqueda.trim()), 300);
    return () => clearTimeout(temporizador);
  }, [busqueda]);

  const enabled = soloActivas === "todas" ? undefined : soloActivas === "si";
  const filtrado = q !== "" || enabled !== undefined;

  const reglas = useReglas({ chain, q: q || undefined, enabled, page: 1, size: TAMANO });
  const items = reglas.data?.items ?? [];
  const total = reglas.data?.total ?? 0;

  return (
    <div className="pagina">
      <BannerDeDrift />

      <div className="barra">
        <nav className="pestanas" aria-label="Cadenas">
          {CADENAS.map((cadena) => (
            <button
              key={cadena}
              type="button"
              className={`pestana${cadena === chain ? " pestana--activa" : ""}`}
              onClick={() => setChain(cadena)}
            >
              {cadena}
            </button>
          ))}
        </nav>

        <div className="barra__filtros">
          <input
            className="campo__control campo__control--busqueda"
            type="search"
            placeholder="Buscar en nombre y descripcion…"
            value={busqueda}
            onChange={(e) => setBusqueda(e.target.value)}
          />
          <select
            className="campo__control"
            value={soloActivas}
            onChange={(e) => setSoloActivas(e.target.value as "todas" | "si" | "no")}
            aria-label="Filtrar por estado"
          >
            <option value="todas">Activas e inactivas</option>
            <option value="si">Solo activas</option>
            <option value="no">Solo inactivas</option>
          </select>
        </div>

        <div className="barra__acciones">
          {puedeMutar && (
            <>
              <button type="button" className="boton" onClick={() => setAplicando(true)}>
                Aplicar…
              </button>
              <button
                type="button"
                className="boton boton--primario"
                onClick={() => setEdicion({ abierta: true, uuid: null })}
              >
                Nueva regla
              </button>
            </>
          )}
        </div>
      </div>

      <AvisoDeError error={reglas.error} />

      {reglas.isPending ? (
        <p className="vacio">Cargando reglas…</p>
      ) : (
        <>
          <TablaDeReglas
            reglas={items}
            puedeMutar={puedeMutar}
            puedeReordenar={!filtrado}
            motivoSinReordenar={
              filtrado
                ? "Para reordenar, quita los filtros: el backend exige la cadena entera y una vista filtrada no la tiene."
                : undefined
            }
            onEditar={(uuid) => setEdicion({ abierta: true, uuid })}
            atenuada={reglas.isFetching}
          />
          <p className="pie">
            {total} regla(s) en {chain}
            {total > TAMANO && ` · solo se muestran las primeras ${TAMANO}`}
          </p>
        </>
      )}

      {edicion.abierta && (
        <FormularioDeRegla
          uuid={edicion.uuid}
          chainPorDefecto={chain}
          onCerrar={() => setEdicion({ abierta: false })}
        />
      )}

      {aplicando && <DialogoDeAplicar onCerrar={() => setAplicando(false)} />}
    </div>
  );
}
