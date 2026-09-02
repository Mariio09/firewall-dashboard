/**
 * Aplicar, pasando antes por el preview. Bloque A6.
 *
 * El boton no aplica directamente: primero enseña el argv exacto que se va a
 * ejecutar. Es la mitigacion nº2 del problema del auto-bloqueo, y el motivo de
 * que `preview` exista en el contrato. Los comandos llegan como texto listo
 * para leer o pegar en un terminal; `shlex.join` no ha perdido nada por el
 * camino, sigue siendo el argv exacto.
 */
import { useState } from "react";

import { AvisoDeError } from "@/components/ui/AvisoDeError";
import { Modal } from "@/components/ui/Modal";
import { useAplicar, usePreview } from "@/features/firewall/useFirewall";

export function DialogoDeAplicar({ onCerrar }: { onCerrar: () => void }) {
  const preview = usePreview(true);
  const aplicar = useAplicar();
  const [aplicado, setAplicado] = useState(false);

  const total = (preview.data?.chains ?? []).reduce(
    (suma, cadena) => suma + cadena.commands.length,
    0,
  );

  return (
    <Modal titulo="Aplicar la politica al firewall" onCerrar={onCerrar} ancho="ancho">
      {preview.isPending && <p className="vacio">Calculando los comandos…</p>}
      <AvisoDeError error={preview.error} />

      {preview.data !== undefined && (
        <>
          <p className="dialogo__intro">
            Se vaciaran y reconstruiran las tres cadenas gestionadas. Estos son los{" "}
            <strong>{total}</strong> comandos que se ejecutarian, en este orden:
          </p>

          {preview.data.chains.map((cadena) => (
            <section key={cadena.chain} className="preview__cadena">
              <h3 className="preview__titulo">
                {cadena.chain}
                <span className="preview__cuenta">{cadena.applied} regla(s) de usuario</span>
              </h3>
              <pre className="preview__comandos">
                {cadena.commands.length > 0
                  ? cadena.commands.join("\n")
                  : "# sin comandos para esta cadena"}
              </pre>
            </section>
          ))}
        </>
      )}

      <AvisoDeError error={aplicar.error} />
      {aplicado && !aplicar.isError && (
        <p className="aviso aviso--ok" role="status">
          Aplicado. Las tres cadenas se han reconstruido desde la base de datos.
        </p>
      )}

      <footer className="dialogo__pie">
        <button type="button" className="boton" onClick={onCerrar}>
          {aplicado ? "Cerrar" : "Cancelar"}
        </button>
        <button
          type="button"
          className="boton boton--primario"
          disabled={preview.data === undefined || aplicar.isPending}
          onClick={() => {
            aplicar.mutate(undefined, { onSuccess: () => setAplicado(true) });
          }}
        >
          {aplicar.isPending ? "Aplicando…" : "Aplicar ahora"}
        </button>
      </footer>
    </Modal>
  );
}
