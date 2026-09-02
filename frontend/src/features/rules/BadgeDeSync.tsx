/**
 * El estado de sincronizacion de una regla. Bloque A6.
 *
 * Esta columna no es decorativa: es donde se ve un `failed` despues de un 201.
 * La regla existe en la base de datos y el firewall no ha podido aplicarla, y
 * esa distancia es justo lo que el diseño quiere hacer visible (ADR-0011).
 */
import type { SyncState } from "@/api/types";

const TONO: Record<SyncState, string> = {
  applied: "verde",
  pending: "ambar",
  failed: "rojo",
  drift: "rojo",
};

const TEXTO: Record<SyncState, string> = {
  applied: "aplicada",
  pending: "pendiente",
  failed: "fallo",
  drift: "drift",
};

export function BadgeDeSync({ estado, motivo }: { estado: SyncState; motivo?: string | null }) {
  return (
    <span
      className={`badge badge--${TONO[estado]} badge--pequeno`}
      title={motivo ?? undefined}
    >
      <span className="badge__punto" aria-hidden="true" />
      {TEXTO[estado]}
    </span>
  );
}
