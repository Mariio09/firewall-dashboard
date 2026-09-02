/**
 * El badge del header. Bloque A6.
 *
 * Un dashboard que solo enseñe la tabla `rules` esta enseñando una intencion.
 * Esto es lo que la convierte en un estado: que backend hay detras, si las
 * cadenas gestionadas existen, cuantas reglas siguen sin aplicar y cuando fue
 * la ultima aplicacion.
 */
import { fechaCompleta, haceCuanto } from "@/lib/format";
import { useEstadoDelFirewall } from "@/features/firewall/useFirewall";

export function EstadoBadge() {
  const { data, isPending, isError } = useEstadoDelFirewall();

  if (isPending) {
    return <span className="badge badge--neutro">comprobando…</span>;
  }
  if (isError || data === undefined) {
    return (
      <span className="badge badge--rojo" title="El backend no responde">
        sin contacto
      </span>
    );
  }

  const roto = data.has_drift || !data.scaffold_ok;
  const pendientes = data.rules_pending > 0;
  const tono = roto ? "rojo" : pendientes ? "ambar" : "verde";
  const texto = !data.scaffold_ok
    ? "sin cadenas FWDASH"
    : data.has_drift
      ? "drift"
      : pendientes
        ? `${data.rules_pending} sin aplicar`
        : "en sincronia";

  return (
    <span
      className={`badge badge--${tono}`}
      title={`Ultima aplicacion: ${fechaCompleta(data.last_applied_at)}`}
    >
      <span className="badge__punto" aria-hidden="true" />
      <span>{texto}</span>
      <span className="badge__sep">·</span>
      <span className="badge__backend">{data.backend}</span>
      <span className="badge__sep">·</span>
      <span>{haceCuanto(data.last_applied_at)}</span>
    </span>
  );
}
