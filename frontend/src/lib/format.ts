/**
 * Formateo para la UI. Bloque A6.
 *
 * Las fechas del backend llegan SIEMPRE con offset (ADR-0010), asi que
 * `new Date()` las entiende sin trucos. Si alguna vez llega una sin `Z` ni
 * `+00:00`, el bug esta en el backend y hay que arreglarlo alli.
 */

const RELATIVO = new Intl.RelativeTimeFormat("es", { numeric: "auto" });
const ABSOLUTO = new Intl.DateTimeFormat("es-ES", { dateStyle: "medium", timeStyle: "medium" });

const ESCALAS: readonly [Intl.RelativeTimeFormatUnit, number][] = [
  ["second", 60],
  ["minute", 60],
  ["hour", 24],
  ["day", 7],
];

/** "hace 3 minutos". Para el badge, donde lo que importa es la antiguedad. */
export function haceCuanto(iso: string | null | undefined): string {
  if (!iso) return "nunca";
  const fecha = new Date(iso);
  if (Number.isNaN(fecha.getTime())) return "fecha invalida";

  let cantidad = (fecha.getTime() - Date.now()) / 1000;
  for (const escala of ESCALAS) {
    const [unidad, limite] = escala;
    if (Math.abs(cantidad) < limite) return RELATIVO.format(Math.round(cantidad), unidad);
    cantidad /= limite;
  }
  return RELATIVO.format(Math.round(cantidad), "week");
}

/** Fecha completa, para el `title` de lo que se enseña en relativo. */
export function fechaCompleta(iso: string | null | undefined): string {
  if (!iso) return "nunca";
  const fecha = new Date(iso);
  return Number.isNaN(fecha.getTime()) ? "fecha invalida" : ABSOLUTO.format(fecha);
}

/** `1536` -> `1,5 KB`. Los contadores de iptables crecen rapido. */
export function bytes(valor: number): string {
  const unidades = ["B", "KB", "MB", "GB", "TB"];
  let n = valor;
  let i = 0;
  while (n >= 1024 && i < unidades.length - 1) {
    n /= 1024;
    i += 1;
  }
  const unidad = unidades[i] ?? "B";
  return `${i === 0 ? n : n.toFixed(1)} ${unidad}`;
}

/** El selector de una regla, en la forma en que se lee en un iptables -S. */
export function selector(
  valor: string | null | undefined,
  puerto: string | null | undefined,
): string {
  if (!valor && !puerto) return "—";
  if (!puerto) return valor ?? "—";
  if (!valor) return `:${puerto}`;
  return `${valor}:${puerto}`;
}
