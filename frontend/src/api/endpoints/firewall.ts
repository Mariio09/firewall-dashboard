/**
 * Endpoints de `/firewall`. Bloque A6.
 *
 * `preview` y `apply` devuelven la misma forma porque son la misma funcion con
 * `dry_run` distinto. Enseñar el argv exacto antes de ejecutarlo es la
 * mitigacion nº2 del problema del auto-bloqueo, y por eso el boton de aplicar
 * de la UI pasa por el preview.
 */
import { request } from "@/api/client";
import type { ApplyResponse, FirewallStatus } from "@/api/types";

/** Alimenta el badge del header y el banner de drift. Rol `viewer`. */
export function estadoDelFirewall(): Promise<FirewallStatus> {
  return request<FirewallStatus>("/firewall/status");
}

/** Los comandos que se ejecutarian, sin ejecutar ninguno. Rol `operator`. */
export function previsualizar(): Promise<ApplyResponse> {
  return request<ApplyResponse>("/firewall/preview");
}

/** Reconstruye las tres cadenas. Si el firewall falla, 502. Rol `operator`. */
export function aplicar(): Promise<ApplyResponse> {
  return request<ApplyResponse>("/firewall/apply", { method: "POST" });
}
