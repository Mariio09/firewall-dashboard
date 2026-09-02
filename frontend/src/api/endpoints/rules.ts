/**
 * Endpoints de `/rules`. Bloque A6.
 *
 * Lo que estas llamadas escriben es la POLITICA DESEADA, no el firewall. Con
 * `AUTO_APPLY=true` (por defecto) el backend reconcilia en la misma peticion,
 * pero el `sync_state` de la respuesta es quien dice como acabo: `applied`,
 * `pending` o `failed`. Un 201 no significa que la regla este en iptables
 * (ADR-0011), y por eso la tabla tiene columna de estado.
 */
import { request } from "@/api/client";
import type { Chain, Page, RuleCreate, RuleListItem, RuleRead, RuleUpdate } from "@/api/types";

export interface FiltroDeReglas {
  chain?: Chain;
  enabled?: boolean;
  q?: string;
  page?: number;
  size?: number;
}

export function listarReglas(filtro: FiltroDeReglas = {}): Promise<Page<RuleListItem>> {
  return request<Page<RuleListItem>>("/rules", { query: { ...filtro } });
}

export function verRegla(uuid: string): Promise<RuleRead> {
  return request<RuleRead>(`/rules/${encodeURIComponent(uuid)}`);
}

export function crearRegla(datos: RuleCreate): Promise<RuleRead> {
  return request<RuleRead>("/rules", { method: "POST", body: datos });
}

export function modificarRegla(uuid: string, datos: RuleUpdate): Promise<RuleRead> {
  return request<RuleRead>(`/rules/${encodeURIComponent(uuid)}`, {
    method: "PATCH",
    body: datos,
  });
}

export function alternarRegla(uuid: string): Promise<RuleRead> {
  return request<RuleRead>(`/rules/${encodeURIComponent(uuid)}/toggle`, { method: "POST" });
}

export function borrarRegla(uuid: string): Promise<void> {
  return request<void>(`/rules/${encodeURIComponent(uuid)}`, { method: "DELETE" });
}

/**
 * Reescribe el orden de una cadena entera.
 *
 * La lista tiene que traer TODAS las reglas de la cadena; si falta alguna el
 * backend responde 409 con las que faltan. De ahi que la UI solo permita
 * arrastrar cuando se esta viendo una cadena sin filtrar: una vista filtrada no
 * tiene la cadena entera que mandar.
 */
export function reordenarCadena(uuids: string[]): Promise<RuleListItem[]> {
  return request<RuleListItem[]>("/rules/reorder", { method: "POST", body: { uuids } });
}
