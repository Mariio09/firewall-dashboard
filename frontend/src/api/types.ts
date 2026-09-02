/**
 * Tipos del API, derivados del OpenAPI del backend.
 *
 * Bloque A6. `schema.d.ts` lo genera `npm run gen:api` contra el backend en
 * marcha; este archivo solo le pone nombres cortos a lo que el frontend usa.
 *
 * Por que no se escriben a mano: el contrato ya esta escrito una vez, en los
 * schemas de Pydantic. Una segunda copia aqui no dejaria de compilar el dia que
 * el backend cambie un campo, solo mentiria en verde hasta que alguien abriera
 * el navegador.
 */
import type { components } from "@/api/schema";

type Schemas = components["schemas"];

export type Chain = Schemas["Chain"];
export type Action = Schemas["Action"];
export type Protocol = Schemas["Protocol"];
export type SyncState = Schemas["SyncState"];
export type Role = Schemas["Role"];

export type RuleCreate = Schemas["RuleCreate"];
export type RuleUpdate = Schemas["RuleUpdate"];
export type RuleRead = Schemas["RuleRead"];
export type RuleListItem = Schemas["RuleListItem"];

export type ApplyResponse = Schemas["ApplyResponse"];
export type ChainApply = Schemas["ChainApply"];
export type ChainDrift = Schemas["ChainDrift"];
export type FirewallStatus = Schemas["FirewallStatus"];

export type TokenPair = Schemas["TokenPair"];
export type UserRead = Schemas["UserRead"];

/**
 * `Page[T]` es generico en Pydantic y openapi-typescript lo aplana a un schema
 * por instanciacion (`Page_RuleListItem_`). Se redeclara aqui, que son cuatro
 * campos, para no atar el frontend a como el generador decida nombrarlos.
 */
export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

/**
 * Valores para los desplegables. Van a mano y no derivados del tipo porque un
 * `type` no existe en tiempo de ejecucion; si el backend añade una cadena, el
 * `satisfies` de abajo hace que esto deje de compilar.
 */
export const CADENAS = ["INPUT", "OUTPUT", "FORWARD"] as const satisfies readonly Chain[];
export const ACCIONES = ["ACCEPT", "DROP", "REJECT"] as const satisfies readonly Action[];
export const PROTOCOLOS = ["all", "tcp", "udp", "icmp"] as const satisfies readonly Protocol[];

/** Jerarquia de roles, de menor a mayor. `admin` incluye lo de `operator`. */
const ESCALERA: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };

/**
 * Espejo de `require_role()` del backend. Solo sirve para decidir que se pinta:
 * el permiso lo decide el servidor, y esconder un boton no protege nada.
 */
export function tieneRol(actual: Role | undefined, minimo: Role): boolean {
  if (actual === undefined) return false;
  return ESCALERA[actual] >= ESCALERA[minimo];
}
