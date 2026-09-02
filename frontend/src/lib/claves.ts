/**
 * Claves de react-query, en un modulo sin hooks.
 *
 * Estan aqui y no junto a cada hook porque una mutacion de reglas invalida el
 * estado del firewall y al reves: si cada archivo declarase su clave, se
 * importarian en circulo.
 */
export const CLAVE_REGLAS = ["rules"] as const;
export const CLAVE_ESTADO = ["firewall", "status"] as const;
export const CLAVE_PREVIEW = ["firewall", "preview"] as const;
