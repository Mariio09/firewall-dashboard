/**
 * Endpoints de `/auth`. Bloque A6.
 *
 * No hay `logout`: con refresh stateless no habria nada que invalidar en el
 * servidor (ADR-0008). Cerrar sesion es olvidar los tokens en `client.ts`.
 */
import { request } from "@/api/client";
import type { TokenPair, UserRead } from "@/api/types";

export function login(username: string, password: string): Promise<TokenPair> {
  return request<TokenPair>("/auth/login", {
    method: "POST",
    body: { username, password },
  });
}

/** Quien soy, segun el servidor. El token no es un salvoconducto: se relee. */
export function quienSoy(): Promise<UserRead> {
  return request<UserRead>("/auth/me");
}
