/**
 * Cliente HTTP. Unico punto del frontend que habla con el backend.
 *
 * Bloque A4/A6.
 *
 * Decision de seguridad: el token se guarda EN MEMORIA, no en `localStorage`.
 * Cualquier XSS puede leer `localStorage`; una variable de modulo no es
 * accesible desde una consola inyectada. El precio es que la sesion se pierde al
 * refrescar la pagina, y se paga a gusto. Ver docs/SECURITY.md §9.
 *
 * TODO(A4): implementar `request()` con inyeccion del header Authorization,
 * manejo de 401 (refresh y reintento una vez) y traduccion de la forma de error
 * del backend  {error: {code, message, details, request_id}}  a una excepcion
 * tipada.
 */

export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1";

let accessToken: string | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly status: number,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function request<T>(_path: string, _init?: RequestInit): Promise<T> {
  throw new Error("TODO(A4): implementar el cliente HTTP");
}
