/**
 * Cliente HTTP. Unico punto del frontend que habla con el backend.
 *
 * Bloque A4/A6.
 *
 * Decision de seguridad: los tokens se guardan EN MEMORIA, no en
 * `localStorage`. Cualquier XSS puede leer `localStorage`; una variable de
 * modulo no es accesible desde una consola inyectada. El precio es que la
 * sesion se pierde al refrescar la pagina, y se paga a gusto.
 * Ver docs/SECURITY.md §9.
 *
 * Aqui viven las tres cosas que ningun componente deberia repetir: meter el
 * `Authorization`, renovar el token cuando caduca a mitad de sesion, y traducir
 * la forma de error del backend a una excepcion con la que se pueda hacer
 * `switch`.
 */
import type { TokenPair } from "@/api/types";

export const API_BASE_URL: string =
  import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1";

let accessToken: string | null = null;
let refreshToken: string | null = null;

export function setTokens(par: TokenPair | null): void {
  accessToken = par?.access_token ?? null;
  refreshToken = par?.refresh_token ?? null;
}

export function getAccessToken(): string | null {
  return accessToken;
}

/**
 * Aviso de "la sesion ya no vale". Lo escucha el proveedor de auth para vaciar
 * el usuario y mandar al login sin que ningun componente tenga que mirar
 * codigos de error.
 *
 * No existe `/logout` en el backend y es deliberado: con refresh stateless no
 * habria nada que invalidar (ADR-0008). Cerrar sesion es olvidar el token aqui.
 */
type Aviso = () => void;
let alCaducarLaSesion: Aviso | null = null;

export function alCaducar(cb: Aviso | null): void {
  alCaducarLaSesion = cb;
}

/**
 * Un error del backend, ya desenvuelto.
 *
 * `code` es estable y legible por maquina; `message` es lo que se le enseña a
 * una persona. Que exista un unico sobre `{error: {...}}` para toda la API es
 * lo que permite tener un solo sitio que lo abra, en vez de un `if` por
 * endpoint.
 */
export interface ProblemaDeCampo {
  campo: string;
  mensaje: string;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly status: number,
    readonly details: Record<string, unknown> = {},
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }

  /**
   * Los campos que el backend señala como culpables.
   *
   * Vienen en dos formas distintas y las dos son legitimas: los validadores del
   * dominio ponen un `details.campo` —en español, como el resto del codigo—, y
   * el handler de los 422 de Pydantic manda `details.errors` con un `field` y un
   * `message` por cada problema. Traducir aqui las dos es lo que permite que el
   * formulario tenga una sola regla: pinta en rojo lo que salga de esta lista.
   */
  get problemas(): ProblemaDeCampo[] {
    const lista: ProblemaDeCampo[] = [];

    const suelto = this.details["campo"] ?? this.details["field"];
    if (typeof suelto === "string" && suelto !== "") {
      lista.push({ campo: suelto, mensaje: this.message });
    }

    const errores = this.details["errors"];
    if (Array.isArray(errores)) {
      for (const entrada of errores) {
        if (entrada === null || typeof entrada !== "object") continue;
        const registro = entrada as Record<string, unknown>;
        const campo = registro["field"];
        const mensaje = registro["message"];
        if (typeof campo === "string" && campo !== "") {
          lista.push({
            campo,
            mensaje: typeof mensaje === "string" && mensaje !== "" ? mensaje : this.message,
          });
        }
      }
    }

    return lista;
  }

  /** El primer campo culpable, para cuando solo hace falta uno. */
  get campo(): string | undefined {
    return this.problemas[0]?.campo;
  }
}

interface SobreDeError {
  error?: {
    code?: string;
    message?: string;
    details?: Record<string, unknown>;
    request_id?: string | null;
  };
}

async function desenvolver(res: Response): Promise<ApiError> {
  let sobre: SobreDeError | null = null;
  try {
    sobre = (await res.json()) as SobreDeError;
  } catch {
    // Un 502 de un proxy, o el backend caido: no hay JSON que abrir.
    sobre = null;
  }
  const cuerpo = sobre?.error;
  return new ApiError(
    cuerpo?.message ?? `El backend respondio ${res.status} sin explicar por que.`,
    cuerpo?.code ?? "http_error",
    res.status,
    cuerpo?.details ?? {},
    cuerpo?.request_id ?? undefined,
  );
}

export interface Peticion {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  signal?: AbortSignal;
}

function construirUrl(path: string, query?: Peticion["query"]): string {
  const base = API_BASE_URL.replace(/\/+$/, "");
  if (!query) return base + path;
  const params = new URLSearchParams();
  for (const [clave, valor] of Object.entries(query)) {
    // `undefined`, `null` y `""` significan "no filtres por esto". `false` si
    // se manda: `?enabled=false` es un filtro, no la ausencia de uno.
    if (valor === undefined || valor === null || valor === "") continue;
    params.set(clave, String(valor));
  }
  const cadena = params.toString();
  return cadena ? `${base}${path}?${cadena}` : base + path;
}

async function enviar(path: string, opciones: Peticion): Promise<Response> {
  const cabeceras: Record<string, string> = { Accept: "application/json" };
  if (opciones.body !== undefined) cabeceras["Content-Type"] = "application/json";
  if (accessToken) cabeceras["Authorization"] = `Bearer ${accessToken}`;

  return fetch(construirUrl(path, opciones.query), {
    method: opciones.method ?? "GET",
    headers: cabeceras,
    body: opciones.body === undefined ? undefined : JSON.stringify(opciones.body),
    signal: opciones.signal,
  });
}

/**
 * Renovacion del access token. Una sola en vuelo.
 *
 * Sin el candado, seis peticiones en paralelo al caducar el token dispararian
 * seis refrescos, y cinco de ellos escribirian tokens ya viejos encima del
 * bueno.
 */
let refrescoEnCurso: Promise<boolean> | null = null;

async function pedirTokensNuevos(token: string): Promise<boolean> {
  try {
    const res = await fetch(construirUrl("/auth/refresh"), {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ refresh_token: token }),
    });
    if (!res.ok) return false;
    setTokens((await res.json()) as TokenPair);
    return true;
  } catch {
    // El backend no responde. No es una sesion invalida, pero para quien
    // llama el resultado es el mismo: esta peticion no se puede completar.
    return false;
  }
}

function refrescar(): Promise<boolean> {
  const token = refreshToken;
  if (!token) return Promise.resolve(false);

  const enCurso =
    refrescoEnCurso ??
    pedirTokensNuevos(token).finally(() => {
      refrescoEnCurso = null;
    });
  refrescoEnCurso = enCurso;
  return enCurso;
}

/**
 * Hace la peticion y devuelve el cuerpo ya parseado.
 *
 * Ante un 401 con sesion abierta intenta renovar **una vez** y reintenta. Si
 * tampoco, olvida los tokens y avisa: insistir solo cambiaria un error por un
 * bucle.
 */
export async function request<T>(path: string, opciones: Peticion = {}): Promise<T> {
  const habiaSesion = accessToken !== null || refreshToken !== null;
  let res = await enviar(path, opciones);

  if (res.status === 401 && habiaSesion && (await refrescar())) {
    res = await enviar(path, opciones);
  }

  if (!res.ok) {
    const error = await desenvolver(res);
    if (res.status === 401 && habiaSesion) {
      setTokens(null);
      alCaducarLaSesion?.();
    }
    throw error;
  }

  // 204 en `DELETE /rules/{uuid}`: no hay cuerpo que parsear.
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}
