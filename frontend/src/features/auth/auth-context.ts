/**
 * El contexto de sesion, sin componentes.
 *
 * Vive en su propio archivo para que `AuthProvider.tsx` exporte solo un
 * componente: mezclarlos rompe el hot reload de React Refresh y el lint lo
 * avisa.
 */
import { createContext } from "react";

import type { UserRead } from "@/api/types";

export interface EstadoDeAuth {
  /** `null` mientras no haya sesion. No se persiste: ver `api/client.ts`. */
  usuario: UserRead | null;
  entrar: (username: string, password: string) => Promise<void>;
  salir: () => void;
}

export const ContextoDeAuth = createContext<EstadoDeAuth | null>(null);
