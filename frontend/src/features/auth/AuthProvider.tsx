/**
 * Proveedor de sesion. Bloque A6.
 *
 * La sesion vive en memoria y muere con la pestaña, que es la consecuencia
 * aceptada de no guardar el token en `localStorage`. Recargar la pagina lleva
 * al login, y eso no es un bug.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { alCaducar, setTokens } from "@/api/client";
import { login, quienSoy } from "@/api/endpoints/auth";
import type { UserRead } from "@/api/types";
import { ContextoDeAuth, type EstadoDeAuth } from "@/features/auth/auth-context";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [usuario, setUsuario] = useState<UserRead | null>(null);
  const queryClient = useQueryClient();

  const salir = useCallback(() => {
    setTokens(null);
    setUsuario(null);
    // Sin esto, entrar con otro usuario enseñaria durante un instante los datos
    // del anterior, cacheados por react-query.
    queryClient.clear();
  }, [queryClient]);

  // El cliente HTTP avisa cuando un 401 no se ha podido salvar renovando.
  useEffect(() => {
    alCaducar(salir);
    return () => alCaducar(null);
  }, [salir]);

  const entrar = useCallback(async (username: string, password: string) => {
    const par = await login(username, password);
    setTokens(par);
    try {
      // El rol no se lee del token: se pregunta al servidor, que es quien lo
      // sabe. Un token es una credencial, no una fuente de verdad.
      setUsuario(await quienSoy());
    } catch (error) {
      setTokens(null);
      throw error;
    }
  }, []);

  const valor = useMemo<EstadoDeAuth>(
    () => ({ usuario, entrar, salir }),
    [usuario, entrar, salir],
  );

  return <ContextoDeAuth.Provider value={valor}>{children}</ContextoDeAuth.Provider>;
}
