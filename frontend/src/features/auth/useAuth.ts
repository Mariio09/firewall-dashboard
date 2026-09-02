import { useContext } from "react";

import { ContextoDeAuth, type EstadoDeAuth } from "@/features/auth/auth-context";

export function useAuth(): EstadoDeAuth {
  const valor = useContext(ContextoDeAuth);
  if (valor === null) {
    throw new Error("useAuth() se ha usado fuera de <AuthProvider>.");
  }
  return valor;
}
