/**
 * Guard de rutas. Bloque A6.
 *
 * Es comodidad, no seguridad: quien no tenga token recibira 401 de todos modos.
 * Lo que evita es enseñar un dashboard vacio y tres errores rojos.
 */
import { Navigate, Outlet, useLocation } from "react-router-dom";

import { useAuth } from "@/features/auth/useAuth";

export function RequireAuth() {
  const { usuario } = useAuth();
  const donde = useLocation();

  if (usuario === null) {
    return <Navigate to="/login" replace state={{ desde: donde.pathname }} />;
  }
  return <Outlet />;
}
