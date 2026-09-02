/**
 * Marco de la aplicacion: cabecera con el badge de estado y quien eres.
 * Bloque A6.
 */
import { Outlet } from "react-router-dom";

import { EstadoBadge } from "@/features/firewall/EstadoBadge";
import { useAuth } from "@/features/auth/useAuth";

export function Layout() {
  const { usuario, salir } = useAuth();

  return (
    <div className="marco">
      <header className="cabecera">
        <div className="cabecera__marca">
          <span className="cabecera__logo" aria-hidden="true">
            ▚
          </span>
          <span>firewall-dashboard</span>
        </div>

        <EstadoBadge />

        <div className="cabecera__usuario">
          <span>
            {usuario?.username}
            <span className="rol">{usuario?.role}</span>
          </span>
          <button type="button" className="boton boton--pequeno" onClick={salir}>
            Salir
          </button>
        </div>
      </header>

      <main className="contenido">
        <Outlet />
      </main>
    </div>
  );
}
