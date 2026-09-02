/**
 * Pantalla de entrada. Bloque A6.
 *
 * El backend responde lo mismo ante usuario inexistente, contraseña incorrecta
 * y cuenta desactivada, asi que aqui tampoco se intenta adivinar cual de las
 * tres fue: se enseña el mensaje del servidor tal cual.
 */
import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";

import { ApiError } from "@/api/client";
import { useAuth } from "@/features/auth/useAuth";

interface EstadoDeRuta {
  desde?: string;
}

export function LoginPage() {
  const { usuario, entrar } = useAuth();
  const navegar = useNavigate();
  const ubicacion = useLocation();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [enviando, setEnviando] = useState(false);

  if (usuario !== null) {
    const estado = ubicacion.state as EstadoDeRuta | null;
    return <Navigate to={estado?.desde ?? "/rules"} replace />;
  }

  async function alEnviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    setError(null);
    setEnviando(true);
    try {
      await entrar(username, password);
      navegar("/rules", { replace: true });
    } catch (fallo) {
      setError(
        fallo instanceof ApiError
          ? fallo.message
          : "No se ha podido contactar con el backend. ¿Esta levantado?",
      );
    } finally {
      setEnviando(false);
    }
  }

  return (
    <div className="login">
      <form className="login__caja" onSubmit={alEnviar}>
        <h1 className="login__titulo">firewall-dashboard</h1>
        <p className="login__sub">Gestion de reglas de iptables</p>

        <label className="campo">
          <span className="campo__etiqueta">Usuario</span>
          <input
            className="campo__control"
            name="username"
            autoComplete="username"
            autoFocus
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>

        <label className="campo">
          <span className="campo__etiqueta">Contraseña</span>
          <input
            className="campo__control"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>

        {error !== null && (
          <p className="aviso aviso--error" role="alert">
            {error}
          </p>
        )}

        <button className="boton boton--primario" type="submit" disabled={enviando}>
          {enviando ? "Entrando…" : "Entrar"}
        </button>

        <p className="login__nota">
          La sesion vive en memoria: al recargar la pagina hay que volver a entrar. Es el
          precio de no guardar el token donde pueda leerlo un XSS.
        </p>
      </form>
    </div>
  );
}
