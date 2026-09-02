/**
 * Un error de la API, enseñado como lo que es. Bloque A6.
 *
 * Se pinta el `request_id` cuando viene: es lo que permite cruzar lo que ve el
 * usuario con la linea exacta del log estructurado del backend.
 *
 * Y se pinta el detalle por campo cuando lo hay, porque el mensaje de un 422 es
 * siempre el mismo ("Los datos enviados no son validos") y lo util esta dentro.
 */
import { ApiError } from "@/api/client";

export function AvisoDeError({ error }: { error: unknown }) {
  if (error === null || error === undefined) return null;

  if (error instanceof ApiError) {
    const detalles = error.problemas.filter((problema) => problema.mensaje !== error.message);
    return (
      <div className="aviso aviso--error" role="alert">
        <span>{error.message}</span>
        <span className="aviso__meta">
          <code>{error.code}</code>
          {error.requestId !== undefined && <code title="request_id">{error.requestId}</code>}
        </span>
        {detalles.length > 0 && (
          <ul className="aviso__campos">
            {detalles.map((problema) => (
              <li key={`${problema.campo}:${problema.mensaje}`}>
                <code>{problema.campo}</code> — {problema.mensaje}
              </li>
            ))}
          </ul>
        )}
      </div>
    );
  }

  return (
    <p className="aviso aviso--error" role="alert">
      {error instanceof Error ? error.message : "Error inesperado."}
    </p>
  );
}
