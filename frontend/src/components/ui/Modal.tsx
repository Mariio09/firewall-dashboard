/**
 * Dialogo modal. Bloque A6. Sin dependencias: lo que hace falta es un fondo,
 * una caja, Escape y foco atrapado a ojo.
 */
import { useEffect, type ReactNode } from "react";

interface Props {
  titulo: string;
  onCerrar: () => void;
  children: ReactNode;
  ancho?: "normal" | "ancho";
}

export function Modal({ titulo, onCerrar, children, ancho = "normal" }: Props) {
  useEffect(() => {
    function alPulsar(evento: KeyboardEvent) {
      if (evento.key === "Escape") onCerrar();
    }
    window.addEventListener("keydown", alPulsar);
    return () => window.removeEventListener("keydown", alPulsar);
  }, [onCerrar]);

  return (
    <div className="modal__fondo" onClick={onCerrar}>
      <div
        className={`modal modal--${ancho}`}
        role="dialog"
        aria-modal="true"
        aria-label={titulo}
        onClick={(evento) => evento.stopPropagation()}
      >
        <header className="modal__cabecera">
          <h2 className="modal__titulo">{titulo}</h2>
          <button type="button" className="boton boton--icono" onClick={onCerrar} aria-label="Cerrar">
            ×
          </button>
        </header>
        <div className="modal__cuerpo">{children}</div>
      </div>
    </div>
  );
}
