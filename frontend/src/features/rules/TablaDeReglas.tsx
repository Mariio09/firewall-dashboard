/**
 * La tabla de reglas. Bloque A6.
 *
 * El orden de las filas es el orden en que iptables las evalua, asi que se
 * arrastra, no se escribe: `position` no es un campo del formulario, es lo que
 * dice esta lista. Al soltar se manda la cadena ENTERA a `/rules/reorder`,
 * porque un reorden parcial dejaria a las que faltan con posiciones antiguas.
 */
import { useMemo, useState } from "react";

import type { RuleListItem } from "@/api/types";
import { AvisoDeError } from "@/components/ui/AvisoDeError";
import { Modal } from "@/components/ui/Modal";
import { BadgeDeSync } from "@/features/rules/BadgeDeSync";
import {
  useAlternarRegla,
  useBorrarRegla,
  useReordenarCadena,
} from "@/features/rules/useRules";
import { bytes, selector } from "@/lib/format";

interface Props {
  reglas: RuleListItem[];
  puedeMutar: boolean;
  /** Falso cuando la vista esta filtrada: no tenemos la cadena entera. */
  puedeReordenar: boolean;
  motivoSinReordenar?: string;
  onEditar: (uuid: string) => void;
  atenuada: boolean;
}

export function TablaDeReglas({
  reglas,
  puedeMutar,
  puedeReordenar,
  motivoSinReordenar,
  onEditar,
  atenuada,
}: Props) {
  const alternar = useAlternarRegla();
  const borrar = useBorrarRegla();
  const reordenar = useReordenarCadena();

  const [arrastrando, setArrastrando] = useState<string | null>(null);
  const [encima, setEncima] = useState<string | null>(null);
  const [ordenLocal, setOrdenLocal] = useState<string[] | null>(null);
  const [aBorrar, setABorrar] = useState<RuleListItem | null>(null);

  /**
   * El orden que se pinta mientras el backend confirma. Si la respuesta trae
   * otras reglas que las que se arrastraron, se descarta: mas vale enseñar el
   * orden del servidor que uno inventado.
   */
  const filas = useMemo(() => {
    if (ordenLocal === null) return reglas;
    const porUuid = new Map(reglas.map((regla) => [regla.uuid, regla]));
    const ordenadas = ordenLocal
      .map((uuid) => porUuid.get(uuid))
      .filter((regla): regla is RuleListItem => regla !== undefined);
    return ordenadas.length === reglas.length ? ordenadas : reglas;
  }, [reglas, ordenLocal]);

  function soltarEn(destino: string) {
    const origen = arrastrando;
    setArrastrando(null);
    setEncima(null);
    if (origen === null || origen === destino) return;

    const actual = filas.map((regla) => regla.uuid);
    const desde = actual.indexOf(origen);
    const hasta = actual.indexOf(destino);
    if (desde === -1 || hasta === -1) return;

    const nuevo = [...actual];
    nuevo.splice(desde, 1);
    nuevo.splice(hasta, 0, origen);

    setOrdenLocal(nuevo);
    reordenar.mutate(nuevo, { onSettled: () => setOrdenLocal(null) });
  }

  if (reglas.length === 0) {
    return <p className="vacio">No hay reglas que cumplan el filtro.</p>;
  }

  return (
    <>
      <AvisoDeError error={reordenar.error} />
      <AvisoDeError error={alternar.error} />
      <AvisoDeError error={borrar.error} />

      <div className="tabla__envoltorio">
        <table className={`tabla${atenuada ? " tabla--atenuada" : ""}`}>
          <thead>
            <tr>
              <th className="tabla__arrastre" scope="col">
                <span className="visualmente-oculto">Orden</span>
              </th>
              <th scope="col">#</th>
              <th scope="col">Nombre</th>
              <th scope="col">Accion</th>
              <th scope="col">Proto</th>
              <th scope="col">Origen</th>
              <th scope="col">Destino</th>
              <th scope="col">Estado</th>
              <th scope="col" className="tabla__num">
                Paquetes
              </th>
              <th scope="col" className="tabla__num">
                Bytes
              </th>
              <th scope="col">Activa</th>
              <th scope="col">
                <span className="visualmente-oculto">Acciones</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {filas.map((regla) => (
              <tr
                key={regla.uuid}
                draggable={puedeReordenar && puedeMutar}
                onDragStart={() => setArrastrando(regla.uuid)}
                onDragEnd={() => {
                  setArrastrando(null);
                  setEncima(null);
                }}
                onDragOver={(evento) => {
                  if (!puedeReordenar || !puedeMutar) return;
                  evento.preventDefault();
                  setEncima(regla.uuid);
                }}
                onDrop={(evento) => {
                  evento.preventDefault();
                  soltarEn(regla.uuid);
                }}
                className={[
                  regla.enabled ? "" : "fila--desactivada",
                  arrastrando === regla.uuid ? "fila--arrastrando" : "",
                  encima === regla.uuid && arrastrando !== regla.uuid ? "fila--destino" : "",
                ]
                  .filter(Boolean)
                  .join(" ")}
              >
                <td className="tabla__arrastre">
                  <span
                    className="asa"
                    title={
                      puedeReordenar && puedeMutar
                        ? "Arrastra para cambiar el orden de evaluacion"
                        : motivoSinReordenar
                    }
                    aria-hidden="true"
                  >
                    ⠿
                  </span>
                </td>
                <td className="tabla__num">{regla.position}</td>
                <td>
                  <button
                    type="button"
                    className="enlace"
                    onClick={() => onEditar(regla.uuid)}
                    title="Ver y editar"
                  >
                    {regla.name}
                  </button>
                </td>
                <td>
                  <span className={`accion accion--${regla.action.toLowerCase()}`}>
                    {regla.action}
                  </span>
                </td>
                <td>{regla.protocol}</td>
                <td className="tabla__mono">{selector(regla.src_ip, regla.src_port)}</td>
                <td className="tabla__mono">{selector(regla.dst_ip, regla.dst_port)}</td>
                <td>
                  <BadgeDeSync estado={regla.sync_state} />
                </td>
                <td className="tabla__num">{regla.hit_count.toLocaleString("es-ES")}</td>
                <td className="tabla__num">{bytes(regla.bytes_count)}</td>
                <td>
                  <button
                    type="button"
                    className={`interruptor${regla.enabled ? " interruptor--on" : ""}`}
                    disabled={!puedeMutar || alternar.isPending}
                    onClick={() => alternar.mutate(regla.uuid)}
                    aria-pressed={regla.enabled}
                    title={
                      puedeMutar
                        ? "Desactivar no borra la regla: el renderer la omite"
                        : "Tu rol no permite cambiar reglas"
                    }
                  >
                    <span className="interruptor__bolita" />
                  </button>
                </td>
                <td className="tabla__acciones">
                  <button
                    type="button"
                    className="boton boton--pequeno"
                    onClick={() => onEditar(regla.uuid)}
                  >
                    Editar
                  </button>
                  <button
                    type="button"
                    className="boton boton--pequeno boton--peligro"
                    disabled={!puedeMutar}
                    onClick={() => setABorrar(regla)}
                  >
                    Borrar
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {!puedeReordenar && motivoSinReordenar !== undefined && (
        <p className="pista">{motivoSinReordenar}</p>
      )}

      {aBorrar !== null && (
        <Modal titulo="Borrar la regla" onCerrar={() => setABorrar(null)}>
          <p>
            Se borrara <strong>{aBorrar.name}</strong> de la base de datos y se reconstruira
            la cadena <strong>{aBorrar.chain}</strong>.
          </p>
          <p className="dialogo__intro">
            Si solo quieres dejar de aplicarla, desactivala: la regla sigue existiendo, con su
            descripcion, y vuelve en un clic.
          </p>
          <footer className="dialogo__pie">
            <button type="button" className="boton" onClick={() => setABorrar(null)}>
              Cancelar
            </button>
            <button
              type="button"
              className="boton boton--peligro"
              disabled={borrar.isPending}
              onClick={() => {
                borrar.mutate(aBorrar.uuid, { onSuccess: () => setABorrar(null) });
              }}
            >
              {borrar.isPending ? "Borrando…" : "Borrar"}
            </button>
          </footer>
        </Modal>
      )}
    </>
  );
}
