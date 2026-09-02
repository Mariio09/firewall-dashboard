/**
 * Alta y edicion de una regla. Bloque A6.
 *
 * No hay campo `position`: las reglas se añaden al final de su cadena y el
 * orden se arrastra en la tabla. Tampoco `table_name` ni `ip_version`: el MVP
 * solo genera IPv4 en `filter`, y ofrecerlos aqui dejaria crear reglas que el
 * renderer rechaza al aplicarlas — un error a destiempo y en el sitio
 * equivocado.
 *
 * La respuesta del backend trae los valores NORMALIZADOS, que pueden no ser los
 * que se escribieron (`1.2.3.4` vuelve como `1.2.3.4/32`). Por eso al guardar se
 * cierra el formulario y manda la tabla: enseñar lo que se guardo, no lo que se
 * tecleo.
 */
import { useEffect, useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";

import { ApiError } from "@/api/client";
import { verRegla } from "@/api/endpoints/rules";
import {
  ACCIONES,
  CADENAS,
  PROTOCOLOS,
  type Action,
  type Chain,
  type Protocol,
  type RuleCreate,
  type RuleUpdate,
} from "@/api/types";
import { AvisoDeError } from "@/components/ui/AvisoDeError";
import { Modal } from "@/components/ui/Modal";
import { BadgeDeSync } from "@/features/rules/BadgeDeSync";
import { useCrearRegla, useModificarRegla } from "@/features/rules/useRules";
import { CLAVE_REGLAS } from "@/lib/claves";
import { fechaCompleta } from "@/lib/format";

interface Formulario {
  name: string;
  description: string;
  chain: Chain;
  action: Action;
  protocol: Protocol;
  src_ip: string;
  dst_ip: string;
  src_port: string;
  dst_port: string;
  in_interface: string;
  out_interface: string;
  enabled: boolean;
  log_enabled: boolean;
  log_prefix: string;
  expires_at: string;
}

function vacio(chain: Chain): Formulario {
  return {
    name: "",
    description: "",
    chain,
    action: "DROP",
    protocol: "all",
    src_ip: "",
    dst_ip: "",
    src_port: "",
    dst_port: "",
    in_interface: "",
    out_interface: "",
    enabled: true,
    log_enabled: false,
    log_prefix: "",
    expires_at: "",
  };
}

/** `""` significa "este selector no se usa", y en el contrato eso es `null`. */
function texto(valor: string): string | null {
  const limpio = valor.trim();
  return limpio === "" ? null : limpio;
}

/**
 * `datetime-local` da "2026-09-30T22:00", sin offset. El backend rechaza un
 * instante sin offset con un 422 (ADR-0010), asi que se convierte aqui: el
 * navegador sabe en que zona esta el usuario, y `toISOString()` lo deja en UTC.
 */
function aInstante(valor: string): string | null {
  if (valor === "") return null;
  const fecha = new Date(valor);
  return Number.isNaN(fecha.getTime()) ? null : fecha.toISOString();
}

function aCampoLocal(iso: string | null | undefined): string {
  if (!iso) return "";
  const fecha = new Date(iso);
  if (Number.isNaN(fecha.getTime())) return "";
  const dos = (n: number) => String(n).padStart(2, "0");
  return (
    `${fecha.getFullYear()}-${dos(fecha.getMonth() + 1)}-${dos(fecha.getDate())}` +
    `T${dos(fecha.getHours())}:${dos(fecha.getMinutes())}`
  );
}

interface Props {
  /** `null` para crear. */
  uuid: string | null;
  chainPorDefecto: Chain;
  onCerrar: () => void;
}

export function FormularioDeRegla({ uuid, chainPorDefecto, onCerrar }: Props) {
  const editando = uuid !== null;
  const [form, setForm] = useState<Formulario>(() => vacio(chainPorDefecto));

  const regla = useQuery({
    queryKey: [...CLAVE_REGLAS, "detalle", uuid],
    queryFn: () => verRegla(uuid as string),
    enabled: editando,
  });

  useEffect(() => {
    const datos = regla.data;
    if (datos === undefined) return;
    setForm({
      name: datos.name,
      description: datos.description ?? "",
      chain: datos.chain,
      action: datos.action,
      protocol: datos.protocol,
      src_ip: datos.src_ip ?? "",
      dst_ip: datos.dst_ip ?? "",
      src_port: datos.src_port ?? "",
      dst_port: datos.dst_port ?? "",
      in_interface: datos.in_interface ?? "",
      out_interface: datos.out_interface ?? "",
      enabled: datos.enabled,
      log_enabled: datos.log_enabled,
      log_prefix: datos.log_prefix ?? "",
      expires_at: aCampoLocal(datos.expires_at),
    });
  }, [regla.data]);

  const crear = useCrearRegla();
  const modificar = useModificarRegla();
  const error: unknown = crear.error ?? modificar.error ?? regla.error;
  // Puede venir mas de uno: un 422 de Pydantic trae la lista entera.
  const camposMalos = new Set(
    error instanceof ApiError ? error.problemas.map((problema) => problema.campo) : [],
  );
  const guardando = crear.isPending || modificar.isPending;

  // iptables no acepta `--dport` sin `-p tcp` o `-p udp`. Ofrecer el campo con
  // `protocol: all` seria ofrecer una regla que el renderer rechaza.
  const hayPuertos = form.protocol === "tcp" || form.protocol === "udp";

  function cambiar(parcial: Partial<Formulario>) {
    setForm((anterior) => ({ ...anterior, ...parcial }));
  }

  function alEnviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    const comun = {
      name: form.name.trim(),
      description: texto(form.description),
      chain: form.chain,
      action: form.action,
      protocol: form.protocol,
      src_ip: texto(form.src_ip),
      dst_ip: texto(form.dst_ip),
      src_port: hayPuertos ? texto(form.src_port) : null,
      dst_port: hayPuertos ? texto(form.dst_port) : null,
      in_interface: texto(form.in_interface),
      out_interface: texto(form.out_interface),
      enabled: form.enabled,
      log_enabled: form.log_enabled,
      log_prefix: form.log_enabled ? texto(form.log_prefix) : null,
      expires_at: aInstante(form.expires_at),
    };

    if (editando) {
      modificar.mutate({ uuid, datos: comun satisfies RuleUpdate }, { onSuccess: onCerrar });
    } else {
      crear.mutate(comun satisfies RuleCreate, { onSuccess: onCerrar });
    }
  }

  const claseDe = (campo: string) =>
    `campo__control${camposMalos.has(campo) ? " campo__control--malo" : ""}`;

  return (
    <Modal titulo={editando ? "Editar regla" : "Nueva regla"} onCerrar={onCerrar} ancho="ancho">
      {editando && regla.isPending ? (
        <p className="vacio">Cargando la regla…</p>
      ) : (
        <form onSubmit={alEnviar}>
          <div className="rejilla">
            <label className="campo campo--ancho">
              <span className="campo__etiqueta">Nombre</span>
              <input
                className={claseDe("name")}
                required
                maxLength={100}
                value={form.name}
                onChange={(e) => cambiar({ name: e.target.value })}
              />
              <span className="campo__pista">
                Viaja dentro del <code>--comment</code> de la regla.
              </span>
            </label>

            <label className="campo campo--ancho">
              <span className="campo__etiqueta">Descripcion</span>
              <textarea
                className={claseDe("description")}
                rows={2}
                value={form.description}
                onChange={(e) => cambiar({ description: e.target.value })}
              />
              <span className="campo__pista">
                El porque de la regla. Es lo que se agradece dentro de seis meses.
              </span>
            </label>

            <label className="campo">
              <span className="campo__etiqueta">Cadena</span>
              <select
                className={claseDe("chain")}
                value={form.chain}
                onChange={(e) => cambiar({ chain: e.target.value as Chain })}
              >
                {CADENAS.map((cadena) => (
                  <option key={cadena} value={cadena}>
                    {cadena}
                  </option>
                ))}
              </select>
            </label>

            <label className="campo">
              <span className="campo__etiqueta">Accion</span>
              <select
                className={claseDe("action")}
                value={form.action}
                onChange={(e) => cambiar({ action: e.target.value as Action })}
              >
                {ACCIONES.map((accion) => (
                  <option key={accion} value={accion}>
                    {accion}
                  </option>
                ))}
              </select>
            </label>

            <label className="campo">
              <span className="campo__etiqueta">Protocolo</span>
              <select
                className={claseDe("protocol")}
                value={form.protocol}
                onChange={(e) => cambiar({ protocol: e.target.value as Protocol })}
              >
                {PROTOCOLOS.map((protocolo) => (
                  <option key={protocolo} value={protocolo}>
                    {protocolo}
                  </option>
                ))}
              </select>
            </label>

            <label className="campo">
              <span className="campo__etiqueta">IP origen</span>
              <input
                className={claseDe("src_ip")}
                placeholder="203.0.113.0/24"
                value={form.src_ip}
                onChange={(e) => cambiar({ src_ip: e.target.value })}
              />
            </label>

            <label className="campo">
              <span className="campo__etiqueta">IP destino</span>
              <input
                className={claseDe("dst_ip")}
                placeholder="10.0.0.5"
                value={form.dst_ip}
                onChange={(e) => cambiar({ dst_ip: e.target.value })}
              />
            </label>

            <label className="campo">
              <span className="campo__etiqueta">Puerto origen</span>
              <input
                className={claseDe("src_port")}
                disabled={!hayPuertos}
                placeholder={hayPuertos ? "1024:65535" : "requiere tcp o udp"}
                value={hayPuertos ? form.src_port : ""}
                onChange={(e) => cambiar({ src_port: e.target.value })}
              />
            </label>

            <label className="campo">
              <span className="campo__etiqueta">Puerto destino</span>
              <input
                className={claseDe("dst_port")}
                disabled={!hayPuertos}
                placeholder={hayPuertos ? "22" : "requiere tcp o udp"}
                value={hayPuertos ? form.dst_port : ""}
                onChange={(e) => cambiar({ dst_port: e.target.value })}
              />
            </label>

            <label className="campo">
              <span className="campo__etiqueta">Interfaz de entrada</span>
              <input
                className={claseDe("in_interface")}
                placeholder="eth0"
                value={form.in_interface}
                onChange={(e) => cambiar({ in_interface: e.target.value })}
              />
            </label>

            <label className="campo">
              <span className="campo__etiqueta">Interfaz de salida</span>
              <input
                className={claseDe("out_interface")}
                placeholder="eth0"
                value={form.out_interface}
                onChange={(e) => cambiar({ out_interface: e.target.value })}
              />
            </label>

            <label className="campo">
              <span className="campo__etiqueta">Caduca el</span>
              <input
                className={claseDe("expires_at")}
                type="datetime-local"
                value={form.expires_at}
                onChange={(e) => cambiar({ expires_at: e.target.value })}
              />
              <span className="campo__pista">
                Se manda en UTC con offset. Hoy es informativo: nadie la apaga aun.
              </span>
            </label>

            <div className="campo campo--ancho campo--casillas">
              <label className="casilla">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(e) => cambiar({ enabled: e.target.checked })}
                />
                <span>Activa</span>
              </label>

              <label className="casilla">
                <input
                  type="checkbox"
                  checked={form.log_enabled}
                  onChange={(e) => cambiar({ log_enabled: e.target.checked })}
                />
                <span>Registrar en el log</span>
              </label>

              {form.log_enabled && (
                <input
                  className={`${claseDe("log_prefix")} campo__control--corto`}
                  maxLength={29}
                  placeholder="prefijo (opcional)"
                  value={form.log_prefix}
                  onChange={(e) => cambiar({ log_prefix: e.target.value })}
                />
              )}
            </div>
          </div>

          {regla.data !== undefined && (
            <section className="detalle">
              <BadgeDeSync estado={regla.data.sync_state} motivo={regla.data.last_error} />
              <span>posicion {regla.data.position}</span>
              <span>creada por {regla.data.created_by ?? "—"}</span>
              <span>aplicada: {fechaCompleta(regla.data.applied_at)}</span>
              {regla.data.last_error !== null && regla.data.last_error !== undefined && (
                <p className="detalle__error">{regla.data.last_error}</p>
              )}
            </section>
          )}

          <AvisoDeError error={error} />

          <footer className="dialogo__pie">
            <button type="button" className="boton" onClick={onCerrar}>
              Cancelar
            </button>
            <button type="submit" className="boton boton--primario" disabled={guardando}>
              {guardando ? "Guardando…" : editando ? "Guardar cambios" : "Crear regla"}
            </button>
          </footer>
        </form>
      )}
    </Modal>
  );
}
