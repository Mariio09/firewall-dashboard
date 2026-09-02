/**
 * Hooks de `/rules`. Bloque A6.
 *
 * Toda mutacion invalida ademas el estado del firewall: crear, tocar o borrar
 * una regla cambia lo que `GET /firewall/status` responde, y el badge tiene que
 * enterarse sin que el usuario recargue.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  alternarRegla,
  borrarRegla,
  crearRegla,
  listarReglas,
  modificarRegla,
  reordenarCadena,
  type FiltroDeReglas,
} from "@/api/endpoints/rules";
import type { RuleCreate, RuleUpdate } from "@/api/types";
import { CLAVE_ESTADO, CLAVE_REGLAS } from "@/lib/claves";

export type { FiltroDeReglas };

export function useReglas(filtro: FiltroDeReglas) {
  return useQuery({
    queryKey: [...CLAVE_REGLAS, filtro],
    queryFn: () => listarReglas(filtro),
    // Cambiar de cadena o teclear en el buscador no debe vaciar la tabla: se
    // sigue viendo lo anterior, atenuado, hasta que llega lo nuevo.
    placeholderData: (anterior) => anterior,
  });
}

/** Invalida lo que cualquier mutacion de reglas puede haber cambiado. */
function useRefrescar() {
  const queryClient = useQueryClient();
  return () => {
    void queryClient.invalidateQueries({ queryKey: CLAVE_REGLAS });
    void queryClient.invalidateQueries({ queryKey: CLAVE_ESTADO });
  };
}

export function useCrearRegla() {
  const refrescar = useRefrescar();
  return useMutation({
    mutationFn: (datos: RuleCreate) => crearRegla(datos),
    onSuccess: refrescar,
  });
}

export function useModificarRegla() {
  const refrescar = useRefrescar();
  return useMutation({
    mutationFn: ({ uuid, datos }: { uuid: string; datos: RuleUpdate }) =>
      modificarRegla(uuid, datos),
    onSuccess: refrescar,
  });
}

export function useAlternarRegla() {
  const refrescar = useRefrescar();
  return useMutation({
    mutationFn: (uuid: string) => alternarRegla(uuid),
    onSuccess: refrescar,
  });
}

export function useBorrarRegla() {
  const refrescar = useRefrescar();
  return useMutation({
    mutationFn: (uuid: string) => borrarRegla(uuid),
    onSuccess: refrescar,
  });
}

/**
 * Reordenar.
 *
 * `onSettled` y no `onSuccess`: si el backend rechaza el orden (409 porque
 * falta alguna regla de la cadena), hay que volver a leer para deshacer el
 * orden que la tabla ya estaba enseñando.
 */
export function useReordenarCadena() {
  const refrescar = useRefrescar();
  return useMutation({
    mutationFn: (uuids: string[]) => reordenarCadena(uuids),
    onSettled: refrescar,
  });
}
