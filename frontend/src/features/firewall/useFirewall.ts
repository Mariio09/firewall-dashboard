/**
 * Hooks de `/firewall`. Bloque A6.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { aplicar, estadoDelFirewall, previsualizar } from "@/api/endpoints/firewall";
import { CLAVE_ESTADO, CLAVE_PREVIEW, CLAVE_REGLAS } from "@/lib/claves";

/**
 * El estado del firewall, refrescado solo.
 *
 * Cada llamada relee el sistema y actualiza de paso los contadores de las
 * reglas, asi que el intervalo no es solo para el badge: es lo que hace que los
 * paquetes de la tabla se muevan. 15 s es suficiente para un dashboard y no
 * convierte un `iptables -L -v -n -x` en un bucle cerrado.
 */
export function useEstadoDelFirewall() {
  return useQuery({
    queryKey: CLAVE_ESTADO,
    queryFn: estadoDelFirewall,
    refetchInterval: 15_000,
    // Un fallo del backend no debe dejar el badge en blanco: se sigue viendo
    // el ultimo estado conocido mientras se reintenta.
    placeholderData: (anterior) => anterior,
  });
}

/** El preview solo se pide cuando el dialogo esta abierto, y no se cachea. */
export function usePreview(abierto: boolean) {
  return useQuery({
    queryKey: CLAVE_PREVIEW,
    queryFn: previsualizar,
    enabled: abierto,
    staleTime: 0,
    gcTime: 0,
  });
}

/**
 * Aplicar.
 *
 * Aqui un fallo del firewall llega como 502 y hay que enseñarlo: es lo que
 * distingue este boton del auto-apply, donde el 502 esconderia que la regla si
 * se creo (ADR-0011).
 */
export function useAplicar() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: aplicar,
    onSettled: () => {
      // Tanto si fue bien como si no: el `sync_state` de las reglas ha podido
      // cambiar en ambos casos.
      void queryClient.invalidateQueries({ queryKey: CLAVE_ESTADO });
      void queryClient.invalidateQueries({ queryKey: CLAVE_REGLAS });
    },
  });
}
