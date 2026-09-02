import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import App from "@/App";
import "@/styles.css";

/**
 * Bloque A6.
 *
 * `retry: 0`: un 401 o un 422 no mejoran por insistir, y reintentar tres veces
 * solo retrasa el mensaje de error. Lo unico que se reintenta solo es el estado
 * del firewall, que tiene su propio intervalo.
 */
const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 0, refetchOnWindowFocus: false, staleTime: 5_000 },
    mutations: { retry: 0 },
  },
});

const contenedor = document.getElementById("root");
if (!contenedor) throw new Error("No se encontro el elemento #root");

createRoot(contenedor).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
