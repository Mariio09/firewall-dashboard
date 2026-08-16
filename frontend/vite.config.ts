import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    port: 5173,
    // Bind solo a localhost: el frontend de desarrollo no debe ser accesible
    // desde otras maquinas de la red.
    host: "127.0.0.1",
  },
});
