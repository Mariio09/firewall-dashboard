/**
 * Raiz de la aplicacion: las rutas. Bloque A6.
 *
 * Organizacion por dominio (`features/`), no por tipo de archivo: cada fase
 * añade una carpeta en lugar de dispersar archivos por `components/`, `hooks/`
 * y `pages/`. Ver docs/ARCHITECTURE.md §8.
 */
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { Layout } from "@/components/Layout";
import { AuthProvider } from "@/features/auth/AuthProvider";
import { LoginPage } from "@/features/auth/LoginPage";
import { RequireAuth } from "@/features/auth/RequireAuth";
import { RulesPage } from "@/features/rules/RulesPage";

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<RequireAuth />}>
            <Route element={<Layout />}>
              <Route index element={<Navigate to="/rules" replace />} />
              <Route path="rules" element={<RulesPage />} />
            </Route>
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
