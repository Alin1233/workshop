import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// En dev, les appels /api sont relayés vers le back-for-front de la stack (port de gestion SUPERVISION_PORT, 8091) :
// le navigateur demande l'identifiant admin / secrets/supervision_password comme en production.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: { "/api": "http://127.0.0.1:8091" },
  },
});
