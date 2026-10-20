import { defineConfig, mergeConfig } from "vitest/config";
import viteConfig from "./vite.config";

// Tests de l'écran de supervision (Vitest + React Testing Library) : DOM simulé par jsdom, aucun appel réseau
// (fetch toujours simulé), horloge simulée pour les chronomètres et les compte à rebours.
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "jsdom",
      include: ["src/**/*.test.{ts,tsx}"],
      setupFiles: ["./src/test/setup.ts"],
      restoreMocks: true,
      unstubGlobals: true,
    },
  }),
);
