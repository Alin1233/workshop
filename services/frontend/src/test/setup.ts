import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

// Sans `globals`, React Testing Library ne démonte pas les rendus tout seul : on nettoie après chaque test,
// ainsi que la session de l'onglet et d'éventuelles horloges simulées.
afterEach(() => {
  cleanup();
  sessionStorage.clear();
  vi.useRealTimers();
});
