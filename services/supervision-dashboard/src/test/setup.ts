import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Démonte les rendus entre deux tests (chronomètres et minuteries compris).
afterEach(() => {
  cleanup();
});
