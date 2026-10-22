import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

// Le détecteur de visage (WebAssembly) ne tourne pas sous jsdom : par défaut, la capture repasse au compte à rebours ;
// un test le simule avec vi.mocked(loadFaceTracker).
vi.mock("../lib/faceTracker", () => ({ loadFaceTracker: vi.fn(async () => null) }));

// jsdom n'implémente pas les modales natives : ouverture et fermeture réduites à l'attribut open et à l'événement close.
HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
  this.open = true;
};
HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
  this.open = false;
  this.dispatchEvent(new Event("close"));
};

// Sans `globals`, React Testing Library ne démonte pas les rendus tout seul : on nettoie après chaque test,
// ainsi que la session de l'onglet et d'éventuelles horloges simulées.
afterEach(() => {
  cleanup();
  sessionStorage.clear();
  vi.useRealTimers();
});
