import { act } from "@testing-library/react";
import { vi } from "vitest";

// Cette méthode permet de simuler la caméra du navigateur (jsdom n'a ni getUserMedia, ni vidéo, ni canvas) : flux
// 640 × 480 dont on peut vérifier l'arrêt, captures JPEG factices ; `error` simule un refus (permission, absence).
export function mockCamera(error?: DOMException) {
  const track = { stop: vi.fn() };
  const getUserMedia = vi.fn(async () => {
    if (error) throw error;
    return { getTracks: () => [track] } as unknown as MediaStream;
  });
  Object.defineProperty(navigator, "mediaDevices", { value: { getUserMedia }, configurable: true });
  vi.spyOn(HTMLVideoElement.prototype, "videoWidth", "get").mockReturnValue(640);
  vi.spyOn(HTMLVideoElement.prototype, "videoHeight", "get").mockReturnValue(480);
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue({ drawImage: vi.fn() } as never);
  let shots = 0;
  vi.spyOn(HTMLCanvasElement.prototype, "toBlob").mockImplementation((callback) =>
    callback(new Blob([`jpeg-${++shots}`], { type: "image/jpeg" })),
  );
  return { getUserMedia, track };
}

// Cette méthode permet de retirer la caméra simulée (le navigateur de test redevient sans caméra).
export function restoreCamera() {
  vi.restoreAllMocks();
  Reflect.deleteProperty(navigator, "mediaDevices");
}

// Cette méthode permet de laisser s'écouler les comptes à rebours (3 s par pose) avec une horloge simulée, seconde par
// seconde : chaque seconde n'est programmée qu'après le rendu de la précédente.
export async function elapse(ms: number) {
  for (let left = ms; left > 0; left -= 1000) {
    await act(() => vi.advanceTimersByTimeAsync(Math.min(1000, left)));
  }
}
