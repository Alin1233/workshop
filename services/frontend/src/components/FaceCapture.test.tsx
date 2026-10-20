import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { FacePose } from "../lib/api";
import type { FaceObservation } from "../lib/faceGuide";
import { loadFaceTracker } from "../lib/faceTracker";
import { elapse, mockCamera, restoreCamera } from "../test/camera";
import FaceCapture from "./FaceCapture";

afterEach(restoreCamera);

// Cette méthode permet d'afficher la capture avec une horloge simulée (comptes à rebours) et des rappels espionnés.
function setup(poses: FacePose[] = ["center", "left", "right"]) {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const onCaptured = vi.fn();
  const onCancel = vi.fn();
  const { unmount } = render(<FaceCapture poses={poses} onCaptured={onCaptured} onCancel={onCancel} />);
  return { onCaptured, onCancel, unmount, user: userEvent.setup({ advanceTimers: vi.advanceTimersByTime }) };
}

describe("FaceCapture", () => {
  it("prend une capture par pose, dans l'ordre du défi, puis coupe la caméra", async () => {
    const camera = mockCamera();
    const { onCaptured, user } = setup(["center", "right", "left"]);

    await user.click(await screen.findByRole("button", { name: "Démarrer" }));
    expect(camera.getUserMedia).toHaveBeenCalledWith(expect.objectContaining({ audio: false }));
    expect(screen.getByText("Regardez droit vers la caméra")).toBeInTheDocument();
    expect(screen.getByTestId("face-countdown")).toHaveTextContent("3");

    await elapse(3000);
    expect(await screen.findByText("Tournez la tête vers la droite")).toBeInTheDocument();
    expect(screen.getByText("Capture 2 sur 3")).toBeInTheDocument();
    await elapse(3000);
    expect(await screen.findByText("Tournez la tête vers la gauche")).toBeInTheDocument();
    expect(onCaptured).not.toHaveBeenCalled();
    await elapse(3000);

    await vi.waitFor(() => expect(onCaptured).toHaveBeenCalledTimes(1));
    const frames: Blob[] = onCaptured.mock.calls[0][0];
    expect(await Promise.all(frames.map((f) => f.text()))).toEqual(["jpeg-1", "jpeg-2", "jpeg-3"]);
    expect(camera.track.stop).toHaveBeenCalled();
    expect(screen.getByText("Captures prises")).toBeInTheDocument();
  });

  it("s'adapte à un défi de connexion à deux poses (de face puis un côté)", async () => {
    mockCamera();
    const { onCaptured, user } = setup(["center", "left"]);

    expect(await screen.findByText(/Deux photos : de face, puis la tête tournée d'un côté/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Démarrer" }));
    expect(screen.getByText("Capture 1 sur 2")).toBeInTheDocument();
    await elapse(3000);
    expect(await screen.findByText("Capture 2 sur 2")).toBeInTheDocument();
    await elapse(3000);

    await vi.waitFor(() => expect(onCaptured).toHaveBeenCalledTimes(1));
    expect(onCaptured.mock.calls[0][0]).toHaveLength(2);
  });

  it("coupe la caméra quand l'utilisateur annule (le parent la démonte)", async () => {
    const camera = mockCamera();
    const { onCancel, unmount, user } = setup();
    await screen.findByRole("button", { name: "Démarrer" });

    await user.click(screen.getByRole("button", { name: "Annuler" }));
    expect(onCancel).toHaveBeenCalledTimes(1);
    unmount();
    expect(camera.track.stop).toHaveBeenCalled();
  });

  it("explique un refus d'accès à la caméra", async () => {
    mockCamera(new DOMException("refus", "NotAllowedError"));
    setup();

    expect(await screen.findByRole("alert")).toHaveTextContent("Accès à la caméra refusé");
    expect(screen.queryByRole("button", { name: "Démarrer" })).not.toBeInTheDocument();
  });

  it("propose l'adresse HTTPS quand le navigateur n'ouvre pas la caméra (HTTP)", async () => {
    setup();

    expect(screen.getByRole("alert")).toHaveTextContent("La caméra n'est accessible qu'en HTTPS");
  });

  it("guide la pose en direct et capture seul quand elle est tenue", async () => {
    const camera = mockCamera();
    const scene: FaceObservation = { faces: 0, yaw: 0, width: 0.4, centerX: 0.5, centerY: 0.5 };
    const tracker = { observe: vi.fn(() => ({ ...scene })), close: vi.fn() };
    vi.mocked(loadFaceTracker).mockResolvedValueOnce(tracker);
    const onCaptured = vi.fn();
    const { unmount } = render(<FaceCapture poses={["center", "left", "right"]} onCaptured={onCaptured} onCancel={vi.fn()} />);

    const hint = await screen.findByTestId("face-hint");
    expect(screen.queryByRole("button", { name: "Démarrer" })).not.toBeInTheDocument();
    await vi.waitFor(() => expect(hint).toHaveTextContent("Visage non détecté"));
    scene.faces = 1;
    expect(await screen.findByText("Capture 2 sur 3", {}, { timeout: 3000 })).toBeInTheDocument();

    expect(screen.getByText("Tournez la tête vers la gauche")).toBeInTheDocument();
    await vi.waitFor(() => expect(screen.getByTestId("face-hint")).toHaveTextContent("Tournez encore la tête vers la gauche"));
    scene.yaw = 0.4;
    expect(await screen.findByText("Capture 3 sur 3", {}, { timeout: 3000 })).toBeInTheDocument();
    await vi.waitFor(() => expect(screen.getByTestId("face-hint")).toHaveTextContent("Dans l'autre sens : tournez la tête vers la droite"));
    scene.yaw = -0.4;

    await vi.waitFor(() => expect(onCaptured).toHaveBeenCalledTimes(1), { timeout: 3000 });
    expect(onCaptured.mock.calls[0][0]).toHaveLength(3);
    expect(camera.track.stop).toHaveBeenCalled();
    unmount();
    expect(tracker.close).toHaveBeenCalled();
  });
});
