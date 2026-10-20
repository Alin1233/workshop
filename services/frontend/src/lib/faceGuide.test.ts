import { describe, expect, it } from "vitest";
import { assessPose, type FaceObservation } from "./faceGuide";

const FRONT: FaceObservation = { faces: 1, yaw: 0.02, width: 0.4, centerX: 0.5, centerY: 0.5 };

describe("assessPose", () => {
  it("demande d'abord un visage seul, à bonne distance et centré", () => {
    expect(assessPose({ ...FRONT, faces: 0 }, "center", 0).hint).toMatch(/^Visage non détecté/);
    expect(assessPose({ ...FRONT, faces: 2 }, "center", 0).hint).toBe("Une seule personne doit être face à la caméra");
    expect(assessPose({ ...FRONT, width: 0.1 }, "center", 0).hint).toBe("Rapprochez-vous de la caméra");
    expect(assessPose({ ...FRONT, width: 0.9 }, "center", 0).hint).toBe("Reculez un peu");
    expect(assessPose({ ...FRONT, centerX: 0.8 }, "center", 0).hint).toBe("Centrez votre visage dans l'ovale");
  });

  it("accepte la capture de face seulement tête droite", () => {
    expect(assessPose(FRONT, "center", 0)).toEqual({ ok: true, hint: "Ne bougez plus…" });
    expect(assessPose({ ...FRONT, yaw: 0.3 }, "center", 0)).toEqual({ ok: false, hint: "Regardez droit vers la caméra" });
  });

  it("mesure les profils par rapport à la capture de face, dans une plage", () => {
    const front = 0.05;
    expect(assessPose({ ...FRONT, yaw: 0.15 }, "left", front).hint).toBe("Tournez encore la tête vers la gauche");
    expect(assessPose({ ...FRONT, yaw: 0.45 }, "left", front).ok).toBe(true);
    expect(assessPose({ ...FRONT, yaw: 0.9 }, "left", front).hint).toBe("Un peu moins : revenez légèrement vers la caméra");
    expect(assessPose({ ...FRONT, yaw: 0.45 }, "right", front).hint).toBe("Dans l'autre sens : tournez la tête vers la droite");
    expect(assessPose({ ...FRONT, yaw: -0.35 }, "right", front).ok).toBe(true);
  });
});
