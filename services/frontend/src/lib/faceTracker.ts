import { FaceDetector } from "@mediapipe/tasks-vision";
import wasmLoaderPath from "@mediapipe/tasks-vision/vision_wasm_internal.js?url";
import wasmBinaryPath from "@mediapipe/tasks-vision/vision_wasm_internal.wasm?url";
import type { FaceObservation } from "./faceGuide";

// Modèle de détection BlazeFace (MediaPipe, Apache 2.0), servi par le front (Dockerfile) : rien ne part vers un tiers.
const MODEL_PATH = "/mediapipe/blaze_face_short_range.tflite";

export type FaceTracker = { observe: (video: HTMLVideoElement, now: number) => FaceObservation; close: () => void };

// Cette méthode permet de charger le détecteur de visage du navigateur, qui guide l'utilisateur avant chaque capture ;
// renvoie null s'il ne peut pas tourner (WebAssembly bloqué, modèle absent) : la capture repasse au compte à rebours.
export async function loadFaceTracker(): Promise<FaceTracker | null> {
  try {
    const detector = await FaceDetector.createFromOptions(
      { wasmLoaderPath, wasmBinaryPath },
      { baseOptions: { modelAssetPath: MODEL_PATH, delegate: "CPU" }, runningMode: "VIDEO", minDetectionConfidence: 0.6 },
    );
    return {
      observe(video, now) {
        const { detections } = detector.detectForVideo(video, now);
        const [first] = detections;
        const box = first?.boundingBox;
        const [eyeA, eyeB, nose] = first?.keypoints ?? [];
        if (!box || !eyeA || !eyeB || !nose) return { faces: 0, yaw: 0, width: 0, centerX: 0.5, centerY: 0.5 };
        const gap = Math.max(Math.abs(eyeA.x - eyeB.x), 1e-3);
        return {
          faces: detections.length,
          yaw: (nose.x - (eyeA.x + eyeB.x) / 2) / gap,
          width: box.width / video.videoWidth,
          centerX: (box.originX + box.width / 2) / video.videoWidth,
          centerY: (box.originY + box.height / 2) / video.videoHeight,
        };
      },
      close: () => detector.close(),
    };
  } catch {
    return null;
  }
}
