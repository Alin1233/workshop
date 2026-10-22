import { useCallback, useEffect, useRef, useState } from "react";
import type { FacePose } from "../lib/api";
import { assessPose, type Guidance } from "../lib/faceGuide";
import type { FaceTracker } from "../lib/faceTracker";

// Consigne de chaque pose, telle que la voit l'utilisateur dans l'aperçu en miroir.
const INSTRUCTIONS: Record<FacePose, { arrow: string; text: string }> = {
  center: { arrow: "●", text: "Regardez droit vers la caméra" },
  left: { arrow: "←", text: "Tournez la tête vers la gauche" },
  right: { arrow: "→", text: "Tournez la tête vers la droite" },
};
const COUNTDOWN_SECONDS = 3;
// Guidage : analyse du flux 10 fois par seconde, capture quand la pose est tenue HOLD_MS sans interruption.
const ANALYSIS_INTERVAL_MS = 100;
const HOLD_MS = 600;
// Largeur des captures envoyées : assez pour la détection (visage de 80 px au moins), loin des 400 Ko acceptés.
const CAPTURE_WIDTH = 640;

const primaryButton =
  "rounded-lg bg-ink px-4 py-2 text-sm font-semibold text-white transition hover:bg-ink-2 disabled:opacity-60";
const secondaryButton = "rounded-lg border border-line bg-white px-4 py-2 text-sm text-ink transition hover:bg-chip disabled:opacity-60";

// guided : le détecteur du navigateur guide et déclenche les captures ; ready/capturing : compte à rebours, à défaut.
type Phase = "starting" | "guided" | "ready" | "capturing" | "done";
type Props = { poses: FacePose[]; onCaptured: (frames: Blob[]) => void; onCancel: () => void; busy?: boolean };

// Cette méthode permet de savoir d'emblée si la caméra est inaccessible : le navigateur ne l'ouvre qu'en contexte
// sécurisé (HTTPS, ou http://localhost), d'où le renvoi vers l'adresse HTTPS du WAF.
export function cameraUnavailableReason(): string | null {
  if ("mediaDevices" in navigator && typeof navigator.mediaDevices.getUserMedia === "function") return null;
  return window.isSecureContext
    ? "Aucune caméra n'est accessible dans ce navigateur."
    : "La caméra n'est accessible qu'en HTTPS : ouvrez l'adresse https:// de la plateforme.";
}

// Cette méthode permet de traduire un refus du navigateur (permission, absence de caméra) en message compréhensible.
function cameraErrorMessage(err: unknown): string {
  const name = err instanceof DOMException ? err.name : "";
  if (name === "NotAllowedError") return "Accès à la caméra refusé : autorisez-le dans le navigateur, puis réessayez.";
  if (name === "NotFoundError" || name === "OverconstrainedError") return "Aucune caméra détectée sur cet appareil.";
  if (name === "NotReadableError") return "La caméra est déjà utilisée par une autre application.";
  return "Impossible d'ouvrir la caméra.";
}

// Cette méthode permet de couper la caméra (le voyant s'éteint) dès que les captures sont prises ou abandonnées.
function stopStream(stream: MediaStream | null): void {
  stream?.getTracks().forEach((track) => track.stop());
}

// Cette méthode permet de prendre une image JPEG du flux vidéo, non inversée : le serveur attend la vue de la caméra,
// seul l'aperçu est affiché en miroir.
async function grabFrame(video: HTMLVideoElement | null): Promise<Blob> {
  if (!video?.videoWidth) throw new Error("flux vidéo indisponible");
  const scale = Math.min(1, CAPTURE_WIDTH / video.videoWidth);
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(video.videoWidth * scale);
  canvas.height = Math.round(video.videoHeight * scale);
  const context = canvas.getContext("2d");
  if (!context) throw new Error("canvas indisponible");
  context.drawImage(video, 0, 0, canvas.width, canvas.height);
  return new Promise((resolve, reject) =>
    canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("encodage JPEG impossible"))), "image/jpeg", 0.85),
  );
}

// Cette méthode permet de charger le détecteur de visage à la demande (son moteur WebAssembly pèse plusieurs Mo) ;
// null si le navigateur ne peut pas le faire tourner.
function loadTracker(): Promise<FaceTracker | null> {
  return import("../lib/faceTracker").then((module) => module.loadFaceTracker()).catch(() => null);
}

// Cette méthode permet de filmer l'utilisateur et de prendre une capture par pose du défi : guidé en direct par le
// détecteur du navigateur (capture automatique une fois la pose tenue), ou à défaut après un compte à rebours de 3 s.
export default function FaceCapture({ poses, onCaptured, onCancel, busy = false }: Props) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const trackerRef = useRef<FaceTracker | null>(null);
  const framesRef = useRef<Blob[]>([]);
  const frontYawRef = useRef(0);
  const onCapturedRef = useRef(onCaptured);
  const [phase, setPhase] = useState<Phase>("starting");
  const [error, setError] = useState<string | null>(cameraUnavailableReason);
  const [index, setIndex] = useState(0);
  const [count, setCount] = useState(COUNTDOWN_SECONDS);
  const [guidance, setGuidance] = useState<Guidance | null>(null);

  useEffect(() => {
    onCapturedRef.current = onCaptured;
  }, [onCaptured]);

  // Ouverture de la caméra frontale et chargement du détecteur au montage, fermeture des deux au démontage.
  useEffect(() => {
    if (cameraUnavailableReason()) return;
    let cancelled = false;
    const camera = navigator.mediaDevices.getUserMedia({
      video: { facingMode: "user", width: { ideal: 640 }, height: { ideal: 480 } },
      audio: false,
    });
    Promise.all([camera, loadTracker()])
      .then(([stream, tracker]) => {
        if (cancelled) {
          tracker?.close();
          return stopStream(stream);
        }
        streamRef.current = stream;
        trackerRef.current = tracker;
        if (videoRef.current) videoRef.current.srcObject = stream;
        setPhase(tracker ? "guided" : "ready");
      })
      .catch((err) => {
        if (!cancelled) setError(cameraErrorMessage(err));
      });
    return () => {
      cancelled = true;
      stopStream(streamRef.current);
      streamRef.current = null;
      trackerRef.current?.close();
      trackerRef.current = null;
    };
  }, []);

  // Cette méthode permet de ranger une capture et de passer à la pose suivante, ou de tout envoyer après la dernière.
  const record = useCallback(
    (frame: Blob) => {
      framesRef.current = [...framesRef.current, frame];
      if (framesRef.current.length < poses.length) {
        setIndex(framesRef.current.length);
        setCount(COUNTDOWN_SECONDS);
        setGuidance(null);
        return;
      }
      stopStream(streamRef.current);
      streamRef.current = null;
      setPhase("done");
      onCapturedRef.current(framesRef.current);
    },
    [poses.length],
  );

  // Guidage en direct : la consigne suit ce que voit le détecteur, la capture part dès que la pose est tenue.
  useEffect(() => {
    const tracker = trackerRef.current;
    if (phase !== "guided" || !tracker) return;
    let frameId = 0;
    let last = -Infinity;
    let heldSince: number | null = null;
    let grabbing = false;
    let stopped = false;
    const tick = (now: number) => {
      if (stopped) return;
      frameId = requestAnimationFrame(tick);
      const video = videoRef.current;
      if (grabbing || !video?.videoWidth || now - last < ANALYSIS_INTERVAL_MS) return;
      last = now;
      const pose = poses[framesRef.current.length];
      let observation;
      try {
        observation = tracker.observe(video, now);
      } catch {
        return;
      }
      const next = assessPose(observation, pose, frontYawRef.current);
      setGuidance((prev) => (prev?.ok === next.ok && prev.hint === next.hint ? prev : next));
      if (!next.ok) {
        heldSince = null;
        return;
      }
      heldSince ??= now;
      if (now - heldSince < HOLD_MS) return;
      grabbing = true;
      heldSince = null;
      const yaw = observation.yaw;
      grabFrame(video)
        .then((frame) => {
          if (stopped) return;
          if (pose === "center") frontYawRef.current = yaw;
          grabbing = false;
          record(frame);
        })
        .catch(() => {
          if (!stopped) setError("Capture impossible : réessayez.");
        });
    };
    frameId = requestAnimationFrame(tick);
    return () => {
      stopped = true;
      cancelAnimationFrame(frameId);
    };
  }, [phase, poses, record]);

  // Compte à rebours de la pose courante, puis capture et passage à la suivante (sans détecteur).
  useEffect(() => {
    if (phase !== "capturing") return;
    if (count > 0) {
      const timer = setTimeout(() => setCount((value) => value - 1), 1000);
      return () => clearTimeout(timer);
    }
    let cancelled = false;
    grabFrame(videoRef.current)
      .then((frame) => {
        if (!cancelled) record(frame);
      })
      .catch(() => {
        if (!cancelled) setError("Capture impossible : réessayez.");
      });
    return () => {
      cancelled = true;
    };
  }, [phase, count, record]);

  const pose = INSTRUCTIONS[poses[index] ?? "center"];
  const active = phase === "guided" || phase === "capturing";
  const ovalColor = phase !== "guided" || !guidance ? "border-white/70" : guidance.ok ? "border-mint" : "border-amber";

  return (
    <div className="space-y-3" data-testid="face-capture">
      {error ? (
        <p className="rounded-lg border border-brick-line bg-brick-soft px-3 py-2 text-sm text-brick" role="alert">
          {error}
        </p>
      ) : (
        <div className="relative aspect-[4/3] overflow-hidden rounded-xl bg-ink">
          <video
            ref={videoRef}
            autoPlay
            muted
            playsInline
            aria-label="Aperçu de la caméra"
            className={`h-full w-full -scale-x-100 object-cover transition ${phase === "done" ? "opacity-40" : ""}`}
          />
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <div className={`aspect-[3/4] h-3/4 rounded-[50%] border-4 transition-colors ${ovalColor}`} />
          </div>
          {phase === "starting" && (
            <p className="absolute inset-0 flex items-center justify-center text-sm text-white">Ouverture de la caméra…</p>
          )}
          {active && (
            <ol className="absolute inset-x-0 top-0 flex justify-center gap-1.5 p-2" aria-hidden>
              {poses.map((step, i) => (
                <li key={step} className={`h-1.5 w-8 rounded-full ${i < index ? "bg-mint" : i === index ? "bg-white" : "bg-white/30"}`} />
              ))}
            </ol>
          )}
          {active && (
            <div className="absolute inset-x-0 bottom-0 bg-ink/75 px-3 py-2 text-center text-white">
              <p className="text-sm font-semibold" aria-live="assertive">
                <span aria-hidden>{pose.arrow} </span>
                {pose.text}
              </p>
              {phase === "guided" ? (
                <p className={`text-sm ${guidance?.ok ? "text-mint" : "text-amber-soft"}`} aria-live="polite" data-testid="face-hint">
                  {guidance?.hint ?? "Recherche du visage…"}
                </p>
              ) : (
                <p className="text-2xl font-bold tabular-nums" data-testid="face-countdown">
                  {count > 0 ? count : "Capture…"}
                </p>
              )}
            </div>
          )}
          {phase === "done" && (
            <p className="absolute inset-0 flex items-center justify-center text-sm font-semibold text-white">
              {busy ? "Vérification…" : "Captures prises"}
            </p>
          )}
        </div>
      )}
      {!error && (
        <p className="text-xs text-muted">
          {active
            ? `Capture ${index + 1} sur ${poses.length}`
            : `Placez votre visage dans l'ovale, bien éclairé. ${
                poses.length === 2
                  ? "Deux photos : de face, puis la tête tournée d'un côté."
                  : "Trois photos : de face, puis la tête tournée de chaque côté."
              }`}
        </p>
      )}
      <div className="flex gap-2">
        {phase === "ready" && !error && (
          <button type="button" onClick={() => setPhase("capturing")} className={primaryButton}>
            Démarrer
          </button>
        )}
        <button type="button" onClick={onCancel} disabled={busy} className={secondaryButton}>
          Annuler
        </button>
      </div>
    </div>
  );
}
