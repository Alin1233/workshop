import type { FacePose } from "./api";

// Ce que le détecteur du navigateur voit sur une image du flux (coordonnées rapportées à l'image, de 0 à 1, non inversée).
export type FaceObservation = {
  faces: number;
  // Lacet calculé comme l'auth-service (face.estimate_yaw) : décalage du nez par rapport au milieu des yeux, en écarts
  // d'yeux ; positif quand la personne tourne la tête vers sa gauche.
  yaw: number;
  width: number;
  centerX: number;
  centerY: number;
};
export type Guidance = { ok: boolean; hint: string };

// Bornes plus strictes que celles du serveur (YAW_CENTER_MAX 0,20, YAW_TURN_MIN 0,15) pour laisser une marge à l'écart
// entre les deux détecteurs ; au-delà de TURN_MAX, le visage de profil ne ressemble plus assez à celui de face.
export const CENTER_MAX = 0.12;
export const TURN_MIN = 0.25;
export const TURN_MAX = 0.65;
const MIN_WIDTH = 0.22;
const MAX_WIDTH = 0.7;
const MAX_OFFSET = 0.2;

// Côté vers lequel tourner, tel que l'utilisateur le voit dans l'aperçu en miroir.
const SIDE: Record<Exclude<FacePose, "center">, { sign: number; label: string }> = {
  left: { sign: 1, label: "gauche" },
  right: { sign: -1, label: "droite" },
};

// Cette méthode permet de dire à l'utilisateur ce qui empêche la capture de la pose demandée (cadrage, distance, sens
// de la rotation) ; frontYaw est le lacet mesuré sur la capture de face, référence des profils comme sur le serveur.
export function assessPose(observation: FaceObservation, pose: FacePose, frontYaw: number): Guidance {
  const { faces, yaw, width, centerX, centerY } = observation;
  if (faces === 0) return { ok: false, hint: "Visage non détecté : placez-vous dans l'ovale, face à la lumière" };
  if (faces > 1) return { ok: false, hint: "Une seule personne doit être face à la caméra" };
  if (width < MIN_WIDTH) return { ok: false, hint: "Rapprochez-vous de la caméra" };
  if (width > MAX_WIDTH) return { ok: false, hint: "Reculez un peu" };
  if (Math.abs(centerX - 0.5) > MAX_OFFSET || Math.abs(centerY - 0.5) > MAX_OFFSET) {
    return { ok: false, hint: "Centrez votre visage dans l'ovale" };
  }
  if (pose === "center") {
    return Math.abs(yaw) > CENTER_MAX
      ? { ok: false, hint: "Regardez droit vers la caméra" }
      : { ok: true, hint: "Ne bougez plus…" };
  }
  const { sign, label } = SIDE[pose];
  const turn = sign * (yaw - frontYaw);
  if (turn < -TURN_MIN) return { ok: false, hint: `Dans l'autre sens : tournez la tête vers la ${label}` };
  if (turn < TURN_MIN) return { ok: false, hint: `Tournez encore la tête vers la ${label}` };
  if (turn > TURN_MAX) return { ok: false, hint: "Un peu moins : revenez légèrement vers la caméra" };
  return { ok: true, hint: "Ne bougez plus…" };
}
