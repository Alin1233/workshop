// Formats d'affichage (français, fuseau du navigateur) : heures, durées, chronomètres.

const clockFormat = new Intl.DateTimeFormat("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const dayFormat = new Intl.DateTimeFormat("fr-FR", { day: "2-digit", month: "2-digit" });

// Cette méthode permet de lire un horodatage ISO en millisecondes (null s'il est absent ou illisible).
export function toMs(value: string | null | undefined): number | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

// Cette méthode permet d'afficher l'heure d'un événement (HH:MM:SS), précédée du jour s'il ne s'agit pas d'aujourd'hui.
export function clockTime(value: string | number | null | undefined, now = Date.now()): string {
  const ms = typeof value === "number" ? value : toMs(value);
  if (ms === null) return "—";
  const sameDay = new Date(ms).toDateString() === new Date(now).toDateString();
  return sameDay ? clockFormat.format(ms) : `${dayFormat.format(ms)} ${clockFormat.format(ms)}`;
}

// Cette méthode permet d'écrire une durée courte à la française : « 6,7 s », « 46 s », « 2 min 05 s », « 1 h 03 min ».
export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return "—";
  const s = Math.max(0, seconds);
  if (s < 10) return `${s.toFixed(1).replace(".", ",")} s`;
  if (s < 60) return `${Math.round(s)} s`;
  if (s < 3600) {
    const total = Math.round(s);
    return `${Math.floor(total / 60)} min ${String(total % 60).padStart(2, "0")} s`;
  }
  const minutes = Math.floor(s / 60);
  return `${Math.floor(minutes / 60)} h ${String(minutes % 60).padStart(2, "0")} min`;
}

// Cette méthode permet d'afficher un chronomètre ou un compte à rebours « MM:SS » (« H:MM:SS » au-delà d'une heure).
export function chrono(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const sec = total % 60;
  const mmss = `${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  return h ? `${h}:${mmss}` : mmss;
}

// Cette méthode permet d'écrire l'écart à un instant de référence : « T+15,4 s ».
export function offset(seconds: number | null): string {
  if (seconds === null) return "";
  return `T+${duration(seconds)}`;
}

// Cette méthode permet d'écrire l'ancienneté d'un événement : « à l'instant », « il y a 12 s », « il y a 3 min ».
export function ago(seconds: number | null): string {
  if (seconds === null) return "";
  if (seconds < 2) return "à l'instant";
  if (seconds < 60) return `il y a ${Math.round(seconds)} s`;
  if (seconds < 3600) return `il y a ${Math.round(seconds / 60)} min`;
  return `il y a ${Math.round(seconds / 3600)} h`;
}

// Cette méthode permet d'écrire un score décimal à la française (0,95).
export function decimal(value: number | null | undefined, digits = 2): string {
  if (value === null || value === undefined) return "—";
  return value.toFixed(digits).replace(".", ",");
}
