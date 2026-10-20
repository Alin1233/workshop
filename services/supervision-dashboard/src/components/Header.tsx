import { ago, clockTime } from "../lib/format";
import { useNow } from "../lib/poll";
import { Brand } from "./ui";

// Cette méthode permet de qualifier la fraîcheur des données : en direct, figées (rafraîchissement en retard) ou
// supervision injoignable (le back-for-front ne répond plus).
export function liveness(updatedAt: number | null, error: string | null, intervalMs: number, now: number) {
  if (updatedAt === null) return error ? "offline" : "connecting";
  const age = (now - updatedAt) / 1000;
  if (error && age > (intervalMs * 3) / 1000) return "offline";
  return age <= (intervalMs * 2.5) / 1000 + 1 ? "live" : "stale";
}

const LIVE_STYLES = {
  live: { dot: "bg-ok animate-pulse", text: "text-ok", label: "EN DIRECT" },
  stale: { dot: "bg-warn", text: "text-warn", label: "DONNÉES FIGÉES" },
  offline: { dot: "bg-bad animate-pulse", text: "text-bad", label: "SUPERVISION INJOIGNABLE" },
  connecting: { dot: "bg-unknown", text: "text-fog", label: "CONNEXION…" },
};

// Cette méthode permet d'afficher l'en-tête : marque, indicateur « en direct » avec l'heure du dernier rafraîchissement,
// et l'horloge (secondes visibles : la capture du Clip Chrono montre qu'il n'y a pas de coupe).
export default function Header({ updatedAt, error, intervalMs }: { updatedAt: number | null; error: string | null; intervalMs: number }) {
  const now = useNow(500);
  const browserNow = Date.now();
  const state = liveness(updatedAt, error, intervalMs, browserNow);
  const style = LIVE_STYLES[state];
  const age = updatedAt === null ? null : (browserNow - updatedAt) / 1000;
  return (
    <header className="flex items-center justify-between gap-6">
      <Brand />
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-3 rounded-full border border-edge bg-panel px-4 py-1.5" role="status" data-testid="live-indicator" data-state={state}>
          <span className={`h-3 w-3 rounded-full ${style.dot}`} />
          <span className={`text-[14px] font-bold tracking-[0.14em] ${style.text}`}>{style.label}</span>
          <span className="text-[14px] text-fog tabular">
            {updatedAt === null ? "en attente des données" : `actualisé ${ago(age)} · ${clockTime(updatedAt)}`}
            {` · toutes les ${intervalMs / 1000} s`}
          </span>
        </div>
        <time className="text-[36px] font-bold leading-none text-snow tabular" data-testid="wall-clock">
          {clockTime(now)}
        </time>
      </div>
    </header>
  );
}
