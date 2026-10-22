import { ago, clockTime } from "../lib/format";
import { useNow } from "../lib/poll";
import { Icon } from "./ui";

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

// Cette méthode permet d'afficher une pastille de la barre d'outils (fenêtre de temps, rafraîchissement) : simple
// indication, pas un bouton.
function ToolbarChip({ icon, children, className = "" }: { icon: "clock" | "sync"; children: string; className?: string }) {
  return (
    <span className={`h-8 items-center gap-1.5 rounded-sm border border-edge bg-panel-2 px-2.5 text-[13px] text-snow ${className}`}>
      <Icon name={icon} className="h-3.5 w-3.5 text-fog" />
      {children}
    </span>
  );
}

// Cette méthode permet d'afficher la barre du haut : marque et fil d'Ariane, indicateur « en direct » avec l'heure du
// dernier rafraîchissement, fenêtre et période de rafraîchissement, horloge du serveur (secondes visibles : la capture du
// Clip Chrono montre qu'il n'y a pas de coupe).
export default function Header({ updatedAt, error, intervalMs }: { updatedAt: number | null; error: string | null; intervalMs: number }) {
  const now = useNow(500);
  const browserNow = Date.now();
  const state = liveness(updatedAt, error, intervalMs, browserNow);
  const style = LIVE_STYLES[state];
  const age = updatedAt === null ? null : (browserNow - updatedAt) / 1000;
  return (
    <header className="sticky top-0 z-20 flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-edge bg-panel px-3 py-2 md:px-4">
      <nav className="flex min-w-0 flex-1 items-center gap-2 text-[14px]" aria-label="Fil d'Ariane">
        <span className="grid h-7 w-7 shrink-0 place-items-center rounded-sm bg-panel-2" aria-hidden>
          <span className="h-3 w-3 rounded-full border-[2.5px] border-mint" />
        </span>
        <span className="hidden whitespace-nowrap text-fog lg:inline">Resilience Pay</span>
        <Icon name="chevron" className="hidden h-3.5 w-3.5 text-mute lg:block" />
        <span className="hidden whitespace-nowrap text-fog sm:inline">Supervision</span>
        <Icon name="chevron" className="hidden h-3.5 w-3.5 text-mute sm:block" />
        <span className="truncate font-medium text-snow" aria-current="page">Reprise d'activité</span>
      </nav>

      <time className="order-2 text-[22px] leading-none font-semibold text-white tabular sm:order-3 sm:text-[24px]" data-testid="wall-clock">
        {clockTime(now)}
      </time>

      <div className="order-3 flex w-full items-center gap-2 sm:order-2 sm:w-auto">
        <div className="flex h-8 min-w-0 flex-1 items-center gap-2 rounded-sm border border-edge bg-panel-2 px-2.5 sm:flex-none" role="status" data-testid="live-indicator" data-state={state}>
          <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${style.dot}`} />
          <span className={`shrink-0 text-[12.5px] font-semibold tracking-wide ${style.text}`}>{style.label}</span>
          <span className="truncate text-[13px] text-fog tabular">
            {updatedAt === null ? "en attente des données" : `actualisé ${ago(age)} · ${clockTime(updatedAt)}`}
          </span>
        </div>
        <ToolbarChip icon="clock" className="hidden lg:inline-flex">30 dernières minutes</ToolbarChip>
        <ToolbarChip icon="sync" className="inline-flex">{`${intervalMs / 1000} s`}</ToolbarChip>
      </div>
    </header>
  );
}
