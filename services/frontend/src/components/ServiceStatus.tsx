import type { HealthState } from "../lib/useServiceHealth";

const STYLES: Record<HealthState, { pill: string; dot: string; label: string }> = {
  checking: { pill: "border-line bg-white text-muted", dot: "bg-faint", label: "Vérification…" },
  ok: { pill: "border-line bg-white text-muted", dot: "bg-teal ring-teal/15", label: "Tous les services opérationnels" },
  degraded: { pill: "border-amber-line bg-amber-soft text-amber-ink", dot: "bg-amber ring-amber/20", label: "Service dégradé" },
  down: { pill: "border-brick-line bg-brick-soft text-brick", dot: "bg-brick ring-brick/20 animate-pulse", label: "Service indisponible" },
};

// Cette méthode permet d'afficher une pastille de santé (point coloré + libellé), réutilisée dans les bandeaux.
export function StatusDot({ ok }: { ok: boolean | null }) {
  const color = ok === null ? "bg-faint" : ok ? "bg-teal ring-teal/15" : "bg-amber ring-amber/20";
  return <span className={`inline-block h-1.75 w-1.75 shrink-0 rounded-full ring-3 ${color}`} />;
}

// Cette méthode permet d'afficher en continu l'état global des services (rendu visible avant, pendant et après un incident).
export default function ServiceStatus({ state }: { state: HealthState }) {
  const style = STYLES[state];
  return (
    <div
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs ${style.pill}`}
      data-testid="service-status"
      data-state={state}
      role="status"
    >
      <span className={`h-1.75 w-1.75 rounded-full ring-3 ${style.dot}`} />
      <span className="sr-only sm:not-sr-only">{style.label}</span>
    </div>
  );
}
