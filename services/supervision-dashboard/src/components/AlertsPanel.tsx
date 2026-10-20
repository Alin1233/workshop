import { ago, toMs } from "../lib/format";
import { useNow } from "../lib/poll";
import type { AlertItem } from "../lib/types";
import { Empty } from "./ui";

const DOMAINS: Record<string, string> = {
  availability: "disponibilité", integrity: "intégrité", security: "sécurité", anomaly: "anomalie ML",
};

// Cette méthode permet d'afficher les alertes actives (Alertmanager : règles Prometheus et SOC Loki) et celles encore en
// attente de confirmation dans Prometheus, avec gravité, domaine, source et ancienneté.
export default function AlertsPanel({ alerts }: { alerts: AlertItem[] | null }) {
  const now = useNow(1000);
  if (alerts === null) return <Empty>En attente des alertes…</Empty>;
  if (alerts.length === 0) return <Empty tone="ok">✓ Aucune alerte active</Empty>;
  return (
    <ul className="flex flex-col gap-1.5" data-testid="alerts-list">
      {alerts.map((alert) => {
        const critical = alert.severity === "critical";
        const pending = alert.state === "pending";
        const since = toMs(alert.starts_at);
        return (
          <li
            key={`${alert.name}-${alert.service}-${alert.client_ip ?? ""}-${alert.state}`}
            className={`rounded-lg border-l-4 bg-panel-2 px-3 py-2 ${pending ? "border-warn/70 opacity-90" : critical ? "border-bad" : "border-warn"}`}
            data-testid="alert-item"
            data-state={alert.state}
          >
            <div className="flex items-center gap-2">
              <span className={`rounded px-1.5 py-0.5 text-[11px] font-black tracking-wider ${critical ? "bg-bad text-white" : "bg-warn text-ink"}`}>
                {critical ? "CRITIQUE" : "AVERTISSEMENT"}
              </span>
              <span className="truncate text-[16px] font-bold text-snow">{alert.name}</span>
              <span className="ml-auto shrink-0 text-[13px] text-mute tabular">{since !== null ? ago((now - since) / 1000) : ""}</span>
            </div>
            <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[13px] text-fog">
              <span>{DOMAINS[alert.domain] ?? alert.domain}</span>
              <span>· {alert.source === "loki" ? "SOC Loki" : "Prometheus"}</span>
              {alert.service ? <span>· {alert.service}</span> : null}
              {alert.client_ip ? <span className="font-mono text-snow">· {alert.client_ip}</span> : null}
              {pending ? <span className="font-semibold text-warn">· en confirmation</span> : null}
              {alert.silenced ? <span className="font-semibold text-warn">· silence posé</span> : null}
            </div>
            {alert.summary ? <p className="truncate text-[13px] text-mute" title={alert.summary}>{alert.summary}</p> : null}
          </li>
        );
      })}
    </ul>
  );
}
