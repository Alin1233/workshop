import { ago, toMs } from "../lib/format";
import { useNow } from "../lib/poll";
import type { AlertItem } from "../lib/types";
import { Badge, Empty, Icon } from "./ui";

const DOMAINS: Record<string, string> = {
  availability: "disponibilité", integrity: "intégrité", security: "sécurité", anomaly: "anomalie ML",
};

// Cette méthode permet d'afficher les alertes actives (Alertmanager : règles Prometheus et SOC Loki) et celles encore en
// attente de confirmation dans Prometheus, comme une liste d'alertes Grafana : état, nom, ancienneté, étiquettes.
export default function AlertsPanel({ alerts }: { alerts: AlertItem[] | null }) {
  const now = useNow(1000);
  if (alerts === null) return <Empty>En attente des alertes…</Empty>;
  if (alerts.length === 0) return <Empty tone="ok">Aucune alerte active</Empty>;
  return (
    <ul className="flex flex-col" data-testid="alerts-list">
      {alerts.map((alert) => {
        const critical = alert.severity === "critical";
        const pending = alert.state === "pending";
        const since = toMs(alert.starts_at);
        const color = pending ? "text-warn" : critical ? "text-bad" : "text-warn";
        return (
          <li
            key={`${alert.name}-${alert.service}-${alert.client_ip ?? ""}-${alert.state}`}
            className="flex gap-2 border-b border-edge-weak py-1.5 last:border-b-0"
            data-testid="alert-item"
            data-state={alert.state}
          >
            <span className={`mt-px ${color} ${pending ? "" : "animate-pulse"}`}><Icon name={pending ? "clock" : "bell"} /></span>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline gap-2">
                <span className="truncate text-[14px] font-semibold text-snow">{alert.name}</span>
                <span className={`ml-auto shrink-0 text-[12.5px] tabular ${color}`}>
                  {pending ? "en confirmation" : "en alerte"}{since !== null ? ` · ${ago((now - since) / 1000)}` : ""}
                </span>
              </div>
              <div className="mt-0.5 flex flex-wrap gap-1">
                <Badge tone={critical ? "bad" : "warn"}>{critical ? "critique" : "avertissement"}</Badge>
                <Badge>{DOMAINS[alert.domain] ?? alert.domain}</Badge>
                <Badge>{alert.source === "loki" ? "SOC Loki" : "Prometheus"}</Badge>
                {alert.service ? <Badge>{alert.service}</Badge> : null}
                {alert.client_ip ? <Badge className="tabular">{alert.client_ip}</Badge> : null}
                {alert.silenced ? <Badge tone="warn">silence posé</Badge> : null}
              </div>
              {alert.summary ? <p className="mt-0.5 truncate text-[12.5px] text-fog" title={alert.summary}>{alert.summary}</p> : null}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
