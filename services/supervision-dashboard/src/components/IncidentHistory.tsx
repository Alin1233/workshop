import { clockTime, duration } from "../lib/format";
import { actionLabel, decisionLabel } from "../lib/labels";
import type { IncidentSummary } from "../lib/types";
import { Empty, NatureChip } from "./ui";

const OUTCOMES: Record<string, { label: string; className: string }> = {
  recovered: { label: "rétabli", className: "text-ok" },
  escalated: { label: "escaladé", className: "text-bad" },
  observed: { label: "observé", className: "text-fog" },
  resolved_without_action: { label: "retombé seul", className: "text-fog" },
};

// Cette méthode permet de résumer ce qui a été fait : la dernière action exécutée, sinon la décision.
function whatWasDone(incident: IncidentSummary, all: IncidentSummary[]): string {
  if (incident.follow_up_of) {
    const parent = all.find((other) => other.id === incident.follow_up_of);
    return `rattaché à ${parent ? parent.alertname : "l'incident précédent"} : déjà traité, vérifié seulement`;
  }
  const action = incident.last_action;
  if (action) return `${actionLabel(action.action, action.target)}${action.result !== "success" ? ` (${action.result})` : ""}`;
  return decisionLabel(incident.decision);
}

// Cette méthode permet d'afficher l'historique des derniers incidents : heure, alerte, nature, réponse, issue, durée.
export default function IncidentHistory({ incidents, focusId }: { incidents: IncidentSummary[] | null; focusId: string | null }) {
  if (incidents === null) return <Empty>En attente de l'historique…</Empty>;
  if (incidents.length === 0) return <Empty>Aucun incident enregistré</Empty>;
  return (
    <ul className="flex flex-col" data-testid="incident-history">
      {incidents.map((incident) => {
        const outcome = incident.open
          ? { label: incident.state === "recovered" ? "rétabli" : "en cours", className: incident.state === "recovered" ? "text-ok" : "text-warn" }
          : OUTCOMES[incident.outcome ?? ""] ?? { label: incident.outcome ?? "—", className: "text-fog" };
        return (
          <li key={incident.id} className={`border-b border-edge/60 px-1.5 py-1.5 ${incident.id === focusId ? "bg-white/5" : ""}`}>
            <div className="flex items-center gap-2">
              <span className="w-[62px] shrink-0 text-[13px] text-fog tabular">{clockTime(incident.created_at)}</span>
              <span className="truncate text-[14.5px] font-semibold text-snow">{incident.alertname}</span>
              <NatureChip nature={incident.nature} />
              <span className={`ml-auto shrink-0 text-[13px] font-bold ${outcome.className}`}>{outcome.label}</span>
            </div>
            <div className="flex items-center gap-2 pl-[70px] text-[12.5px] text-mute">
              <span className="truncate">{incident.service ?? "—"} · {whatWasDone(incident, incidents)}</span>
              {incident.duration_s !== null ? <span className="ml-auto shrink-0 tabular">{duration(incident.duration_s)}</span> : null}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
