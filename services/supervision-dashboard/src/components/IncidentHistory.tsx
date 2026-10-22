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

// Cette méthode permet d'afficher l'historique des derniers incidents en tableau : heure, alerte, nature, réponse, issue,
// durée. Dans un panneau étroit, la nature puis la réponse sont masquées (largeur du panneau, pas de l'écran).
export default function IncidentHistory({ incidents, focusId }: { incidents: IncidentSummary[] | null; focusId: string | null }) {
  if (incidents === null) return <Empty>En attente de l'historique…</Empty>;
  if (incidents.length === 0) return <Empty>Aucun incident enregistré</Empty>;
  return (
    <div className="@container">
      <table className="w-full table-fixed border-collapse text-[13px]" data-testid="incident-history">
        <thead>
          <tr className="border-b border-edge text-left text-[12.5px] text-fog">
            <th className="w-[7.25rem] py-1.5 pr-2 font-medium">Heure</th>
            <th className="py-1.5 pr-2 font-medium @sm:w-[30%]">Alerte</th>
            <th className="hidden w-[7rem] py-1.5 pr-2 font-medium @xl:table-cell">Nature</th>
            <th className="hidden py-1.5 pr-2 font-medium @sm:table-cell">Réponse</th>
            <th className="w-[4.5rem] py-1.5 pr-2 font-medium">Issue</th>
            <th className="w-[3.75rem] py-1.5 text-right font-medium">Durée</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => {
            const outcome = incident.open
              ? { label: incident.state === "recovered" ? "rétabli" : "en cours", className: incident.state === "recovered" ? "text-ok" : "text-warn" }
              : OUTCOMES[incident.outcome ?? ""] ?? { label: incident.outcome ?? "—", className: "text-fog" };
            const response = `${incident.service ?? "—"} · ${whatWasDone(incident, incidents)}`;
            return (
              <tr key={incident.id} className={`border-b border-edge-weak last:border-b-0 ${incident.id === focusId ? "bg-white/[0.05]" : ""}`} title={incident.id}>
                <td className="truncate py-1.5 pr-2 tabular text-[12.5px] text-fog">{clockTime(incident.created_at)}</td>
                <td className="truncate py-1.5 pr-2 font-semibold text-snow">{incident.alertname}</td>
                <td className="hidden py-1.5 pr-2 @xl:table-cell"><NatureChip nature={incident.nature} /></td>
                <td className="hidden truncate py-1.5 pr-2 text-fog @sm:table-cell" title={response}>{response}</td>
                <td className={`truncate py-1.5 pr-2 font-semibold ${outcome.className}`}>{outcome.label}</td>
                <td className="py-1.5 text-right text-snow tabular">{incident.duration_s !== null ? duration(incident.duration_s) : "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
