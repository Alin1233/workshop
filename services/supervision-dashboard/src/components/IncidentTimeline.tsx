import { ago, clockTime, duration, offset, toMs } from "../lib/format";
import { useNow } from "../lib/poll";
import { buildSteps, type CheckItem, type Step, type StepStatus } from "../lib/timeline";
import type { GlobalStatus, IncidentDetail } from "../lib/types";
import { Empty, NatureChip } from "./ui";

const MARK: Record<StepStatus, { circle: string; text: string; icon: string }> = {
  done: { circle: "border-ok bg-ok text-ink", text: "text-snow", icon: "✓" },
  current: { circle: "border-warn bg-warn/20 text-warn animate-pulse", text: "text-warn", icon: "●" },
  pending: { circle: "border-edge bg-transparent text-mute", text: "text-mute", icon: "" },
  failed: { circle: "border-bad bg-bad text-white", text: "text-bad", icon: "✕" },
  skipped: { circle: "border-edge bg-white/5 text-mute", text: "text-fog", icon: "–" },
};

const CHECK_STYLE: Record<CheckItem["status"], string> = {
  ok: "border-ok/60 bg-ok/15 text-ok",
  failed: "border-bad bg-bad/20 text-bad",
  unavailable: "border-warn/60 bg-warn/10 text-warn",
  running: "border-warn bg-warn/20 text-warn animate-pulse",
  pending: "border-edge text-mute",
};
const CHECK_ICON: Record<CheckItem["status"], string> = { ok: "✓", failed: "✕", unavailable: "?", running: "…", pending: "○" };

// Cette méthode permet d'afficher une étape de la chronologie : pastille d'état, titre, heure et écart au début,
// détail (décision en clair, action et son résultat, contrôles de vérification).
function StepRow({ step, last }: { step: Step; last: boolean }) {
  const mark = MARK[step.status];
  return (
    <li className="relative flex gap-3" data-testid={`step-${step.key}`} data-status={step.status}>
      {!last ? <span aria-hidden className={`absolute left-[15px] top-8 bottom-[-6px] w-0.5 ${step.status === "done" ? "bg-ok/60" : "bg-edge"}`} /> : null}
      <span className={`z-10 grid h-8 w-8 shrink-0 place-items-center rounded-full border-2 text-[15px] font-black ${mark.circle}`} aria-hidden>
        {mark.icon}
      </span>
      <div className="min-w-0 flex-1 pb-1">
        <div className="flex items-baseline justify-between gap-3">
          <p className={`text-[16.5px] font-bold leading-tight ${mark.text}`}>
            {step.title}
            {step.nature ? <span className="ml-2 align-middle"><NatureChip nature={step.nature} /></span> : null}
          </p>
          <p className="shrink-0 text-[14px] text-fog tabular">
            {step.atMs !== null ? clockTime(step.atMs) : ""}
            {step.offsetS !== null ? <span className="ml-2 text-mute">{offset(step.offsetS)}</span> : null}
            {step.durationS !== null && step.durationS >= 0.05 ? <span className="ml-2 text-mute">({duration(step.durationS)})</span> : null}
          </p>
        </div>
        {step.detail ? <p className="truncate text-[14.5px] leading-snug text-snow/90" title={step.detail}>{step.detail}</p> : null}
        {step.note ? <p className="truncate text-[13px] leading-snug text-mute" title={step.note}>{step.note}</p> : null}
        {step.checks?.length ? (
          <ul className="mt-0.5 flex flex-wrap gap-1.5">
            {step.checks.map((check) => (
              <li key={check.key} className={`rounded-md border px-2 py-0.5 text-[13px] font-semibold ${CHECK_STYLE[check.status]}`} data-testid={`check-${check.key}`} data-status={check.status}>
                {CHECK_ICON[check.status]} {check.label}
                {check.note ? <span className="font-normal opacity-85"> · {check.note}</span> : null}
                {check.ms !== null && check.ms >= 100 ? <span className="font-normal opacity-70"> · {check.ms} ms</span> : null}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </li>
  );
}

// Cette méthode permet d'afficher le début d'un incident que le moteur n'a pas encore reçu : l'anomalie est visible
// (sondes, détecteur, alerte en attente), les étapes suivantes restent à venir.
function PreIncident({ status }: { status: GlobalStatus }) {
  const since = toMs(status.since);
  const steps: Step[] = [
    { key: "alert", title: "Anomalie observée", status: "current", atMs: since, offsetS: since !== null ? 0 : null, durationS: null, detail: status.step },
    { key: "detected", title: "Détecté par le moteur", status: "pending", atMs: null, offsetS: null, durationS: null, detail: "En attente de l'alerte (confirmation Prometheus / SOC, Alertmanager)" },
    { key: "decided", title: "Décision", status: "pending", atMs: null, offsetS: null, durationS: null, detail: "Disponibilité (redémarrage) ou compromission (blocage, restauration)" },
    { key: "action", title: "Action", status: "pending", atMs: null, offsetS: null, durationS: null, detail: "—" },
    { key: "verification", title: "Vérification", status: "pending", atMs: null, offsetS: null, durationS: null, detail: "Conteneurs, sondes, intégrité, transaction témoin" },
    { key: "outcome", title: "Rétablissement", status: "pending", atMs: null, offsetS: null, durationS: null, detail: "—" },
  ];
  return (
    <ol className="flex flex-col gap-1" data-testid="timeline-steps">
      {steps.map((step, i) => <StepRow key={step.key} step={step} last={i === steps.length - 1} />)}
    </ol>
  );
}

// Cette méthode permet d'afficher la chronologie de l'incident en cours ou du dernier incident, telle que le moteur
// l'a horodatée : alerte, détection, décision (nature + action), action, vérification, issue.
export default function IncidentTimeline({ incident, status }: { incident: IncidentDetail | null; status: GlobalStatus | null }) {
  const now = useNow(5000);
  const preIncident = status && (status.phase === "incident" || status.phase === "remediation") && !status.incident_id;
  if (preIncident) {
    return (
      <div className="flex h-full flex-col gap-2">
        <p className="text-[15px] font-semibold text-bad">Nouvel incident : en attente de sa prise en charge par le moteur</p>
        <PreIncident status={status} />
      </div>
    );
  }
  if (!incident) return <Empty>Aucun incident enregistré par le moteur</Empty>;
  const steps = buildSteps(incident);
  const closed = toMs(incident.closed_at);
  return (
    <div className="flex h-full flex-col gap-2">
      <div className="flex items-baseline gap-x-3 overflow-hidden whitespace-nowrap" title={incident.id}>
        <p className={`text-[15px] font-bold ${incident.open ? (incident.state === "recovered" ? "text-ok" : "text-warn") : "text-fog"}`}>
          {!incident.open
            ? `Dernier incident · clos ${ago(closed !== null ? (now - closed) / 1000 : null)}`
            : incident.state === "recovered" ? "Incident rétabli · en attente de la retombée des alertes" : "Incident en cours"}
        </p>
        <p className="truncate text-[15px] text-snow">{incident.alertname}{incident.service ? ` · ${incident.service}` : ""}</p>
      </div>
      <ol className="flex min-h-0 flex-col gap-0.5" data-testid="timeline-steps">
        {steps.map((step, i) => <StepRow key={step.key} step={step} last={i === steps.length - 1} />)}
      </ol>
    </div>
  );
}
