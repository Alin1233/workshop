import { ago, clockTime, duration, offset, toMs } from "../lib/format";
import { useNow } from "../lib/poll";
import { buildSteps, type CheckItem, type Step, type StepStatus } from "../lib/timeline";
import type { GlobalStatus, IncidentDetail } from "../lib/types";
import { BADGE_TONES, Empty, Icon, NatureChip, type BadgeTone, type IconName } from "./ui";

const MARK: Record<StepStatus, { icon: IconName; color: string; text: string }> = {
  done: { icon: "check", color: "text-ok", text: "text-snow" },
  current: { icon: "sync", color: "text-warn animate-pulse", text: "text-warn" },
  pending: { icon: "circle", color: "text-mute", text: "text-mute" },
  failed: { icon: "cross", color: "text-bad", text: "text-bad" },
  skipped: { icon: "minus", color: "text-mute", text: "text-fog" },
};

const CHECK_TONE: Record<CheckItem["status"], BadgeTone> = { ok: "ok", failed: "bad", unavailable: "warn", running: "warn", pending: "neutral" };
const CHECK_ICON: Record<CheckItem["status"], IconName> = { ok: "check", failed: "cross", unavailable: "question", running: "sync", pending: "circle" };

// Cette méthode permet d'afficher une étape de la chronologie : icône d'état, titre, heure et écart au début,
// détail (décision en clair, action et son résultat, contrôles de vérification).
function StepRow({ step, last }: { step: Step; last: boolean }) {
  const mark = MARK[step.status];
  return (
    <li className="relative flex gap-2.5" data-testid={`step-${step.key}`} data-status={step.status}>
      {!last ? <span aria-hidden className={`absolute top-6 bottom-0 left-[9px] w-px ${step.status === "done" ? "bg-ok/50" : "bg-edge"}`} /> : null}
      <span className={`mt-0.5 ${mark.color}`}><Icon name={mark.icon} className="h-[19px] w-[19px]" /></span>
      <div className="min-w-0 flex-1 pb-2 wall:pb-1.5">
        <div className="flex flex-wrap items-baseline justify-between gap-x-3">
          <p className={`flex items-center gap-2 text-[14.5px] leading-tight font-semibold ${mark.text}`}>
            {step.title}
            {step.nature ? <NatureChip nature={step.nature} /> : null}
          </p>
          <p className="shrink-0 tabular text-[12.5px] text-fog">
            {step.atMs !== null ? clockTime(step.atMs) : ""}
            {step.offsetS !== null ? <span className="ml-2 text-snow">{offset(step.offsetS)}</span> : null}
            {step.durationS !== null && step.durationS >= 0.05 ? <span className="ml-2 text-mute">({duration(step.durationS)})</span> : null}
          </p>
        </div>
        {step.detail ? <p className="text-[13.5px] leading-snug text-snow/90 wall:truncate" title={step.detail}>{step.detail}</p> : null}
        {step.note ? <p className="text-[12.5px] leading-snug text-fog wall:truncate" title={step.note}>{step.note}</p> : null}
        {step.checks?.length ? (
          <ul className="mt-1 flex flex-wrap gap-1">
            {step.checks.map((check) => (
              <li
                key={check.key}
                className={`inline-flex items-center gap-1 rounded-sm border px-1.5 text-[12px] leading-[20px] ${BADGE_TONES[CHECK_TONE[check.status]]} ${check.status === "running" ? "animate-pulse" : ""}`}
                data-testid={`check-${check.key}`}
                data-status={check.status}
              >
                <Icon name={CHECK_ICON[check.status]} className="h-3.5 w-3.5" />
                <span className="font-semibold">{check.label}</span>
                {check.note ? <span className="opacity-85"> · {check.note}</span> : null}
                {check.ms !== null && check.ms >= 100 ? <span className="opacity-70"> · {check.ms} ms</span> : null}
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
    <ol className="flex flex-col" data-testid="timeline-steps">
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
        <p className="text-[14px] font-semibold text-bad">Nouvel incident : en attente de sa prise en charge par le moteur</p>
        <PreIncident status={status} />
      </div>
    );
  }
  if (!incident) return <Empty>Aucun incident enregistré par le moteur</Empty>;
  const steps = buildSteps(incident);
  const closed = toMs(incident.closed_at);
  return (
    <div className="flex h-full flex-col gap-2">
      <div className="flex flex-wrap items-baseline gap-x-3 border-b border-edge-weak pb-1.5 wall:flex-nowrap wall:overflow-hidden wall:whitespace-nowrap" title={incident.id}>
        <p className={`text-[14px] font-semibold ${incident.open ? (incident.state === "recovered" ? "text-ok" : "text-warn") : "text-fog"}`}>
          {!incident.open
            ? `Dernier incident · clos ${ago(closed !== null ? (now - closed) / 1000 : null)}`
            : incident.state === "recovered" ? "Incident rétabli · en attente de la retombée des alertes" : "Incident en cours"}
        </p>
        <p className="truncate text-[14px] text-snow">{incident.alertname}{incident.service ? ` · ${incident.service}` : ""}</p>
      </div>
      <ol className="flex min-h-0 flex-col" data-testid="timeline-steps">
        {steps.map((step, i) => <StepRow key={step.key} step={step} last={i === steps.length - 1} />)}
      </ol>
    </div>
  );
}
