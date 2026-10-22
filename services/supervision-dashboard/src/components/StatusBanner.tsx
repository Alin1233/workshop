import { chrono, clockTime, duration, toMs } from "../lib/format";
import { useNow } from "../lib/poll";
import type { GlobalStatus, Phase } from "../lib/types";
import { Icon, Panel, type IconName } from "./ui";

// fill : panneau en fond plein (incident, remédiation, rétabli) ; sinon fond sombre et valeur colorée, comme un panneau
// stat de Grafana en mode « valeur »
const PHASES: Record<Phase, { title: string; fill?: string; color: string; sub: string; icon: IconName; value: string }> = {
  operational: { title: "Opérationnel", color: "text-ok", sub: "text-snow", icon: "check", value: "text-mute" },
  incident: { title: "Incident en cours", fill: "border-bad-deep fill-bad text-white", color: "text-white", sub: "text-white/90", icon: "warning", value: "text-bad" },
  remediation: { title: "Remédiation en cours", fill: "border-warn-deep fill-warn text-ink", color: "text-ink", sub: "text-ink/85", icon: "sync", value: "text-warn" },
  restored: { title: "Service rétabli", fill: "border-ok-deep fill-ok text-white", color: "text-white", sub: "text-white/90", icon: "check", value: "text-ok" },
  unknown: { title: "État inconnu", color: "text-fog", sub: "text-fog", icon: "question", value: "text-mute" },
};

// Étapes de la reprise, dans l'ordre du Clip Chrono : le segment de l'étape en cours est mis en évidence.
const PROGRESS = ["Anomalie", "Alerte et décision", "Action", "Vérification", "Rétabli"];
const STEP_INDEX: Record<string, number> = {
  anomaly: 0, alert: 1, detected: 1, decided: 1, observing: 1, escalated: 1, acting: 2, failed: 2, verifying: 3,
  recovered: 4, closed: 4,
};
const CURRENT_SEGMENT: Partial<Record<Phase, string>> = {
  incident: "fill-bad text-white",
  remediation: "fill-warn text-ink",
  restored: "fill-ok text-white",
};

// Cette méthode permet d'afficher l'état global en trois panneaux stat : phase en grand avec l'étape en cours, la décision
// du moteur et les remarques sur les sources ; chronomètre depuis la première anomalie (ou durée figée du rétablissement
// et réaction du moteur) ; avancement de la reprise en segments, comme une « state timeline ».
export default function StatusBanner({ status, stale = false }: { status: GlobalStatus | null; stale?: boolean }) {
  const now = useNow(1000);
  const phase: Phase = status?.phase ?? "unknown";
  const style = PHASES[phase];
  const since = toMs(status?.since);
  const running = phase === "incident" || phase === "remediation";
  const index = status ? STEP_INDEX[status.step_key] : undefined;
  const restored = phase === "restored" && status?.duration_s != null;

  return (
    <div className="grid grid-cols-1 gap-2 md:col-span-12 md:grid-cols-12 xl:col-span-24 xl:grid-cols-24" data-testid="status-banner" data-phase={phase}>
      <Panel title="État global" fill={style.fill} className="md:col-span-12 xl:col-span-11">
        <div className="flex h-full items-center gap-3" role="status" aria-live="polite">
          <Icon name={style.icon} className={`h-10 w-10 sm:h-12 sm:w-12 ${style.color} ${running ? "animate-pulse" : ""}`} />
          <div className="flex min-w-0 flex-1 flex-col gap-1">
            <h1 className={`text-[26px] leading-none font-semibold tracking-tight sm:text-[32px] wall:text-[40px] ${style.color}`}>{style.title}</h1>
            <p className={`text-[15px] leading-snug font-medium sm:text-[17px] wall:truncate wall:text-[19px] ${style.sub}`} data-testid="status-step">
              {status?.step ?? "Connexion aux sources de supervision…"}
            </p>
            <div className={`flex flex-wrap items-center gap-x-4 gap-y-1 text-[13.5px] wall:flex-nowrap wall:overflow-hidden wall:whitespace-nowrap ${style.sub}`}>
              {status?.decision ? <span data-testid="status-decision">Décision : <strong>{status.decision}</strong></span> : null}
              {status?.alertname ? <span>{status.alertname}{status.service ? ` · ${status.service}` : ""}</span> : null}
              {status?.incident_id ? <span className="tabular text-[12.5px] opacity-80">{status.incident_id}</span> : null}
              {status && status.open_incidents > 1 ? <span>+{status.open_incidents - 1} autre(s) incident(s) ouvert(s)</span> : null}
              {status?.escalated ? <span className="rounded-sm bg-white px-1.5 font-bold text-bad-deep">ESCALADÉ</span> : null}
              {stale ? <span className="font-semibold">données figées</span> : null}
            </div>
            {status?.notes.length ? (
              <p className={`flex items-center gap-1.5 text-[13px] opacity-90 ${style.sub}`} data-testid="status-notes">
                <Icon name="warning" className="h-3.5 w-3.5" />
                <span className="wall:truncate">{status.notes.join(" · ")}</span>
              </p>
            ) : null}
          </div>
        </div>
      </Panel>

      <Panel
        title={running ? "Depuis la première anomalie" : restored ? "De la première anomalie au service vérifié" : "Durée de la reprise"}
        className="md:col-span-5 xl:col-span-5"
      >
        <div className="flex h-full min-h-20 flex-col items-center justify-center gap-1 text-center">
          {running && since !== null ? (
            <>
              <span className={`text-[46px] leading-none font-semibold tabular wall:text-[60px] ${style.value}`} data-testid="status-elapsed">
                {chrono((now - since) / 1000)}
              </span>
              <span className="text-[13px] text-fog">première anomalie à {clockTime(since)}</span>
            </>
          ) : restored ? (
            <>
              <span className="text-[46px] leading-none font-semibold text-ok tabular wall:text-[56px]" data-testid="status-duration">
                {duration(status.duration_s)}
              </span>
              {status.reaction_s != null ? (
                <span className="text-[13.5px] text-snow" data-testid="status-reaction">Réaction du moteur : <strong>{duration(status.reaction_s)}</strong></span>
              ) : null}
            </>
          ) : (
            <>
              <span className="text-[32px] leading-none font-semibold text-mute">—</span>
              <span className="text-[13px] text-fog">{phase === "operational" ? "pas d'incident en cours" : "en attente d'un état fiable"}</span>
            </>
          )}
        </div>
      </Panel>

      <Panel title="Étapes de la reprise" className="md:col-span-7 xl:col-span-8">
        {running || phase === "restored" ? (
          <ol className="flex h-full min-h-16 gap-px overflow-hidden rounded-sm" aria-label="Avancement de la reprise">
            {PROGRESS.map((label, i) => {
              const done = index !== undefined && i < index;
              const current = index === i;
              const segment = current ? CURRENT_SEGMENT[phase] : done ? "fill-ok text-white" : "bg-panel-2 text-mute";
              return (
                <li key={label} className={`flex min-w-0 flex-1 flex-col items-center justify-center gap-1 px-1 text-center ${segment}`}>
                  {done || (current && !running) ? <Icon name="check" className="h-4 w-4" /> : null}
                  {current && running ? <Icon name="sync" className="h-4 w-4 animate-[spin_2s_linear_infinite]" /> : null}
                  <span className="text-[12.5px] leading-tight font-semibold sm:text-[13.5px]" aria-current={current ? "step" : undefined}>
                    {label}
                  </span>
                </li>
              );
            })}
          </ol>
        ) : (
          <p className="flex h-full min-h-16 items-center justify-center text-[14px] text-fog">
            {phase === "operational" ? "Pas de reprise en cours" : "État de la reprise inconnu"}
          </p>
        )}
      </Panel>
    </div>
  );
}
