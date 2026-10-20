import { chrono, duration, toMs } from "../lib/format";
import { useNow } from "../lib/poll";
import type { GlobalStatus, Phase } from "../lib/types";

const PHASES: Record<Phase, { title: string; box: string; title_color: string; sub: string; icon: string }> = {
  operational: { title: "Opérationnel", box: "border-ok/50 bg-panel", title_color: "text-ok", sub: "text-fog", icon: "✓" },
  incident: { title: "Incident en cours", box: "border-bad bg-bad-deep", title_color: "text-white", sub: "text-white/90", icon: "!" },
  remediation: { title: "Remédiation en cours", box: "border-warn bg-warn", title_color: "text-ink", sub: "text-ink/85", icon: "↻" },
  restored: { title: "Service rétabli", box: "border-ok bg-ok-deep", title_color: "text-white", sub: "text-white/90", icon: "✓" },
  unknown: { title: "État inconnu", box: "border-edge bg-panel-2", title_color: "text-fog", sub: "text-fog", icon: "?" },
};

// Étapes de la reprise, dans l'ordre du Clip Chrono : la pastille de l'étape en cours est mise en évidence.
const PROGRESS = ["Anomalie", "Alerte et décision", "Action", "Vérification", "Rétabli"];
const STEP_INDEX: Record<string, number> = {
  anomaly: 0, alert: 1, detected: 1, decided: 1, observing: 1, escalated: 1, acting: 2, failed: 2, verifying: 3,
  recovered: 4, closed: 4,
};

// Cette méthode permet d'afficher le bandeau d'état global : phase en très grand, étape en cours, chronomètre depuis
// la première anomalie (ou durée figée du rétablissement), décision du moteur et remarques sur les sources.
export default function StatusBanner({ status, stale = false }: { status: GlobalStatus | null; stale?: boolean }) {
  const now = useNow(1000);
  const phase: Phase = status?.phase ?? "unknown";
  const style = PHASES[phase];
  const since = toMs(status?.since);
  const running = phase === "incident" || phase === "remediation";
  const index = status ? STEP_INDEX[status.step_key] : undefined;
  const dark = phase === "remediation";

  return (
    <section
      className={`relative flex h-[164px] shrink-0 items-stretch gap-6 overflow-hidden rounded-2xl border-2 px-7 py-3.5 transition-colors duration-300 ${style.box}`}
      data-testid="status-banner"
      data-phase={phase}
      role="status"
      aria-live="polite"
    >
      <div className={`grid h-[92px] w-[92px] shrink-0 place-items-center self-center rounded-full text-[54px] font-black ${dark ? "bg-ink/15 text-ink" : phase === "operational" ? "bg-ok/15 text-ok" : "bg-white/15 text-white"} ${running ? "animate-pulse" : ""}`} aria-hidden>
        {style.icon}
      </div>

      <div className="flex min-w-0 flex-1 flex-col justify-center gap-1.5">
        <h1 className={`text-[50px] font-black leading-none tracking-tight ${style.title_color}`}>{style.title}</h1>
        <p className={`truncate text-[23px] font-semibold leading-tight ${style.sub}`} data-testid="status-step">
          {status?.step ?? "Connexion aux sources de supervision…"}
        </p>
        <div className={`flex items-center gap-x-4 overflow-hidden whitespace-nowrap text-[16px] ${style.sub}`}>
          {status?.decision ? <span data-testid="status-decision">Décision : <strong>{status.decision}</strong></span> : null}
          {phase === "restored" && status?.reaction_s != null ? (
            <span data-testid="status-reaction">Réaction du moteur : <strong>{duration(status.reaction_s)}</strong></span>
          ) : null}
          {status?.alertname ? <span>{status.alertname}{status.service ? ` · ${status.service}` : ""}</span> : null}
          {status?.incident_id ? <span className="font-mono text-[14px] opacity-80">{status.incident_id}</span> : null}
          {status && status.open_incidents > 1 ? <span>+{status.open_incidents - 1} autre(s) incident(s) ouvert(s)</span> : null}
          {status?.escalated ? <span className="rounded bg-white px-2 py-0.5 font-bold text-bad-deep">ESCALADÉ</span> : null}
          {stale ? <span className="font-semibold">données figées</span> : null}
        </div>
        {status?.notes.length ? (
          <p className={`truncate text-[14px] ${style.sub} opacity-90`} data-testid="status-notes">⚠ {status.notes.join(" · ")}</p>
        ) : null}
      </div>

      <div className="flex shrink-0 flex-col items-end justify-center gap-2">
        {running && since !== null ? (
          <>
            <span className={`text-[68px] font-black leading-none tabular ${style.title_color}`} data-testid="status-elapsed">
              {chrono((now - since) / 1000)}
            </span>
            <span className={`text-[15px] ${style.sub}`}>depuis la première anomalie observée</span>
          </>
        ) : phase === "restored" && status?.duration_s != null ? (
          <>
            <span className="text-[62px] font-black leading-none text-white tabular" data-testid="status-duration">
              {duration(status.duration_s)}
            </span>
            <span className="text-[15px] text-white/90">de la première anomalie au service vérifié</span>
          </>
        ) : null}
        {phase !== "operational" && phase !== "unknown" ? (
          <ol className="flex items-center gap-1.5" aria-label="Avancement de la reprise">
            {PROGRESS.map((label, i) => {
              const done = index !== undefined && i < index;
              const current = index === i;
              return (
                <li key={label} className="flex items-center gap-1.5">
                  <span
                    className={`rounded-full px-2.5 py-1 text-[13px] font-bold ${current ? (dark ? "bg-ink text-warn" : "bg-white text-ink") : done ? (dark ? "bg-ink/25 text-ink" : "bg-white/25 text-white") : dark ? "bg-ink/10 text-ink/50" : "bg-white/10 text-white/50"}`}
                    aria-current={current ? "step" : undefined}
                  >
                    {label}
                  </span>
                </li>
              );
            })}
          </ol>
        ) : null}
      </div>
    </section>
  );
}
