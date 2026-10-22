import type { ReactNode } from "react";
import type { Poll } from "../lib/poll";
import type { ComponentState, Envelope, SourceName } from "../lib/types";

const SOURCE_LABELS: Record<SourceName, string> = {
  prometheus: "Prometheus",
  alertmanager: "Alertmanager",
  loki: "Loki",
  engine: "moteur de remédiation",
};

export const STATE_STYLES: Record<ComponentState, { dot: string; text: string; ring: string; label: string }> = {
  ok: { dot: "bg-ok", text: "text-ok", ring: "border-ok/50", label: "opérationnel" },
  degraded: { dot: "bg-warn", text: "text-warn", ring: "border-warn/70", label: "dégradé" },
  down: { dot: "bg-bad animate-pulse", text: "text-bad", ring: "border-bad", label: "en panne" },
  active: { dot: "bg-busy animate-pulse", text: "text-busy", ring: "border-busy/80", label: "en action" },
  unknown: { dot: "bg-unknown", text: "text-unknown", ring: "border-edge", label: "inconnu" },
};

// Cette méthode permet de lister les sources en défaut d'une réponse, et l'échec du back-for-front lui-même.
export function sourceProblems(poll: Poll<Envelope>, names: SourceName[]): string[] {
  const problems: string[] = [];
  if (poll.error) problems.push(poll.data ? `${poll.error} — dernières données affichées` : poll.error);
  for (const name of names) {
    const status = poll.data?.sources?.[name];
    if (status && !status.ok) problems.push(`${SOURCE_LABELS[name]} : ${status.error ?? "indisponible"}`);
  }
  return problems;
}

// Cette méthode permet d'afficher la pastille « source indisponible » d'un panneau (jamais de panneau vide sans raison).
export function SourceNotice({ problems }: { problems: string[] }) {
  if (!problems.length) return null;
  return (
    <div className="flex items-start gap-2 rounded-md border border-warn/60 bg-warn/10 px-2.5 py-1.5 text-[13px] leading-snug text-warn" role="status" data-testid="source-notice">
      <span aria-hidden className="mt-0.5 font-bold">!</span>
      <span>
        <span className="font-semibold">Source indisponible</span> · {problems.join(" · ")}
      </span>
    </div>
  );
}

// Cette méthode permet d'encadrer un panneau de l'écran : titre, complément à droite, avertissement de source, contenu.
export function Panel({ title, aside, problems = [], className = "", children, testId }: {
  title: string;
  aside?: ReactNode;
  problems?: string[];
  className?: string;
  children: ReactNode;
  testId?: string;
}) {
  return (
    <section className={`flex min-h-0 flex-col gap-2.5 rounded-xl border border-edge bg-panel p-3.5 ${className}`} data-testid={testId} aria-label={title}>
      <header className="flex items-center justify-between gap-3">
        <h2 className="text-[13px] font-bold uppercase tracking-[0.12em] text-fog">{title}</h2>
        {aside ? <div className="text-[13px] text-mute">{aside}</div> : null}
      </header>
      <SourceNotice problems={problems} />
      <div className="min-h-0 flex-1 overflow-hidden">{children}</div>
    </section>
  );
}

// Cette méthode permet de savoir si un panneau n'a aucune donnée fiable : back-for-front injoignable sans données
// antérieures, ou toutes ses sources en panne (un « aucun incident » serait alors trompeur).
export function unavailable(poll: Poll<Envelope>, names: SourceName[]): boolean {
  if (!poll.data) return poll.error !== null;
  return names.every((name) => poll.data?.sources?.[name]?.ok === false);
}

// Cette méthode permet d'afficher l'absence de données d'un panneau dont la source ne répond pas.
export function Unavailable({ what }: { what: string }) {
  return (
    <p className="flex h-full min-h-16 items-center justify-center text-center text-[15px] text-warn" data-testid="unavailable">
      {what} indisponible : la source ne répond pas
    </p>
  );
}

// Cette méthode permet d'afficher un état vide explicite (« aucune alerte », etc.).
export function Empty({ children, tone = "mute" }: { children: ReactNode; tone?: "ok" | "mute" }) {
  return (
    <p className={`flex h-full min-h-16 items-center justify-center text-center text-[15px] ${tone === "ok" ? "text-ok" : "text-mute"}`}>
      {children}
    </p>
  );
}

// Cette méthode permet d'afficher le logo-anneau de la marque (identique au front client) et le nom de l'écran.
export function Brand() {
  return (
    <div className="flex items-center gap-3">
      <span className="grid h-9 w-9 place-items-center rounded-lg bg-white/10">
        <span className="h-3.5 w-3.5 rounded-full border-[3px] border-mint" />
      </span>
      <div className="leading-tight">
        <p className="text-[17px] font-bold tracking-tight text-snow">Resilience Pay · Supervision</p>
        <p className="text-[13px] text-mute">Incident → détection → réaction automatique → service vérifié</p>
      </div>
    </div>
  );
}

// Cette méthode permet d'afficher une étiquette de nature de réponse (disponibilité, compromission…).
export function NatureChip({ nature }: { nature: string | null | undefined }) {
  const styles: Record<string, string> = {
    availability: "border-busy/60 bg-busy/15 text-busy",
    compromise: "border-bad/60 bg-bad/15 text-bad",
  };
  const labels: Record<string, string> = {
    availability: "Disponibilité", compromise: "Compromission", triage: "Tri ML", observe: "Observation", operator: "Opérateur", self: "Moteur",
  };
  if (!nature) return null;
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[12px] font-semibold ${styles[nature] ?? "border-edge bg-white/5 text-fog"}`}>
      {labels[nature] ?? nature}
    </span>
  );
}
