import type { ReactNode } from "react";
import type { Poll } from "../lib/poll";
import type { ComponentState, Envelope, SourceName } from "../lib/types";

const SOURCE_LABELS: Record<SourceName, string> = {
  prometheus: "Prometheus",
  alertmanager: "Alertmanager",
  loki: "Loki",
  engine: "moteur de remédiation",
};

// fill : fond plein des tuiles (mode « arrière-plan » des panneaux stat) ; on : couleur du texte posé dessus
export const STATE_STYLES: Record<ComponentState, { fill: string; on: string; text: string; dot: string; label: string }> = {
  ok: { fill: "fill-ok", on: "text-white", text: "text-ok", dot: "bg-ok", label: "opérationnel" },
  degraded: { fill: "fill-warn", on: "text-ink", text: "text-warn", dot: "bg-warn", label: "dégradé" },
  down: { fill: "fill-bad", on: "text-white", text: "text-bad", dot: "bg-bad", label: "en panne" },
  active: { fill: "fill-busy", on: "text-white", text: "text-busy", dot: "bg-busy", label: "en action" },
  unknown: { fill: "fill-unknown", on: "text-white", text: "text-unknown", dot: "bg-unknown", label: "inconnu" },
};

const ICONS = {
  check: <><circle cx="12" cy="12" r="9" /><path d="m8 12.5 2.6 2.6L16.2 9.5" /></>,
  cross: <><circle cx="12" cy="12" r="9" /><path d="m9.2 9.2 5.6 5.6m0-5.6-5.6 5.6" /></>,
  warning: <><path d="M12 3.8 2.8 19.8h18.4L12 3.8Z" /><path d="M12 10v4.4m0 2.6v.1" /></>,
  sync: <><path d="M19.5 12a7.5 7.5 0 0 1-13.4 4.6M4.5 12a7.5 7.5 0 0 1 13.4-4.6" /><path d="M18.2 3.6v4.2H14m-8.2 12.6v-4.2H10" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7.2V12l3.2 2" /></>,
  bell: <><path d="M6.2 16.5v-5a5.8 5.8 0 0 1 11.6 0v5l1.6 2H4.6l1.6-2Z" /><path d="M10 20.8a2 2 0 0 0 4 0" /></>,
  minus: <><circle cx="12" cy="12" r="9" /><path d="M8 12h8" /></>,
  circle: <circle cx="12" cy="12" r="9" />,
  question: <><circle cx="12" cy="12" r="9" /><path d="M9.6 9.4a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.6m0 3v.1" /></>,
  chevron: <path d="m9.5 6 6 6-6 6" />,
};

export type IconName = keyof typeof ICONS;

// Cette méthode permet d'afficher une icône au trait (couleur du texte courant), à la manière des icônes de Grafana.
export function Icon({ name, className = "h-4 w-4" }: { name: IconName; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className={`shrink-0 ${className}`} aria-hidden>
      {ICONS[name]}
    </svg>
  );
}

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

// Cette méthode permet d'afficher l'avertissement « source indisponible » d'un panneau (jamais de panneau vide sans raison).
export function SourceNotice({ problems }: { problems: string[] }) {
  if (!problems.length) return null;
  return (
    <div className="mx-2 mb-2 flex items-start gap-2 rounded-sm border-l-2 border-warn bg-warn/10 px-2 py-1 text-[12.5px] leading-snug text-warn" role="status" data-testid="source-notice">
      <Icon name="warning" className="mt-px h-3.5 w-3.5" />
      <span>
        <span className="font-semibold">Source indisponible</span> · {problems.join(" · ")}
      </span>
    </div>
  );
}

// Cette méthode permet d'encadrer un panneau à la manière de Grafana : en-tête de 32 px (titre, complément à droite),
// coin orange quand une source manque, avertissement en clair, puis le contenu.
export function Panel({ title, aside, problems = [], className = "", bodyClassName = "", fill, children, testId }: {
  title: string;
  aside?: ReactNode;
  problems?: string[];
  className?: string;
  bodyClassName?: string;
  // Fond plein (mode « arrière-plan » d'un panneau stat) : remplace le fond et la bordure du panneau
  fill?: string;
  children: ReactNode;
  testId?: string;
}) {
  return (
    <section
      className={`relative flex min-h-0 min-w-0 flex-col overflow-hidden rounded border transition-colors duration-300 ${fill ?? "border-edge bg-panel"} ${className}`}
      data-testid={testId}
      aria-label={title}
    >
      {problems.length ? <span aria-hidden className="absolute top-0 left-0 h-0 w-0 border-t-[14px] border-r-[14px] border-t-warn border-r-transparent" title={problems.join("\n")} /> : null}
      <header className="flex h-8 shrink-0 items-center justify-between gap-3 px-2">
        <h2 className={`truncate text-[14px] font-medium ${fill ? "opacity-90" : "text-snow"}`}>{title}</h2>
        {aside ? <div className={`shrink-0 text-[12.5px] ${fill ? "opacity-80" : "text-fog"}`}>{aside}</div> : null}
      </header>
      <SourceNotice problems={problems} />
      <div className={`min-h-0 flex-1 px-2 pb-2 ${bodyClassName}`}>{children}</div>
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
    <p className="flex h-full min-h-20 items-center justify-center text-center text-[14px] text-warn" data-testid="unavailable">
      {what} indisponible : la source ne répond pas
    </p>
  );
}

// Cette méthode permet d'afficher un état vide explicite (« aucune alerte », etc.), coché en vert quand c'est une bonne nouvelle.
export function Empty({ children, tone = "mute" }: { children: ReactNode; tone?: "ok" | "mute" }) {
  return (
    <p className={`flex h-full min-h-20 items-center justify-center gap-1.5 text-center text-[14px] ${tone === "ok" ? "text-ok" : "text-fog"}`}>
      {tone === "ok" ? <Icon name="check" /> : null}
      <span>{children}</span>
    </p>
  );
}

export const BADGE_TONES = {
  ok: "border-ok/40 bg-ok/15 text-ok",
  warn: "border-warn/40 bg-warn/15 text-warn",
  bad: "border-bad/40 bg-bad/15 text-bad",
  busy: "border-busy/40 bg-busy/15 text-busy",
  neutral: "border-edge bg-panel-2 text-fog",
};

export type BadgeTone = keyof typeof BADGE_TONES;

// Cette méthode permet d'afficher une étiquette compacte (gravité, libellé d'alerte, contrôle), comme les badges de Grafana.
export function Badge({ tone = "neutral", className = "", children }: { tone?: BadgeTone; className?: string; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-sm border px-1.5 text-[12px] leading-[18px] font-medium whitespace-nowrap ${BADGE_TONES[tone]} ${className}`}>
      {children}
    </span>
  );
}

const NATURE_TONES: Record<string, BadgeTone> = { availability: "busy", compromise: "bad" };
const NATURE_TEXT: Record<string, string> = {
  availability: "Disponibilité", compromise: "Compromission", triage: "Tri ML", observe: "Observation", operator: "Opérateur", self: "Moteur",
};

// Cette méthode permet d'afficher une étiquette de nature de réponse (disponibilité, compromission…).
export function NatureChip({ nature }: { nature: string | null | undefined }) {
  if (!nature) return null;
  return <Badge tone={NATURE_TONES[nature] ?? "neutral"}>{NATURE_TEXT[nature] ?? nature}</Badge>;
}
