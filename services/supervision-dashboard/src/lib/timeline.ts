// Chronologie d'un incident : de la chronologie brute du moteur (GET /api/incidents/{id}, champ timeline) aux étapes
// affichées — alerte → détecté → décidé → action → vérification (contrôles) → rétabli / échec.
import { clockTime, duration, toMs } from "./format";
import { CHECK_SHORT, actionLabel, decisionLabel, natureLabel } from "./labels";
import type { Decision, EngineAlert, IncidentDetail, TimelineEntry } from "./types";

export type StepKey = "alert" | "detected" | "decided" | "action" | "verification" | "outcome";
export type StepStatus = "done" | "current" | "pending" | "failed" | "skipped";
export type CheckStatus = "ok" | "failed" | "unavailable" | "running" | "pending";

export interface CheckItem {
  key: string;
  label: string;
  status: CheckStatus;
  ms: number | null;
  note: string;
}

export interface Step {
  key: StepKey;
  title: string;
  status: StepStatus;
  atMs: number | null;
  offsetS: number | null;
  durationS: number | null;
  detail: string;
  note?: string;
  nature?: string;
  checks?: CheckItem[];
}

const SOC_ALERTS = new Set(["AuthBruteForce", "InvalidTokenFlood", "WafAttackBlocked", "LedgerIntegrityViolationLogged", "DependencyFailures"]);

// Cette méthode permet de lire un champ du détail d'une entrée de chronologie.
function field<T = unknown>(entry: TimelineEntry | undefined, key: string): T | undefined {
  return entry?.detail?.[key] as T | undefined;
}

// Cette méthode permet de lister les noms des alertes de l'incident (résumé : noms ; détail : alertes complètes).
export function alertNames(incident: Pick<IncidentDetail, "alerts" | "alertname">): string[] {
  const names = (incident.alerts ?? []).map((a) => (typeof a === "string" ? a : (a as EngineAlert).labels?.alertname)).filter(Boolean) as string[];
  const unique = [...new Set(names)];
  return unique.length ? [incident.alertname, ...unique.filter((n) => n !== incident.alertname)] : [incident.alertname];
}

// Cette méthode permet de résumer le résultat d'un contrôle de vérification (sondes, témoin, conteneurs…).
function checkNote(key: string, entry: TimelineEntry | undefined): string {
  if (!entry) return "";
  const detail = entry.detail ?? {};
  if (key === "containers" && detail.containers && typeof detail.containers === "object") {
    const values = Object.values(detail.containers as Record<string, string>);
    return `${values.filter((v) => v === "healthy" || v === "running").length}/${values.length}`;
  }
  if (key === "probes" && detail.probes && typeof detail.probes === "object") {
    const values = Object.values(detail.probes as Record<string, number>);
    return `${values.filter((v) => v >= 1).length}/${values.length}`;
  }
  if (key === "probes" && detail.result === "unavailable") return "Prometheus indisponible";
  if (key === "integrity" && detail.status !== undefined) return `HTTP ${String(detail.status)}`;
  if (key === "waf_block" && detail.ip) return `${String(detail.ip)} refusée`;
  if (key === "witness") {
    if (detail.result === "ok") return "virement 1,00 € via le WAF";
    if (detail.error) return String(detail.error).slice(0, 80);
  }
  return "";
}

// Cette méthode permet de décrire le résultat d'une action exécutée (redémarrage, blocage, restauration).
function actionDetail(entry: TimelineEntry): string {
  const name = entry.event.slice("action:".length);
  const target = field<string>(entry, "target");
  const result = field<string>(entry, "result");
  let text = `${actionLabel(name, target)} — ${result === "success" ? "réussi" : result === "refused" ? "refusé" : "en échec"}`;
  if (name === "block_ip" && field<number>(entry, "ttl_s")) text += ` · levée automatique dans ${duration(field<number>(entry, "ttl_s") ?? 0)}`;
  const restore = field<Record<string, unknown>>(entry, "restore");
  if (name === "restore_db" && restore) {
    const age = restore.backup_age_seconds as number | undefined;
    const took = restore.restore_seconds as number | undefined;
    text += `${age !== undefined ? ` · sauvegarde de ${duration(age)}` : ""}${took !== undefined ? ` · ${duration(took)}` : ""}`;
  }
  return text;
}

// Cette méthode permet de construire les six étapes de l'incident, avec horodatage, écart au début et durée.
export function buildSteps(incident: IncidentDetail): Step[] {
  const timeline = incident.timeline ?? [];
  const t0 = toMs(incident.alert_started_at) ?? toMs(incident.created_at);
  const at = (e?: TimelineEntry | null) => (e ? toMs(e.at) ?? e.ts * 1000 : null);
  const offsetOf = (ms: number | null) => (ms !== null && t0 !== null ? Math.max(0, (ms - t0) / 1000) : null);
  const span = (from: number | null, to: number | null) => (from !== null && to !== null ? Math.max(0, (to - from) / 1000) : null);
  const isOpen = incident.open;

  // Dernière décision réelle (avec un type) : les entrées d'escalade « decided » n'en portent pas
  let decideIndex = -1;
  timeline.forEach((e, i) => {
    if ((e.event === "state:decided" || e.event === "decision") && field(e, "kind")) decideIndex = i;
  });
  const decideEntry = decideIndex >= 0 ? timeline[decideIndex] : undefined;
  const decision: Decision | null = (decideEntry?.detail as Decision | undefined) ?? incident.decision ?? null;
  const attempt = decideIndex >= 0 ? timeline.slice(decideIndex + 1) : [];
  const find = (list: TimelineEntry[], pred: (e: TimelineEntry) => boolean) => list.find(pred);
  const findLast = (list: TimelineEntry[], pred: (e: TimelineEntry) => boolean) => [...list].reverse().find(pred);

  const detectedEntry = find(timeline, (e) => e.event === "state:detected");
  const actingEntry = find(attempt, (e) => e.event === "state:acting");
  const actionEntries = attempt.filter((e) => e.event.startsWith("action:") && e.event !== "action:start_refused");
  const verifyingEntry = find(attempt, (e) => e.event === "state:verifying");
  const failedEntry = findLast(attempt, (e) => e.event === "state:failed");
  const recoveredEntry = findLast(timeline, (e) => e.event === "state:recovered");
  const escalatedEntry = findLast(timeline, (e) => e.event === "state:escalated");
  const closedEntry = findLast(timeline, (e) => e.event === "closed");
  const correlated = timeline.filter((e) => e.event === "alert:correlated").map((e) => field<string>(e, "alertname")).filter(Boolean);
  const names = alertNames(incident);

  // 1. Alerte (Prometheus ou règle SOC de Loki)
  const alertMs = toMs(incident.alert_started_at);
  const steps: Step[] = [{
    key: "alert", title: "Alerte déclenchée", status: alertMs !== null ? "done" : "skipped", atMs: alertMs,
    offsetS: offsetOf(alertMs), durationS: span(alertMs, at(detectedEntry)),
    detail: `${incident.alertname} · ${SOC_ALERTS.has(incident.alertname) ? "règle SOC (Loki)" : "règle Prometheus"}${incident.service ? ` · ${incident.service}` : ""}`,
  }];

  // 2. Détection par le moteur (webhook Alertmanager)
  const detectedMs = at(detectedEntry) ?? toMs(incident.created_at);
  steps.push({
    key: "detected", title: "Détecté par le moteur", status: detectedMs !== null ? "done" : "pending", atMs: detectedMs,
    offsetS: offsetOf(detectedMs), durationS: span(detectedMs, at(decideEntry)),
    detail: "Webhook Alertmanager reçu : incident ouvert"
      + (correlated.length ? ` · corrélée : ${[...new Set(correlated)].join(", ")}` : names.length > 1 ? ` · alertes : ${names.join(", ")}` : ""),
  });

  // 3. Décision : nature de la réponse et action
  const decidedMs = at(decideEntry);
  steps.push({
    key: "decided", title: "Décision", status: decision ? "done" : "pending", atMs: decidedMs, offsetS: offsetOf(decidedMs),
    durationS: span(decidedMs, at(actingEntry ?? verifyingEntry)),
    detail: decision ? decisionLabel(decision) : "En attente de diagnostic", note: decision?.reason,
    nature: decision?.nature ?? incident.nature,
  });

  // 4. Action (ou absence d'action justifiée)
  const lastAction = actionEntries.at(-1);
  const actionFailed = actionEntries.some((e) => field(e, "result") !== "success") || (!!failedEntry && !verifyingEntry);
  const dedup = find(attempt, (e) => e.event === "dedup" || (e.event === "diagnostic" && !lastAction));
  let action: Step;
  if (decision?.kind === "act") {
    const actingMs = at(actingEntry);
    let detail = lastAction ? actionDetail(lastAction) : actionLabel(decision.action, decision.target ?? decision.service);
    if (!lastAction && dedup) detail = `Aucune action : ${String(field(dedup, "reason") ?? "déjà fait")}`;
    if (find(attempt, (e) => e.event === "restore:requested") && !lastAction) detail = "Restauration demandée au pont de l'hôte (resilience-pg-restore)";
    const health = findLast(attempt, (e) => e.event === "container:health");
    action = {
      key: "action", title: "Action", atMs: actingMs, offsetS: offsetOf(actingMs),
      durationS: span(actingMs, at(verifyingEntry) ?? at(lastAction)),
      status: actionFailed ? "failed" : verifyingEntry || recoveredEntry ? "done" : actingEntry ? "current" : "pending",
      detail: health ? `${detail} · conteneur ${field<string>(health, "status")}` : detail,
    };
  } else {
    const reason: Record<string, string> = {
      verify: "Aucune action : chaîne déjà saine, vérification directe",
      observe: "Aucune action : observation",
      escalate: "Aucune action automatique : escalade à l'opérateur",
      wait: "Attente du démarrage d'un maillon",
    };
    action = {
      key: "action", title: "Action", status: decision ? "skipped" : "pending", atMs: null, offsetS: null, durationS: null,
      detail: decision ? reason[decision.kind ?? ""] ?? "Aucune action" : "En attente de la décision",
    };
  }
  steps.push(action);

  // 5. Vérification : chaque contrôle, dans l'ordre prévu par la décision
  const planned = (field<string[]>(verifyingEntry, "checks") ?? decision?.checks ?? []) as string[];
  const running = isOpen && incident.state === "verifying";
  let firstPending = true;
  const checks: CheckItem[] = planned.map((key) => {
    const entry = findLast(attempt, (e) => e.event === `verification:${key}`);
    let status: CheckStatus;
    if (entry) {
      const result = field<string>(entry, "result");
      status = result === "ok" ? "ok" : result === "unavailable" ? "unavailable" : "failed";
    } else {
      status = running && firstPending ? "running" : "pending";
      firstPending = false;
    }
    return { key, label: CHECK_SHORT[key] ?? key, status, ms: entry ? field<number>(entry, "check_ms") ?? null : null, note: checkNote(key, entry) };
  });
  const verifyingMs = at(verifyingEntry);
  const verifyEnd = at(recoveredEntry && recoveredEntry.ts >= (verifyingEntry?.ts ?? 0) ? recoveredEntry : failedEntry);
  steps.push({
    key: "verification", title: "Vérification", atMs: verifyingMs, offsetS: offsetOf(verifyingMs), durationS: span(verifyingMs, verifyEnd),
    status: checks.some((c) => c.status === "failed") ? "failed" : verifyingEntry && recoveredEntry ? "done" : verifyingEntry ? "current" : action.status === "failed" ? "skipped" : "pending",
    detail: checks.length ? "" : "Contrôles de reprise",
    checks,
  });

  // 6. Issue : rétabli et vérifié, ou échec / escalade
  const closedNote = closedEntry ? `incident clos à la retombée des alertes (${clockTime(at(closedEntry))})` : undefined;
  if (escalatedEntry) {
    const message = incident.escalation?.message ?? field<string>(escalatedEntry, "explanation") ?? "intervention requise";
    steps.push({ key: "outcome", title: "Escaladé à l'opérateur", status: "failed", atMs: at(escalatedEntry), offsetS: offsetOf(at(escalatedEntry)), durationS: null, detail: message, note: closedNote });
  } else if (recoveredEntry && incident.state !== "failed") {
    const total = offsetOf(at(recoveredEntry));
    steps.push({
      key: "outcome", title: "Service rétabli", status: "done", atMs: at(recoveredEntry), offsetS: total, durationS: null,
      detail: `Rétabli et vérifié${incident.duration_s !== null ? ` ${duration(incident.duration_s)} après l'alerte reçue` : ""}${total !== null ? ` · ${duration(total)} depuis l'alerte` : ""}`,
      note: isOpen ? undefined : closedNote,
    });
  } else if (failedEntry && isOpen) {
    steps.push({ key: "outcome", title: "Tentative en échec", status: "failed", atMs: at(failedEntry), offsetS: offsetOf(at(failedEntry)), durationS: null, detail: `${String(field(failedEntry, "reason") ?? field(failedEntry, "error") ?? "échec")} · nouvelle tentative sous anti-boucle` });
  } else {
    steps.push({ key: "outcome", title: "Rétablissement", status: "pending", atMs: null, offsetS: null, durationS: null, detail: isOpen ? "En attente de la vérification" : `Issue : ${incident.outcome ?? "—"}` });
  }

  // Étape en cours : la première étape non terminée d'un incident ouvert
  if (isOpen && !["recovered", "escalated"].includes(incident.state) && !steps.some((s) => s.status === "current")) {
    const next = steps.find((s) => s.status === "pending");
    if (next) next.status = "current";
  }
  return steps;
}

// Cette méthode permet de résumer la nature et la décision d'un incident pour l'historique.
export function incidentHeadline(incident: { nature: string; decision: Decision | null; alertname: string }): string {
  return `${natureLabel(incident.decision?.nature ?? incident.nature)} · ${decisionLabel(incident.decision)}`;
}
