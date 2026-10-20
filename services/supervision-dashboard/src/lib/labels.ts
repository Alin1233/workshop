// Libellés français des notions du moteur de remédiation (nature, action, contrôles, événements).
import type { Decision, EventItem } from "./types";

export const NATURE_LABELS: Record<string, string> = {
  availability: "Disponibilité",
  compromise: "Compromission",
  triage: "Tri ML",
  observe: "Observation",
  operator: "Opérateur",
  self: "Moteur",
};

export const CHECK_LABELS: Record<string, string> = {
  containers: "Conteneurs sains",
  waf_block: "Blocage effectif au WAF",
  integrity: "Intégrité du registre",
  probes: "Sondes de bout en bout",
  witness: "Transaction témoin",
};

// Libellés courts des contrôles, pour les pastilles de la chronologie (une seule ligne à l'écran)
export const CHECK_SHORT: Record<string, string> = {
  containers: "Conteneurs",
  waf_block: "Blocage WAF",
  integrity: "Intégrité",
  probes: "Sondes",
  witness: "Transaction témoin",
};

// Cette méthode permet de nommer l'action décidée (restart, block_ip, restore_db) avec sa cible.
export function actionLabel(action: string | undefined, target: string | undefined): string {
  switch (action) {
    case "restart":
      return `Redémarrage de ${target ?? "?"}`;
    case "start":
      return `Démarrage de ${target ?? "?"}`;
    case "block_ip":
      return `Blocage de ${target ?? "?"} au WAF`;
    case "restore_db":
      return "Restauration de la base (dernière sauvegarde saine)";
    default:
      return action ?? "Action";
  }
}

// Cette méthode permet d'écrire la décision en clair : ce qui sera fait (ou pourquoi rien ne le sera).
export function decisionLabel(decision: Decision | null | undefined): string {
  if (!decision) return "En cours d'analyse";
  switch (decision.kind) {
    case "act":
      return actionLabel(decision.action, decision.target ?? decision.service);
    case "verify":
      return "Vérification seule : la chaîne est déjà saine";
    case "wait":
      return "Attente : un maillon redémarre, nouveau diagnostic ensuite";
    case "observe":
      return "Observation avant toute action";
    case "escalate":
      return "Escalade à l'opérateur";
    default:
      return "En cours d'analyse";
  }
}

// Cette méthode permet de donner le libellé de la nature de la réponse (disponibilité ou compromission).
export function natureLabel(nature: string | null | undefined): string {
  return (nature && NATURE_LABELS[nature]) || "—";
}

// Cette méthode permet de décrire en une ligne un événement du fil (journaux Loki en liste blanche).
export function eventText(event: EventItem): { title: string; detail: string; tone: "ok" | "bad" | "warn" | "info" } {
  const target = event.target_service ?? event.target ?? "";
  const many = event.count > 1 ? ` ×${event.count}` : "";
  switch (event.event_type) {
    case "auth_failure":
      return { title: `Échec d'authentification${many}`, detail: `${event.service}${event.client_ip ? ` · depuis ${event.client_ip}` : ""}`, tone: "warn" };
    case "waf_remediation_block":
      return { title: `Requête refusée par le WAF (IP bloquée)${many}`, detail: `${event.client_ip ?? ""} ${event.method ?? ""} ${event.uri ?? ""}`.trim(), tone: "ok" };
    case "anomaly_detected":
      return { title: "Anomalie détectée par le modèle ML", detail: `${target} · ${event.dominant_feature ?? "?"} · score ${event.anomaly_score ?? "?"}`, tone: "bad" };
    case "anomaly_cleared":
      return { title: "Fin de l'anomalie ML", detail: target, tone: "ok" };
    case "integrity_violation":
      return { title: "Violation d'intégrité du registre", detail: event.service, tone: "bad" };
    case "dependency_failure":
      return { title: "Dépendance injoignable", detail: `${event.service} → base de données`, tone: "bad" };
    case "remediation_detected":
      return { title: "Incident ouvert par le moteur", detail: `${event.alertname ?? ""} · ${target}`, tone: "bad" };
    case "remediation_correlated":
      return { title: "Alerte corrélée à l'incident", detail: `${event.alertname ?? ""} · ${target}`, tone: "info" };
    case "remediation_decided":
      return { title: `Décision · ${natureLabel(event.nature)}`, detail: event.reason ?? target, tone: "info" };
    case "remediation_waiting":
      return { title: "Attente d'un maillon en démarrage", detail: event.reason ?? target, tone: "info" };
    case "remediation_observing":
      return { title: "Observation sans action", detail: event.reason ?? target, tone: "info" };
    case "remediation_action":
      return {
        title: `${actionLabel(event.action, event.target)} · ${event.result === "success" ? "succès" : event.result ?? "?"}`,
        detail: event.incident_id ?? "",
        tone: event.result === "success" ? "ok" : "bad",
      };
    case "remediation_action_failed":
      return { title: "Action en échec", detail: event.error ?? target, tone: "bad" };
    case "remediation_restore_requested":
      return { title: "Restauration demandée au pont de l'hôte", detail: target, tone: "info" };
    case "remediation_restore_result":
      return { title: "Résultat de la restauration", detail: event.result ?? event.outcome ?? "", tone: event.result === "failure" ? "bad" : "ok" };
    case "remediation_verification":
      return {
        title: `Contrôle · ${CHECK_LABELS[event.check ?? ""] ?? event.check ?? "?"} · ${event.result === "ok" ? "OK" : event.result ?? "?"}`,
        detail: `${event.alertname ?? ""} · ${target}`,
        tone: event.result === "ok" ? "ok" : event.result === "unavailable" ? "warn" : "bad",
      };
    case "remediation_recovered":
      return { title: "Service rétabli et vérifié", detail: `${target}${event.duration_s !== undefined ? ` · ${String(event.duration_s).replace(".", ",")} s après l'alerte reçue` : ""}`, tone: "ok" };
    case "remediation_escalated":
      return { title: "Escaladé à l'opérateur", detail: event.explanation ?? event.reason ?? target, tone: "bad" };
    case "remediation_closed":
      return { title: "Incident clos (alertes retombées)", detail: `${event.alertname ?? ""} · ${event.outcome ?? ""}`, tone: "ok" };
    case "remediation_alert_resolved":
      return { title: "Alerte retombée", detail: `${event.alertname ?? ""} · ${target}`, tone: "ok" };
    case "remediation_unblocked":
      return { title: "IP débloquée (fin du TTL)", detail: event.ip ?? "", tone: "info" };
    case "remediation_waf_block":
      return { title: "Liste de blocage du WAF mise à jour", detail: event.ip ?? event.client_ip ?? "", tone: "info" };
    case "remediation_webhook_rejected":
      return { title: "Webhook refusé (jeton invalide)", detail: event.client_ip ?? "", tone: "bad" };
    default:
      return { title: event.event_type.replace(/_/g, " "), detail: event.reason ?? target ?? "", tone: "info" };
  }
}
