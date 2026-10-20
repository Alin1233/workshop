import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { buildSteps } from "../lib/timeline";
import type { GlobalStatus, IncidentDetail } from "../lib/types";
import { bruteForceIncident, restoreIncident, serviceDownIncident } from "../test/fixtures";
import IncidentTimeline from "./IncidentTimeline";

// Cette méthode permet de rejouer l'incident réel à un instant donné : chronologie coupée après l'événement voulu.
function inProgress(incident: IncidentDetail, lastEvent: string, state: string): IncidentDetail {
  const index = incident.timeline.findIndex((e) => e.event === lastEvent);
  return { ...incident, open: true, state, closed_at: null, recovered_at: null, duration_s: null, outcome: null, timeline: incident.timeline.slice(0, index + 1) };
}

describe("chronologie construite depuis un incident réel du moteur", () => {
  it("raconte l'arrêt de payment-api : alerte → détection → décision → redémarrage → contrôles → rétabli", () => {
    const steps = buildSteps(serviceDownIncident);
    expect(steps.map((s) => [s.key, s.status])).toEqual([
      ["alert", "done"], ["detected", "done"], ["decided", "done"], ["action", "done"], ["verification", "done"], ["outcome", "done"],
    ]);
    const [alert, detected, decided, action, verification, outcome] = steps;
    expect(alert.detail).toBe("ServiceDown · règle Prometheus · payment-api");
    expect(detected.detail).toBe("Webhook Alertmanager reçu : incident ouvert · corrélée : EndToEndProbeFailed");
    expect(detected.offsetS).toBeCloseTo(8.74, 1);
    expect(decided.detail).toBe("Redémarrage de payment-api");
    expect(decided.nature).toBe("availability");
    expect(decided.note).toBe("payment-api est exited : redémarrage de payment-api");
    expect(action.detail).toBe("Démarrage de payment-api — réussi · conteneur healthy");
    expect(action.durationS).toBeCloseTo(6.19, 1);
    expect(verification.checks?.map((c) => [c.key, c.status, c.note])).toEqual([
      ["containers", "ok", "2/2"], ["probes", "ok", "3/3"], ["witness", "ok", "virement 1,00 € via le WAF"],
    ]);
    expect(outcome.title).toBe("Service rétabli");
    expect(outcome.detail).toBe("Rétabli et vérifié 6,7 s après l'alerte reçue · 15 s depuis l'alerte");
    expect(outcome.note).toMatch(/^incident clos à la retombée des alertes/);
  });

  it("affiche la nature compromission et la restauration par le pont, avec le contrôle d'intégrité", () => {
    const [, , decided, action, verification] = buildSteps(restoreIncident);
    expect(decided.nature).toBe("compromise");
    expect(decided.detail).toBe("Restauration de la base (dernière sauvegarde saine)");
    expect(action.detail).toBe("Restauration de la base (dernière sauvegarde saine) — réussi · sauvegarde de 1 min 58 s · 10 s");
    expect(verification.checks?.map((c) => c.key)).toEqual(["containers", "integrity", "probes", "witness"]);
    expect(verification.checks?.[1].note).toBe("HTTP 200");
  });

  it("affiche le blocage d'IP au WAF avec son TTL et la vérification du blocage effectif", () => {
    const [alert, , decided, action, verification] = buildSteps(bruteForceIncident);
    expect(alert.detail).toBe("AuthBruteForce · règle SOC (Loki) · auth-service");
    expect(decided.detail).toBe("Blocage de 172.25.0.3 au WAF");
    expect(action.detail).toBe("Blocage de 172.25.0.3 au WAF — réussi · levée automatique dans 1 min 30 s");
    expect(verification.checks?.[0]).toMatchObject({ key: "waf_block", status: "ok", note: "172.25.0.3 refusée" });
  });

  it("montre l'étape en cours pendant la vérification (contrôle suivant en cours, puis à venir)", () => {
    const live = inProgress(serviceDownIncident, "verification:containers", "verifying");
    const steps = buildSteps(live);
    expect(steps.find((s) => s.key === "verification")?.status).toBe("current");
    expect(steps.find((s) => s.key === "verification")?.checks?.map((c) => c.status)).toEqual(["ok", "running", "pending"]);
    expect(steps.find((s) => s.key === "outcome")?.status).toBe("pending");
    const acting = buildSteps(inProgress(serviceDownIncident, "state:acting", "acting"));
    expect(acting.find((s) => s.key === "action")?.status).toBe("current");
    expect(acting.find((s) => s.key === "action")?.detail).toBe("Redémarrage de payment-api");
  });

  it("rend la chronologie complète à l'écran, horodatée et datée par rapport à l'alerte", () => {
    render(<IncidentTimeline incident={serviceDownIncident} status={null} />);
    expect(screen.getByText(/Dernier incident · clos/)).toBeInTheDocument();
    const steps = screen.getByTestId("timeline-steps");
    expect(within(steps).getAllByRole("listitem").filter((li) => li.dataset.testid?.startsWith("step-"))).toHaveLength(6);
    expect(screen.getByTestId("step-decided")).toHaveTextContent("Disponibilité");
    expect(screen.getByTestId("step-decided")).toHaveTextContent("Redémarrage de payment-api");
    expect(screen.getByTestId("step-outcome")).toHaveTextContent("T+15 s");
    expect(screen.getByTestId("check-witness")).toHaveAttribute("data-status", "ok");
    expect(screen.getByTestId("check-witness")).toHaveTextContent("Transaction témoin");
  });

  it("annonce un incident que le moteur n'a pas encore reçu, sans afficher l'ancien", () => {
    const status: GlobalStatus = {
      phase: "incident", step_key: "anomaly", step: "Anomalie détectée par les sondes : payment-api en échec",
      since: "2026-10-20T07:42:03.000Z", duration_s: null, reaction_s: null, incident_id: null, alertname: null, service: null,
      nature: null, decision: null, escalated: false, open_incidents: 0, notes: [],
    };
    render(<IncidentTimeline incident={serviceDownIncident} status={status} />);
    expect(screen.getByText(/en attente de sa prise en charge/)).toBeInTheDocument();
    expect(screen.getByTestId("step-alert")).toHaveAttribute("data-status", "current");
    expect(screen.getByTestId("step-alert")).toHaveTextContent("payment-api en échec");
    expect(screen.queryByText(/Dernier incident/)).not.toBeInTheDocument();
    expect(screen.queryByTestId("step-decided")).toHaveTextContent("Disponibilité (redémarrage) ou compromission");
  });

  it("affiche un état vide explicite sans incident", () => {
    render(<IncidentTimeline incident={null} status={null} />);
    expect(screen.getByText("Aucun incident enregistré par le moteur")).toBeInTheDocument();
  });
});
