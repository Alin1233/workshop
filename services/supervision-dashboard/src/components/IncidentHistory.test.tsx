import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { IncidentSummary } from "../lib/types";
import { serviceDownIncident } from "../test/fixtures";
import IncidentHistory from "./IncidentHistory";

// Cette méthode permet de résumer un incident réel comme le fait GET /api/incidents du back-for-front.
function summary(overrides: Partial<IncidentSummary>): IncidentSummary {
  const { timeline: _timeline, actions: _actions, alerts: _alerts, ...rest } = serviceDownIncident;
  return { ...rest, follow_up_of: null, ...overrides };
}

describe("historique des incidents", () => {
  it("indique la réponse, l'issue et la durée, et signale l'incident rattaché à la même panne", () => {
    const primary = summary({});
    const follow = summary({
      id: "inc-20261020-074220-95b2c1", alertname: "AnomalyDetected", last_action: null, duration_s: 0.5,
      decision: { kind: "verify", nature: "availability" }, follow_up_of: primary.id,
    });
    render(<IncidentHistory incidents={[follow, primary]} focusId={primary.id} />);
    expect(screen.getByText("payment-api · Démarrage de payment-api")).toBeInTheDocument();
    expect(screen.getByText("payment-api · rattaché à ServiceDown : déjà traité, vérifié seulement")).toBeInTheDocument();
    expect(screen.getAllByText("rétabli")).toHaveLength(2);
    expect(screen.getByText("6,7 s")).toBeInTheDocument();
  });
});
