import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GlobalStatus } from "../lib/types";
import StatusBanner from "./StatusBanner";

const NOW = new Date("2026-10-20T07:42:40.000Z");

// Cette méthode permet de construire un état global tel que le renvoie GET /api/overview.
function status(overrides: Partial<GlobalStatus>): GlobalStatus {
  return {
    phase: "operational", step_key: "operational", step: "Tous les parcours clients répondent · aucune alerte métier",
    since: null, duration_s: null, reaction_s: null, incident_id: null, alertname: null, service: null, nature: null,
    decision: null, escalated: false, open_incidents: 0, notes: [], ...overrides,
  };
}

describe("bandeau d'état global", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });
  afterEach(() => vi.useRealTimers());

  it("affiche Opérationnel sans chronomètre avant l'incident", () => {
    render(<StatusBanner status={status({})} />);
    const banner = screen.getByTestId("status-banner");
    expect(banner).toHaveAttribute("data-phase", "operational");
    expect(screen.getByRole("heading", { name: "Opérationnel" })).toBeInTheDocument();
    expect(screen.queryByTestId("status-elapsed")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Avancement de la reprise")).not.toBeInTheDocument();
  });

  it("affiche Incident en cours avec le chronomètre depuis la première anomalie, qui avance seul", () => {
    render(<StatusBanner status={status({
      phase: "incident", step_key: "anomaly", step: "Anomalie détectée par les sondes : payment-api en échec",
      since: "2026-10-20T07:42:03.000Z",
    })} />);
    expect(screen.getByRole("heading", { name: "Incident en cours" })).toBeInTheDocument();
    expect(screen.getByTestId("status-step")).toHaveTextContent("payment-api en échec");
    expect(screen.getByTestId("status-elapsed")).toHaveTextContent("00:37");
    act(() => vi.advanceTimersByTime(5000));
    expect(screen.getByTestId("status-elapsed")).toHaveTextContent("00:42");
    expect(screen.getByText("Anomalie")).toHaveAttribute("aria-current", "step");
  });

  it("affiche Remédiation en cours avec l'étape, la décision (nature et action) et l'incident", () => {
    render(<StatusBanner status={status({
      phase: "remediation", step_key: "verifying", step: "Vérification : transaction témoin",
      since: "2026-10-20T07:42:03.000Z", incident_id: "inc-20261020-074212-d07757", alertname: "ServiceDown",
      service: "payment-api", nature: "availability", decision: "Disponibilité · redémarrage de payment-api", open_incidents: 1,
    })} />);
    expect(screen.getByTestId("status-banner")).toHaveAttribute("data-phase", "remediation");
    expect(screen.getByRole("heading", { name: "Remédiation en cours" })).toBeInTheDocument();
    expect(screen.getByTestId("status-step")).toHaveTextContent("Vérification : transaction témoin");
    expect(screen.getByTestId("status-decision")).toHaveTextContent("Disponibilité · redémarrage de payment-api");
    expect(screen.getByText("inc-20261020-074212-d07757")).toBeInTheDocument();
    expect(screen.getByText("Vérification")).toHaveAttribute("aria-current", "step");
  });

  it("affiche Service rétabli avec la durée figée de bout en bout et le temps de réaction du moteur", () => {
    render(<StatusBanner status={status({
      phase: "restored", step_key: "closed", step: "Service rétabli et vérifié · incident clos",
      since: "2026-10-20T07:41:33.000Z", duration_s: 46.1, reaction_s: 6.7, alertname: "ServiceDown", service: "payment-api",
    })} />);
    expect(screen.getByRole("heading", { name: "Service rétabli" })).toBeInTheDocument();
    expect(screen.getByTestId("status-duration")).toHaveTextContent("46 s");
    expect(screen.getByTestId("status-reaction")).toHaveTextContent("Réaction du moteur : 6,7 s");
    expect(screen.queryByTestId("status-elapsed")).not.toBeInTheDocument();
    act(() => vi.advanceTimersByTime(10_000));
    expect(screen.getByTestId("status-duration")).toHaveTextContent("46 s");
  });

  it("signale l'escalade et les sources en défaut, et reste lisible sans données", () => {
    const { rerender } = render(<StatusBanner status={status({
      phase: "incident", step_key: "escalated", step: "Escaladé à l'opérateur : budget épuisé", escalated: true,
      since: "2026-10-20T07:40:40.000Z", notes: ["moteur de remédiation injoignable : la reprise n'est pas suivie"],
    })} />);
    expect(screen.getByText("ESCALADÉ")).toBeInTheDocument();
    expect(screen.getByTestId("status-elapsed")).toHaveTextContent("02:00");
    expect(screen.getByTestId("status-notes")).toHaveTextContent("moteur de remédiation injoignable");
    rerender(<StatusBanner status={null} />);
    expect(screen.getByTestId("status-banner")).toHaveAttribute("data-phase", "unknown");
    expect(screen.getByRole("heading", { name: "État inconnu" })).toBeInTheDocument();
  });
});
