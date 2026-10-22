import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { ServiceHealth } from "../lib/useServiceHealth";
import IncidentBanner from "./IncidentBanner";

const OK: ServiceHealth = { state: "ok", auth: true, payments: true };
const PAYMENTS_DOWN: ServiceHealth = { state: "degraded", auth: true, payments: false };
const AUTH_DOWN: ServiceHealth = { state: "degraded", auth: false, payments: true };
const ALL_DOWN: ServiceHealth = { state: "down", auth: false, payments: false };
const LAST_UPDATE = new Date(2026, 9, 20, 14, 5);

describe("IncidentBanner", () => {
  it.each<ServiceHealth>([OK, { state: "checking", auth: null, payments: null }])("ne montre rien hors incident (%o)", (health) => {
    const { container } = render(<IncidentBanner health={health} lastUpdated={LAST_UPDATE} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("explique une panne des paiements et rassure sur le renvoi d'un virement", () => {
    render(<IncidentBanner health={PAYMENTS_DOWN} lastUpdated={LAST_UPDATE} />);

    const banner = screen.getByRole("alert");
    expect(banner).toHaveTextContent("Les paiements sont perturbés");
    expect(banner).toHaveTextContent(
      "Solde affiché à jour de 14:05. Vous pouvez renvoyer un virement : il ne sera jamais débité deux fois.",
    );
    expect(banner).toHaveClass("bg-amber-soft");
  });

  it("n'invente pas d'heure de mise à jour tant que le solde n'a jamais été chargé", () => {
    render(<IncidentBanner health={PAYMENTS_DOWN} lastUpdated={null} />);

    const text = screen.getByText(/Vous pouvez renvoyer un virement/);
    expect(text.textContent).toBe("Vous pouvez renvoyer un virement : il ne sera jamais débité deux fois.");
  });

  it("explique une panne de l'authentification : la session en cours reste active", () => {
    render(<IncidentBanner health={AUTH_DOWN} lastUpdated={LAST_UPDATE} />);

    const banner = screen.getByRole("alert");
    expect(banner).toHaveTextContent("La connexion est perturbée");
    expect(banner).toHaveTextContent("Votre session reste active : seules les nouvelles connexions sont touchées.");
  });

  it("signale une indisponibilité totale en rouge", () => {
    render(<IncidentBanner health={ALL_DOWN} lastUpdated={LAST_UPDATE} />);

    const banner = screen.getByRole("alert");
    expect(banner).toHaveTextContent("Services momentanément indisponibles");
    expect(banner).toHaveTextContent(
      "Nos équipes rétablissent le service. Solde affiché à jour de 14:05. Aucun virement ne sera débité deux fois.",
    );
    expect(banner).toHaveClass("bg-brick-soft");
  });

  it("liste l'état de chaque service", () => {
    render(<IncidentBanner health={PAYMENTS_DOWN} lastUpdated={null} />);

    const banner = screen.getByTestId("incident-banner");
    expect(banner).toHaveTextContent("Authentification");
    expect(banner).toHaveTextContent("Paiements");
  });

  it("disparaît au retour à la normale", () => {
    const { rerender } = render(<IncidentBanner health={ALL_DOWN} lastUpdated={LAST_UPDATE} />);
    rerender(<IncidentBanner health={PAYMENTS_DOWN} lastUpdated={LAST_UPDATE} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Les paiements sont perturbés");

    rerender(<IncidentBanner health={OK} lastUpdated={LAST_UPDATE} />);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
