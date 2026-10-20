import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { HealthState } from "../lib/useServiceHealth";
import ServiceStatus, { StatusDot } from "./ServiceStatus";

describe("ServiceStatus", () => {
  it.each<[HealthState, string]>([
    ["checking", "Vérification…"],
    ["ok", "Tous les services opérationnels"],
    ["degraded", "Service dégradé"],
    ["down", "Service indisponible"],
  ])("annonce l'état « %s » : %s", (state, label) => {
    render(<ServiceStatus state={state} />);

    const status = screen.getByRole("status");
    expect(status).toHaveTextContent(label);
    expect(status).toHaveAttribute("data-state", state);
  });

  it("change de ton pendant l'incident puis revient au neutre", () => {
    const { rerender } = render(<ServiceStatus state="ok" />);
    expect(screen.getByRole("status")).not.toHaveClass("bg-amber-soft", "bg-brick-soft");

    rerender(<ServiceStatus state="degraded" />);
    expect(screen.getByRole("status")).toHaveClass("bg-amber-soft");

    rerender(<ServiceStatus state="down" />);
    expect(screen.getByRole("status")).toHaveClass("bg-brick-soft");

    rerender(<ServiceStatus state="ok" />);
    expect(screen.getByRole("status")).toHaveTextContent("Tous les services opérationnels");
    expect(screen.getByRole("status")).not.toHaveClass("bg-amber-soft", "bg-brick-soft");
  });
});

describe("StatusDot", () => {
  it.each([
    [null, "bg-faint"],
    [true, "bg-teal"],
    [false, "bg-amber"],
  ])("colore la pastille d'un service (%s → %s)", (ok, color) => {
    const { container } = render(<StatusDot ok={ok} />);
    expect(container.firstElementChild).toHaveClass(color);
  });
});
