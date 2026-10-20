import { render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import type { SourceStatus } from "./lib/types";

const TIME = "2026-10-20T07:42:18.700Z";
const OK: SourceStatus = { ok: true, error: null, age_s: 0.2, latency_ms: 4 };
const DOWN: SourceStatus = { ok: false, error: "injoignable", age_s: 0.1, latency_ms: 1 };
const COMPONENTS = ["waf", "frontend", "auth-service", "payment-api", "postgres", "observability", "anomaly-detector", "remediation-engine", "restore-bridge"];

// Cette méthode permet de produire les réponses du back-for-front, avec les sources indiquées en panne (forme réelle :
// enveloppe server_time + sources, données vides quand la source manque).
function responses(down: string[]) {
  const s = (name: string) => (down.includes(name) ? DOWN : OK);
  const promDown = down.includes("prometheus");
  const engineDown = down.includes("engine");
  return {
    "/api/overview": {
      server_time: TIME, sources: { prometheus: s("prometheus"), alertmanager: s("alertmanager"), engine: s("engine") },
      status: {
        phase: promDown && engineDown ? "unknown" : "operational", step_key: "operational",
        step: promDown && engineDown ? "Sources de supervision indisponibles" : "Tous les parcours clients répondent · aucune alerte métier",
        since: null, duration_s: null, reaction_s: null, incident_id: null, alertname: null, service: null, nature: null,
        decision: null, escalated: false, open_incidents: 0, notes: engineDown ? ["moteur de remédiation injoignable : la reprise n'est pas suivie"] : [],
      },
      components: COMPONENTS.map((id) => ({
        id, label: id, role: "rôle", state: promDown ? (id === "remediation-engine" && engineDown ? "down" : "unknown") : "ok",
        reason: promDown ? "Prometheus indisponible : état inconnu" : "répond",
      })),
      integrity: { ok: promDown ? null : true, last_check_age_s: promDown ? null : 4 },
      anomaly: { threshold: promDown ? null : 0.8, scores: [] },
    },
    "/api/alerts": { server_time: TIME, sources: { alertmanager: s("alertmanager"), prometheus: s("prometheus") }, alerts: [] },
    "/api/incidents/current": { server_time: TIME, sources: { engine: s("engine") }, incident: null },
    "/api/blocks": { server_time: TIME, sources: { engine: s("engine") }, blocks: [], waf_blocklist: engineDown ? null : true, bridge: null },
    "/api/events": { server_time: TIME, sources: { loki: s("loki") }, events: [] },
    "/api/incidents": { server_time: TIME, sources: { engine: s("engine") }, incidents: [] },
  } as Record<string, unknown>;
}

// Cette méthode permet de simuler fetch vers le back-for-front (aucun appel réseau) avec les réponses données.
function serve(bodies: Record<string, unknown>) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input).split("?")[0];
    return { ok: true, status: 200, json: async () => bodies[path] } as Response;
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("écran de supervision quand des sources tombent", () => {
  it("garde tous les panneaux lisibles et signale chaque source indisponible quand tout est arrêté", async () => {
    const fetchMock = serve(responses(["prometheus", "alertmanager", "loki", "engine"]));
    render(<App intervalMs={60_000} />);
    await waitFor(() => expect(screen.getByTestId("status-banner")).toHaveAttribute("data-phase", "unknown"));
    expect(screen.getByRole("heading", { name: "État inconnu" })).toBeInTheDocument();
    expect(screen.getByTestId("status-step")).toHaveTextContent("Sources de supervision indisponibles");
    for (const panel of ["components", "timeline", "alerts", "blocks", "events", "history"]) {
      await waitFor(() => expect(within(screen.getByTestId(`panel-${panel}`)).getByTestId("source-notice")).toHaveTextContent("Source indisponible"));
    }
    expect(within(screen.getByTestId("panel-events")).getByTestId("source-notice")).toHaveTextContent("Loki : injoignable");
    expect(screen.getByTestId("component-remediation-engine")).toHaveAttribute("data-state", "down");
    expect(screen.getByTestId("component-waf")).toHaveAttribute("data-state", "unknown");
    // Jamais « aucun incident » ou « aucune IP bloquée » quand la source qui le dirait est en panne
    expect(screen.getAllByTestId("unavailable").map((el) => el.textContent)).toEqual([
      "Chronologie indisponible : la source ne répond pas", "Liste des alertes indisponible : la source ne répond pas",
      "État des blocages indisponible : la source ne répond pas", "Fil d'événements indisponible : la source ne répond pas",
      "Historique indisponible : la source ne répond pas",
    ]);
    expect(screen.queryByText(/Aucun/)).not.toBeInTheDocument();
    expect(screen.getByTestId("live-indicator")).toHaveAttribute("data-state", "live");
    const paths = fetchMock.mock.calls.map(([url]) => String(url));
    expect(paths).toEqual(expect.arrayContaining(["/api/overview", "/api/alerts", "/api/incidents/current", "/api/blocks", "/api/events?limit=30", "/api/incidents?limit=8"]));
  });

  it("n'affiche l'avertissement que dans le panneau dont la source est en panne", async () => {
    serve(responses(["loki"]));
    render(<App intervalMs={60_000} />);
    await waitFor(() => expect(screen.getByTestId("status-banner")).toHaveAttribute("data-phase", "operational"));
    await waitFor(() => expect(within(screen.getByTestId("panel-events")).getByTestId("source-notice")).toBeInTheDocument());
    expect(screen.getAllByTestId("source-notice")).toHaveLength(1);
    expect(screen.getByText("✓ Aucune alerte active")).toBeInTheDocument();
    expect(screen.getByTestId("component-payment-api")).toHaveAttribute("data-state", "ok");
  });

  it("ne plante pas quand le back-for-front lui-même ne répond plus", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("Failed to fetch"); }));
    render(<App intervalMs={60_000} />);
    await waitFor(() => expect(screen.getByTestId("live-indicator")).toHaveAttribute("data-state", "offline"));
    expect(screen.getByText("SUPERVISION INJOIGNABLE")).toBeInTheDocument();
    expect(screen.getByTestId("status-banner")).toHaveAttribute("data-phase", "unknown");
    expect(screen.getAllByTestId("source-notice").length).toBeGreaterThanOrEqual(6);
    expect(screen.getAllByText(/supervision injoignable/).length).toBeGreaterThanOrEqual(6);
    expect(screen.getAllByTestId("unavailable")).toHaveLength(5);
    expect(screen.queryByText(/Aucun/)).not.toBeInTheDocument();
  });
});
