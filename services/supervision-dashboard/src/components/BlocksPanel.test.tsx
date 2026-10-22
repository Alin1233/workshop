import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ClockOffset } from "../lib/poll";
import type { BlocksResponse } from "../lib/types";
import BlocksPanel from "./BlocksPanel";

const NOW = new Date("2026-10-20T09:05:52.561Z");

// Cette méthode permet de construire la réponse de GET /api/blocks pour une IP bloquée par la remédiation (TTL 90 s).
function blocked(expiresInS: number): BlocksResponse {
  return {
    server_time: NOW.toISOString(), sources: { engine: { ok: true, error: null, age_s: 0.1, latency_ms: 3 } },
    blocks: [{
      ip: "172.25.0.3", expires_at: new Date(NOW.getTime() + expiresInS * 1000).toISOString(), remaining_s: expiresInS,
      ttl_s: 90, blocked_at: NOW.toISOString(), reason: "AuthBruteForce (compromise)", incident_id: "inc-20261020-090552-34f895",
    }],
    waf_blocklist: true,
    bridge: { configured: true, available: true, runner: "systemd", heartbeat_age_s: 2, busy: false },
  };
}

describe("compte à rebours des blocages d'IP", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });
  afterEach(() => vi.useRealTimers());

  it("décompte chaque seconde jusqu'à la levée automatique", () => {
    render(<BlocksPanel data={blocked(90)} />);
    expect(screen.getByText("172.25.0.3")).toBeInTheDocument();
    expect(screen.getByTestId("block-ttl")).toHaveTextContent("01:30");
    act(() => vi.advanceTimersByTime(1000));
    expect(screen.getByTestId("block-ttl")).toHaveTextContent("01:29");
    act(() => vi.advanceTimersByTime(29_000));
    expect(screen.getByTestId("block-ttl")).toHaveTextContent("01:00");
    act(() => vi.advanceTimersByTime(61_000));
    expect(screen.getByTestId("block-ttl")).toHaveTextContent("levée…");
    expect(screen.getByText(/TTL 90 s/)).toBeInTheDocument();
  });

  it("suit l'horloge du serveur, pas celle du navigateur", () => {
    render(
      <ClockOffset.Provider value={20_000}>
        <BlocksPanel data={blocked(90)} />
      </ClockOffset.Provider>,
    );
    expect(screen.getByTestId("block-ttl")).toHaveTextContent("01:10");
  });

  it("affiche l'absence de blocage et l'état du pont", () => {
    render(<BlocksPanel data={{ ...blocked(90), blocks: [], bridge: { configured: true, available: false, runner: "dev" } }} />);
    expect(screen.getByText("✓ Aucune IP bloquée")).toBeInTheDocument();
    expect(screen.getByText("runner absent")).toBeInTheDocument();
    expect(screen.getByText("chargée")).toBeInTheDocument();
  });
});
