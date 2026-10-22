import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { databaseUnavailable, deferred, json, mockFetch, networkDown } from "../test/http";
import { useServiceHealth } from "./useServiceHealth";

// État simulé des deux /health derrière le reverse proxy.
let up = { auth: true, payments: true };

function installHealthRoutes() {
  return mockFetch({
    "GET /api/auth/health": () => (up.auth ? json(200, { status: "ok" }) : databaseUnavailable()),
    "GET /api/payments/health": () => (up.payments ? json(200, { status: "ok" }) : databaseUnavailable()),
  });
}

// Cette méthode permet d'avancer l'horloge simulée en laissant les réponses de fetch arriver, dans act().
async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  up = { auth: true, payments: true };
});

describe("useServiceHealth", () => {
  it("part de « checking » puis interroge les deux services dès le montage", async () => {
    const http = installHealthRoutes();
    const { result } = renderHook(() => useServiceHealth());

    expect(result.current).toEqual({ state: "checking", auth: null, payments: null });
    await advance(0);

    expect(result.current).toEqual({ state: "ok", auth: true, payments: true });
    expect(http.calls.map((c) => c.path).sort()).toEqual(["/api/auth/health", "/api/payments/health"]);
  });

  it("sonde toutes les 5 secondes", async () => {
    const http = installHealthRoutes();
    renderHook(() => useServiceHealth());
    await advance(0);
    expect(http.calls).toHaveLength(2);

    await advance(4_999);
    expect(http.calls).toHaveLength(2);
    await advance(1);
    expect(http.calls).toHaveLength(4);
    await advance(10_000);
    expect(http.calls).toHaveLength(8);
  });

  it("passe en « degraded » quand l'API de paiement répond 503 database_unavailable", async () => {
    installHealthRoutes();
    up.payments = false;
    const { result } = renderHook(() => useServiceHealth());
    await advance(0);

    expect(result.current).toEqual({ state: "degraded", auth: true, payments: false });
  });

  it("passe en « degraded » quand seule l'authentification est coupée", async () => {
    mockFetch({ "GET /api/auth/health": networkDown, "GET /api/payments/health": () => json(200, { status: "ok" }) });
    const { result } = renderHook(() => useServiceHealth());
    await advance(0);

    expect(result.current).toEqual({ state: "degraded", auth: false, payments: true });
  });

  it("passe en « down » quand les deux services tombent (PostgreSQL arrêté : deux /health en 503)", async () => {
    installHealthRoutes();
    up = { auth: false, payments: false };
    const { result } = renderHook(() => useServiceHealth());
    await advance(0);

    expect(result.current).toEqual({ state: "down", auth: false, payments: false });
  });

  it("suit un incident complet : opérationnel → dégradé → indisponible → retour à la normale", async () => {
    installHealthRoutes();
    const { result } = renderHook(() => useServiceHealth());
    await advance(0);
    expect(result.current.state).toBe("ok");

    up.payments = false;
    await advance(5_000);
    expect(result.current).toEqual({ state: "degraded", auth: true, payments: false });

    up.auth = false;
    await advance(5_000);
    expect(result.current.state).toBe("down");

    up = { auth: true, payments: true };
    await advance(5_000);
    expect(result.current).toEqual({ state: "ok", auth: true, payments: true });
  });

  it("ignore une réponse lente arrivée après une plus récente (pas de retour à un état périmé)", async () => {
    // Premier sondage bloqué (jusqu'au délai de 8 s), le suivant répond tout de suite.
    const slow = { auth: deferred<Response>(), payments: deferred<Response>() };
    const seen = { auth: 0, payments: 0 };
    mockFetch({
      "GET /api/auth/health": () => (seen.auth++ === 0 ? slow.auth.promise : json(200, { status: "ok" })),
      "GET /api/payments/health": () => (seen.payments++ === 0 ? slow.payments.promise : json(200, { status: "ok" })),
    });
    const { result } = renderHook(() => useServiceHealth());
    await advance(5_000);
    expect(result.current.state).toBe("ok");

    await act(async () => {
      slow.auth.resolve(databaseUnavailable());
      slow.payments.resolve(databaseUnavailable());
    });

    expect(result.current).toEqual({ state: "ok", auth: true, payments: true });
  });

  it("suit quand même l'état si chaque réponse arrive après le sondage suivant (service qui ne répond plus)", async () => {
    // Chaque /health ne répond qu'au bout de 8 s (délai du client), alors qu'un sondage part toutes les 5 s.
    const late = () => new Promise<Response>((resolve) => setTimeout(() => resolve(databaseUnavailable()), 8_000));
    mockFetch({ "GET /api/auth/health": late, "GET /api/payments/health": late });
    const { result } = renderHook(() => useServiceHealth());

    await advance(8_000);

    expect(result.current).toEqual({ state: "down", auth: false, payments: false });
  });

  it("arrête de sonder une fois démonté", async () => {
    const http = installHealthRoutes();
    const { unmount } = renderHook(() => useServiceHealth());
    await advance(0);

    unmount();
    await advance(30_000);

    expect(http.calls).toHaveLength(2);
    expect(vi.getTimerCount()).toBe(0);
  });
});
