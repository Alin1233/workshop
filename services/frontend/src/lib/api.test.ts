import { afterEach, describe, expect, it, vi } from "vitest";
import { databaseUnavailable, json, makeTransfer, mockFetch, networkDown } from "../test/http";
import {
  api,
  ApiError,
  formatAccountNumber,
  formatCents,
  groupTransfersByDay,
  loadSession,
  monthTotals,
  newIdempotencyKey,
  parseEuros,
  saveSession,
  splitCents,
} from "./api";

// Cette méthode permet de récupérer l'erreur levée par un appel d'API (et d'échouer si l'appel réussit).
async function apiError(promise: Promise<unknown>): Promise<ApiError> {
  const err = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(ApiError);
  return err as ApiError;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("api.transfer", () => {
  it("envoie la clé d'idempotence, le jeton et le virement en JSON", async () => {
    const token = crypto.randomUUID();
    const key = newIdempotencyKey();
    const created = makeTransfer({ amount_cents: 1250 });
    const http = mockFetch({ "POST /api/payments/transfers": () => json(201, created) });

    await expect(api.transfer(token, key, "RA0123456789", 1250, "Resto")).resolves.toEqual(created);

    const [call] = http.calls;
    expect(http.calls).toHaveLength(1);
    expect(call.method).toBe("POST");
    expect(call.headers.get("Idempotency-Key")).toBe(key);
    expect(call.headers.get("Authorization")).toBe(`Bearer ${token}`);
    expect(call.headers.get("Content-Type")).toBe("application/json");
    expect(call.body).toEqual({ to_account_number: "RA0123456789", amount_cents: 1250, label: "Resto" });
  });

  it("renvoie la même clé à chaque nouvel essai d'un même virement", async () => {
    const token = crypto.randomUUID();
    const key = newIdempotencyKey();
    let attempts = 0;
    const http = mockFetch({
      "POST /api/payments/transfers": () => (++attempts === 1 ? databaseUnavailable() : json(201, makeTransfer())),
    });

    await apiError(api.transfer(token, key, "RA0123456789", 1250, ""));
    await api.transfer(token, key, "RA0123456789", 1250, "");

    expect(http.calls.map((c) => c.headers.get("Idempotency-Key"))).toEqual([key, key]);
  });

  it("traduit une base indisponible (503 database_unavailable) en erreur réessayable, avec le message du service", async () => {
    mockFetch({ "POST /api/payments/transfers": databaseUnavailable });

    const err = await apiError(api.transfer(crypto.randomUUID(), newIdempotencyKey(), "RA0123456789", 1250, ""));

    expect(err).toMatchObject({ status: 503, code: "database_unavailable" });
    expect(err.message).toBe("Service momentanément indisponible. Réessayez dans quelques instants.");
  });

  it("remonte les erreurs métier { code, detail } de l'API de paiement", async () => {
    mockFetch({ "POST /api/payments/transfers": () => json(422, { code: "insufficient_funds", detail: "Solde insuffisant" }) });

    const err = await apiError(api.transfer(crypto.randomUUID(), newIdempotencyKey(), "RA0123456789", 999_999, ""));

    expect(err).toMatchObject({ status: 422, code: "insufficient_funds", message: "Solde insuffisant" });
  });
});

describe("request : erreurs", () => {
  it.each([
    [401, "Session expirée, reconnectez-vous."],
    [403, "Accès refusé."],
    [422, "Données saisies invalides."],
    [429, "Trop de requêtes, patientez un instant."],
    [500, "Le service rencontre un incident. Réessayez dans quelques instants."],
    [502, "Le service rencontre un incident. Réessayez dans quelques instants."],
    [418, "Erreur inattendue (418)."],
  ])("donne un message lisible pour un %i sans détail exploitable", async (status, message) => {
    // Corps non JSON (page d'erreur nginx) : le statut suffit à choisir le message.
    mockFetch({ "GET /api/payments/accounts/me": () => new Response("<html>erreur</html>", { status }) });

    const err = await apiError(api.account(crypto.randomUUID()));

    expect(err).toMatchObject({ status, code: `http_${status}`, message });
  });

  it("ignore un detail non textuel (liste d'erreurs FastAPI en 422)", async () => {
    mockFetch({
      "POST /api/auth/register": () => json(422, { detail: [{ loc: ["body", "email"], msg: "value is not a valid email" }] }),
    });

    const err = await apiError(api.register("alice@exemple.fr", "Alice Martin", crypto.randomUUID()));

    expect(err).toMatchObject({ status: 422, code: "http_422", message: "Données saisies invalides." });
  });

  it("convertit une coupure réseau ou un délai dépassé en erreur network_error (statut 0)", async () => {
    mockFetch({ "GET /api/payments/accounts/me": networkDown });
    expect(await apiError(api.account(crypto.randomUUID()))).toMatchObject({
      status: 0,
      code: "network_error",
      message: "Service injoignable. Réessayez dans quelques instants.",
    });

    mockFetch({
      "GET /api/payments/accounts/me": () => {
        throw new DOMException("signal timed out", "TimeoutError");
      },
    });
    expect(await apiError(api.account(crypto.randomUUID()))).toMatchObject({ status: 0, code: "network_error" });
  });

  it("borne chaque appel par un délai (signal d'abandon)", async () => {
    const http = mockFetch({ "GET /api/payments/transfers": () => json(200, []) });

    await api.transfers(crypto.randomUUID());

    expect(http.calls[0].signal).toBeInstanceOf(AbortSignal);
    expect(http.calls[0].signal?.aborted).toBe(false);
  });
});

describe("authentification", () => {
  it("ouvre une session à partir de la réponse de login, sans jeton dans la requête", async () => {
    vi.useFakeTimers({ now: new Date("2026-10-20T10:00:00Z") });
    const password = crypto.randomUUID();
    const token = crypto.randomUUID();
    const user = { id: crypto.randomUUID(), email: "alice@exemple.fr", full_name: "Alice Martin", role: "client" as const };
    const http = mockFetch({ "POST /api/auth/login": () => json(200, { access_token: token, expires_in: 900, user }) });

    const session = await api.login("alice@exemple.fr", password);

    expect(session).toEqual({ token, expiresAt: Date.parse("2026-10-20T10:15:00Z"), user });
    expect(http.calls[0].body).toEqual({ email: "alice@exemple.fr", password });
    expect(http.calls[0].headers.has("Authorization")).toBe(false);
  });

  it("remonte un refus de connexion avec le message de l'auth-service", async () => {
    mockFetch({ "POST /api/auth/login": () => json(401, { detail: "Identifiants invalides" }) });

    const err = await apiError(api.login("alice@exemple.fr", crypto.randomUUID()));

    expect(err).toMatchObject({ status: 401, code: "http_401", message: "Identifiants invalides" });
  });

  it("inscrit un client avec full_name", async () => {
    const password = crypto.randomUUID();
    const http = mockFetch({ "POST /api/auth/register": () => json(201, { id: crypto.randomUUID() }) });

    await api.register("alice@exemple.fr", "Alice Martin", password);

    expect(http.calls[0].body).toEqual({ email: "alice@exemple.fr", full_name: "Alice Martin", password });
  });

  it("présente le jeton porteur sur les routes du compte", async () => {
    const token = crypto.randomUUID();
    const http = mockFetch({
      "GET /api/payments/accounts/me": () => json(200, {}),
      "GET /api/payments/transfers": () => json(200, []),
    });

    await api.account(token);
    await api.transfers(token);

    expect(http.calls.map((c) => [c.path, c.headers.get("Authorization")])).toEqual([
      ["/api/payments/accounts/me", `Bearer ${token}`],
      ["/api/payments/transfers?limit=20", `Bearer ${token}`],
    ]);
  });
});

describe("session de l'onglet", () => {
  it("se mémorise, se relit puis s'efface", () => {
    const session = { token: crypto.randomUUID(), expiresAt: Date.now() + 60_000, user: { id: "u1", email: "a@exemple.fr", full_name: "A B", role: "client" as const } };

    saveSession(session);
    expect(loadSession()).toEqual(session);

    saveSession(null);
    expect(loadSession()).toBeNull();
    expect(sessionStorage.length).toBe(0);
  });

  it("n'est plus rendue une fois le jeton expiré", () => {
    saveSession({ token: crypto.randomUUID(), expiresAt: Date.now() - 1, user: { id: "u1", email: "a@exemple.fr", full_name: "A B", role: "client" } });

    expect(loadSession()).toBeNull();
  });
});

describe("api.health", () => {
  it("vaut true sur 200, false sur 503 (base indisponible) ou coupure réseau", async () => {
    mockFetch({ "GET /api/auth/health": () => json(200, { status: "ok" }), "GET /api/payments/health": databaseUnavailable });
    expect(await api.health("auth")).toBe(true);
    expect(await api.health("payments")).toBe(false);

    mockFetch({ "GET /api/auth/health": networkDown });
    expect(await api.health("auth")).toBe(false);
  });
});

describe("clé d'idempotence", () => {
  it("est nouvelle à chaque virement", () => {
    const keys = new Set(Array.from({ length: 50 }, newIdempotencyKey));
    expect(keys.size).toBe(50);
  });

  it("reste conforme à l'API (8 à 64 caractères) hors contexte sécurisé, sans crypto.randomUUID", () => {
    // En HTTP sur l'IP du PC Hôte, le navigateur n'expose que crypto.getRandomValues.
    const real = globalThis.crypto;
    vi.stubGlobal("crypto", { getRandomValues: real.getRandomValues.bind(real) });

    const a = newIdempotencyKey();
    const b = newIdempotencyKey();

    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });
});

describe("montants et formats", () => {
  it("convertit une saisie en centimes (null si invalide ou nulle)", () => {
    expect(parseEuros("12,50")).toBe(1250);
    expect(parseEuros("0,29")).toBe(29); // pas d'erreur d'arrondi flottant
    expect(parseEuros("1 234,5")).toBe(123_450);
    expect(parseEuros("0")).toBeNull();
    expect(parseEuros("12,345")).toBeNull();
  });

  it("formate en euros à la française et sépare les centimes pour le solde", () => {
    expect(formatCents(123_456).replace(/\s/g, " ")).toBe("1 234,56 €");
    const split = splitCents(123_456);
    expect(split.units.replace(/\s/g, " ")).toBe("1 234");
    expect(split.decimals.replace(/\s/g, " ")).toBe(",56 €");
  });

  it("affiche le numéro de compte par groupes de 4", () => {
    expect(formatAccountNumber("RA0123456789")).toBe("RA 0123 4567 89");
    expect(formatAccountNumber("inconnu")).toBe("inconnu");
  });

  it("totalise les entrées et sorties du mois en cours seulement", () => {
    const now = new Date(2026, 9, 20, 12);
    const transfers = [
      makeTransfer({ direction: "credit", amount_cents: 10_000, created_at: new Date(2026, 9, 1, 9).toISOString() }),
      makeTransfer({ direction: "debit", amount_cents: 2_500, created_at: new Date(2026, 9, 19, 9).toISOString() }),
      makeTransfer({ direction: "debit", amount_cents: 99_999, created_at: new Date(2026, 8, 30, 23).toISOString() }),
    ];

    expect(monthTotals(transfers, now)).toEqual({ creditCents: 10_000, debitCents: 2_500 });
  });

  it("regroupe l'historique par jour : Aujourd'hui, Hier, puis la date", () => {
    const now = new Date(2026, 9, 20, 12);
    const at = (day: number, hour: number) => makeTransfer({ created_at: new Date(2026, 9, day, hour).toISOString() });
    const transfers = [at(20, 11), at(20, 9), at(19, 18), at(16, 10)];

    const groups = groupTransfersByDay(transfers, now);

    expect(groups.map((g) => [g.label, g.items.length])).toEqual([
      ["Aujourd'hui", 2],
      ["Hier", 1],
      ["vendredi 16 octobre", 1],
    ]);
  });
});
