import { vi } from "vitest";
import type { Account, Session, Transfer } from "../lib/api";

// Un appel intercepté : chemin (avec la chaîne de requête), méthode, en-têtes normalisés, corps JSON décodé
// ou formulaire multipart (captures de la caméra).
export type Call = {
  path: string;
  method: string;
  headers: Headers;
  body: unknown;
  form: FormData | null;
  signal: AbortSignal | null;
};
type Route = (call: Call) => Response | Promise<Response>;

// Cette méthode permet de fabriquer une réponse JSON, comme celles des API derrière le reverse proxy.
export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

// Réponse d'une API dont la base PostgreSQL est tombée (resilience_common.database).
export function databaseUnavailable(): Response {
  return json(503, {
    code: "database_unavailable",
    detail: "Service momentanément indisponible. Réessayez dans quelques instants.",
  });
}

// Cette méthode permet de simuler une coupure réseau (fetch rejette, comme le navigateur).
export function networkDown(): never {
  throw new TypeError("Failed to fetch");
}

// Cette méthode permet de remplacer fetch par un routeur en mémoire (« MÉTHODE /chemin » sans la chaîne de requête) ;
// une route absente répond 501 et reste listée dans `unmatched`, pour qu'aucun appel réseau ne passe inaperçu.
export function mockFetch(routes: Record<string, Route>) {
  const calls: Call[] = [];
  const unmatched: string[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const path = typeof input === "string" ? input : input instanceof URL ? input.pathname + input.search : input.url;
    const method = (init.method ?? "GET").toUpperCase();
    const body = typeof init.body === "string" ? JSON.parse(init.body) : null;
    const form = init.body instanceof FormData ? init.body : null;
    const call: Call = { path, method, headers: new Headers(init.headers), body, form, signal: init.signal ?? null };
    calls.push(call);
    const key = `${method} ${path.split("?")[0]}`;
    const route = routes[key];
    if (!route) {
      unmatched.push(key);
      return json(501, { code: "unmocked_route", detail: `Route non simulée : ${key}` });
    }
    return route(call);
  });
  vi.stubGlobal("fetch", fetchMock);
  return {
    fetch: fetchMock,
    calls,
    unmatched,
    // Cette méthode permet de ne garder que les appels vers une route donnée (« POST /api/payments/transfers »).
    callsTo(key: string): Call[] {
      return calls.filter((c) => `${c.method} ${c.path.split("?")[0]}` === key);
    },
  };
}

// Cette méthode permet de contrôler à la main le moment où une réponse arrive (requête « en vol »).
export function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

// Identifiants générés à chaque test : aucun secret ni jeton en dur dans le dépôt.
export function makeSession(overrides: Partial<Session> = {}): Session {
  return {
    token: crypto.randomUUID(),
    expiresAt: Date.now() + 3_600_000,
    user: { id: crypto.randomUUID(), email: "alice.martin@exemple.fr", full_name: "Alice Martin", role: "client" },
    ...overrides,
  };
}

export function makeAccount(overrides: Partial<Account> = {}): Account {
  return {
    account_number: "RA0123456789",
    owner_name: "Alice Martin",
    currency: "EUR",
    balance_cents: 123_456,
    created_at: "2026-10-01T08:00:00Z",
    ...overrides,
  };
}

export function makeTransfer(overrides: Partial<Transfer> = {}): Transfer {
  return {
    id: crypto.randomUUID(),
    amount_cents: 2_500,
    label: "Remboursement resto",
    status: "completed",
    direction: "debit",
    counterparty_account_number: "RA9876543210",
    counterparty_name: "Bob Durand",
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

// Les montants sont formatés en fr-FR avec des espaces insécables : on compare en espaces simples.
export function plain(text: string | null | undefined): string {
  return (text ?? "").replace(/\s+/g, " ").trim();
}
