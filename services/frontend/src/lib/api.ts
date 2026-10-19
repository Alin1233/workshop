// Client HTTP des services Resilience-Alpha, appelés via le reverse proxy (/api/auth, /api/payments).

export type User = { id: string; email: string; full_name: string; role: "client" | "admin" };
export type Session = { token: string; expiresAt: number; user: User };
export type Account = { account_number: string; owner_name: string; currency: string; balance_cents: number; created_at: string };
export type Transfer = {
  id: string;
  amount_cents: number;
  label: string;
  status: string;
  direction: "debit" | "credit";
  counterparty_account_number: string;
  counterparty_name: string;
  created_at: string;
};

export class ApiError extends Error {
  status: number;
  code: string;

  // Cette méthode permet de porter le statut HTTP et le code métier d'une réponse en échec.
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const SESSION_KEY = "ra.session";

// Cette méthode permet de relire la session stockée lorsque le jeton n'est pas encore expiré.
export function loadSession(): Session | null {
  const raw = sessionStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  const session = JSON.parse(raw) as Session;
  return session.expiresAt > Date.now() ? session : null;
}

// Cette méthode permet de mémoriser (ou effacer, si null) la session pour l'onglet courant.
export function saveSession(session: Session | null): void {
  if (session) sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
  else sessionStorage.removeItem(SESSION_KEY);
}

// Cette méthode permet d'appeler l'API en JSON et de convertir toute erreur (HTTP ou réseau) en ApiError lisible.
async function request<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let response: Response;
  try {
    response = await fetch(path, { ...init, headers, signal: AbortSignal.timeout(8000) });
  } catch {
    throw new ApiError(0, "network_error", "Service injoignable. Réessayez dans quelques instants.");
  }
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = typeof body?.detail === "string" ? body.detail : messageForStatus(response.status);
    throw new ApiError(response.status, body?.code ?? `http_${response.status}`, detail);
  }
  return body as T;
}

// Cette méthode permet de traduire un statut HTTP sans message métier en texte compréhensible.
function messageForStatus(status: number): string {
  if (status === 401) return "Session expirée, reconnectez-vous.";
  if (status === 403) return "Accès refusé.";
  if (status === 422) return "Données saisies invalides.";
  if (status === 429) return "Trop de requêtes, patientez un instant.";
  if (status >= 500) return "Le service rencontre un incident. Réessayez dans quelques instants.";
  return `Erreur inattendue (${status}).`;
}

export const api = {
  // Cette méthode permet d'ouvrir une session à partir d'un email et d'un mot de passe.
  async login(email: string, password: string): Promise<Session> {
    const res = await request<{ access_token: string; expires_in: number; user: User }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    return { token: res.access_token, expiresAt: Date.now() + res.expires_in * 1000, user: res.user };
  },

  // Cette méthode permet de créer un compte client.
  register(email: string, fullName: string, password: string): Promise<User> {
    return request("/api/auth/register", { method: "POST", body: JSON.stringify({ email, full_name: fullName, password }) });
  },

  // Cette méthode permet de récupérer le compte de paiement de l'utilisateur connecté.
  account(token: string): Promise<Account> {
    return request("/api/payments/accounts/me", {}, token);
  },

  // Cette méthode permet de récupérer l'historique des virements de l'utilisateur connecté.
  transfers(token: string): Promise<Transfer[]> {
    return request("/api/payments/transfers?limit=20", {}, token);
  },

  // Cette méthode permet d'émettre un virement ; la même clé d'idempotence doit être renvoyée en cas de nouvel essai.
  transfer(token: string, idempotencyKey: string, toAccount: string, amountCents: number, label: string): Promise<Transfer> {
    return request(
      "/api/payments/transfers",
      {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
        body: JSON.stringify({ to_account_number: toAccount, amount_cents: amountCents, label }),
      },
      token,
    );
  },

  // Cette méthode permet de connaître l'état de santé d'un service (true si opérationnel).
  async health(service: "auth" | "payments"): Promise<boolean> {
    try {
      await request(`/api/${service}/health`);
      return true;
    } catch {
      return false;
    }
  },
};

const euroFormat = new Intl.NumberFormat("fr-FR", { style: "currency", currency: "EUR" });

// Cette méthode permet d'afficher un montant en centimes au format monétaire français.
export function formatCents(cents: number): string {
  return euroFormat.format(cents / 100);
}

// Cette méthode permet de convertir une saisie utilisateur (« 12,50 » ou « 12.5 ») en centimes, ou null si invalide.
export function parseEuros(input: string): number | null {
  const normalized = input.trim().replace(/\s/g, "").replace(",", ".");
  if (!/^\d+(\.\d{1,2})?$/.test(normalized)) return null;
  const cents = Math.round(Number(normalized) * 100);
  return cents > 0 ? cents : null;
}

// Cette méthode permet de générer une clé d'idempotence aléatoire, y compris hors contexte sécurisé
// (accès en HTTP via l'IP du PC Hôte, où crypto.randomUUID n'est pas disponible).
export function newIdempotencyKey(): string {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
