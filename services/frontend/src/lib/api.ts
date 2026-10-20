// Client HTTP des services Resilience-Alpha, appelés via le reverse proxy (/api/auth, /api/payments).

export type User = { id: string; email: string; full_name: string; role: "client" | "admin" };
export type Session = { token: string; expiresAt: number; user: User };
// Second facteur accepté : code (appli ou secours), ou visage s'il est enregistré.
export type MfaMethod = "totp" | "face";
// Connexion suspendue en attente du second facteur (jeton opaque de 5 minutes, jamais stocké).
export type MfaChallenge = { mfaToken: string; methods: MfaMethod[] };
export type MfaStatus = { enabled: boolean; required: boolean; recovery_codes_remaining: number; face_enrolled: boolean };
// Défi de pose de la reconnaissance faciale : une capture par pose, dans l'ordre (de face, puis les deux profils).
export type FacePose = "center" | "left" | "right";
export type FaceChallenge = { challenge_id: string; poses: FacePose[]; expires_in: number };
export type FaceStatus = { enrolled: boolean; enrolled_at: string | null; consented_at: string | null };
export type RejectedCapture = {
  id: string;
  email: string;
  captured_at: string;
  reason: string;
  score: number | null;
  client_ip: string | null;
};
export type MfaSetup = { secret: string; otpauth_uri: string; qr_code: string };
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

// Cette méthode permet d'appeler l'API (JSON, ou multipart pour les captures de la caméra) et de convertir toute erreur
// (HTTP ou réseau) en ApiError lisible ; le navigateur fixe lui-même l'en-tête d'un envoi multipart (frontière).
async function request<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(init.headers);
  if (!(init.body instanceof FormData)) headers.set("Content-Type", "application/json");
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

type TokenResponse = { access_token: string; expires_in: number; user: User };

// Cette méthode permet de convertir la réponse d'émission de jeton de l'auth-service en session du front.
function toSession(res: TokenResponse): Session {
  return { token: res.access_token, expiresAt: Date.now() + res.expires_in * 1000, user: res.user };
}

export const api = {
  // Cette méthode permet d'ouvrir une session à partir d'un email et d'un mot de passe ; si la double authentification
  // est active, renvoie à la place le jeton d'étape à présenter avec le code (verifyMfa).
  async login(email: string, password: string): Promise<Session | MfaChallenge> {
    const res = await request<TokenResponse | { mfa_required: true; mfa_token: string; methods?: MfaMethod[] }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    return "mfa_token" in res ? { mfaToken: res.mfa_token, methods: res.methods ?? ["totp"] } : toSession(res);
  },

  // Cette méthode permet de terminer une connexion avec double authentification (code TOTP ou code de secours).
  async verifyMfa(mfaToken: string, code: string): Promise<Session> {
    return toSession(
      await request<TokenResponse>("/api/auth/login/mfa", { method: "POST", body: JSON.stringify({ mfa_token: mfaToken, code }) }),
    );
  },

  // Cette méthode permet de demander le défi de pose d'une connexion qui se termine par reconnaissance faciale.
  faceLoginChallenge(mfaToken: string): Promise<FaceChallenge> {
    return request("/api/auth/login/mfa/face/challenge", { method: "POST", body: JSON.stringify({ mfa_token: mfaToken }) });
  },

  // Cette méthode permet de terminer une connexion avec les captures du défi de pose (une par pose, dans l'ordre).
  async verifyFace(mfaToken: string, challengeId: string, frames: Blob[]): Promise<Session> {
    const form = framesForm(frames, { mfa_token: mfaToken, challenge_id: challengeId });
    return toSession(await request<TokenResponse>("/api/auth/login/mfa/face", { method: "POST", body: form }));
  },

  // Cette méthode permet de savoir si un visage est enregistré, et depuis quand.
  faceStatus(token: string): Promise<FaceStatus> {
    return request("/api/auth/mfa/face", {}, token);
  },

  // Cette méthode permet d'ouvrir l'enregistrement (ou le remplacement) d'un visage : le consentement et le code sont
  // vérifiés d'emblée, le défi de pose renvoyé accepte ensuite quelques essais.
  faceEnrollChallenge(token: string, code: string): Promise<FaceChallenge> {
    return request("/api/auth/mfa/face/challenge", { method: "POST", body: JSON.stringify({ code, consent: true }) }, token);
  },

  // Cette méthode permet d'enregistrer le visage avec les captures du défi ouvert par faceEnrollChallenge.
  faceEnroll(token: string, challengeId: string, frames: Blob[]): Promise<FaceStatus> {
    const form = framesForm(frames, { challenge_id: challengeId });
    return request("/api/auth/mfa/face", { method: "POST", body: form }, token);
  },

  // Cette méthode permet de supprimer le visage enregistré (son empreinte).
  async faceRemove(token: string): Promise<void> {
    await request("/api/auth/mfa/face", { method: "DELETE" }, token);
  },

  // Cette méthode permet à l'admin de lister les captures refusées à la connexion (conservées 7 jours).
  rejectedCaptures(token: string): Promise<RejectedCapture[]> {
    return request("/api/auth/admin/face-captures", {}, token);
  },

  // Cette méthode permet à l'admin d'afficher une capture refusée (consultation tracée par l'auth-service).
  rejectedCapture(token: string, id: string): Promise<RejectedCapture & { image: string }> {
    return request(`/api/auth/admin/face-captures/${encodeURIComponent(id)}`, {}, token);
  },

  // Cette méthode permet de connaître l'état de la double authentification du compte connecté.
  mfaStatus(token: string): Promise<MfaStatus> {
    return request("/api/auth/mfa", {}, token);
  },

  // Cette méthode permet d'obtenir un nouveau secret TOTP et son QR code, en attente de confirmation.
  mfaSetup(token: string): Promise<MfaSetup> {
    return request("/api/auth/mfa/setup", { method: "POST" }, token);
  },

  // Cette méthode permet d'activer la double authentification avec un premier code ; renvoie les codes de secours.
  async mfaActivate(token: string, code: string): Promise<string[]> {
    const res = await request<{ recovery_codes: string[] }>("/api/auth/mfa/activate", { method: "POST", body: JSON.stringify({ code }) }, token);
    return res.recovery_codes;
  },

  // Cette méthode permet de désactiver la double authentification après confirmation du mot de passe et d'un code.
  async mfaDisable(token: string, password: string, code: string): Promise<void> {
    await request("/api/auth/mfa/disable", { method: "POST", body: JSON.stringify({ password, code }) }, token);
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

// Cette méthode permet de préparer un envoi multipart : champs texte, puis les captures JPEG sous le nom « frames ».
function framesForm(frames: Blob[], fields: Record<string, string>): FormData {
  const form = new FormData();
  for (const [name, value] of Object.entries(fields)) form.append(name, value);
  frames.forEach((frame, i) => form.append("frames", frame, `pose-${i + 1}.jpg`));
  return form;
}

const euroFormat = new Intl.NumberFormat("fr-FR", { style: "currency", currency: "EUR" });

// Cette méthode permet d'afficher un montant en centimes au format monétaire français.
export function formatCents(cents: number): string {
  return euroFormat.format(cents / 100);
}

// Cette méthode permet de séparer un montant en partie entière et en centimes, pour les afficher avec deux graisses.
export function splitCents(cents: number): { units: string; decimals: string } {
  const formatted = formatCents(cents);
  const match = /^(.*?)(,\d{2}\s€)$/u.exec(formatted);
  return match ? { units: match[1], decimals: match[2] } : { units: formatted, decimals: "" };
}

// Cette méthode permet d'afficher un numéro de compte par groupes de 4 (« RA 0123 4567 89 ») pour le lire sans erreur.
export function formatAccountNumber(accountNumber: string): string {
  const match = /^([A-Z]{2})(\d{4})(\d{4})(\d+)$/.exec(accountNumber);
  return match ? match.slice(1).join(" ") : accountNumber;
}

// Cette méthode permet de totaliser les entrées et sorties du mois en cours parmi les mouvements chargés.
export function monthTotals(transfers: Transfer[], now = new Date()): { creditCents: number; debitCents: number } {
  let creditCents = 0;
  let debitCents = 0;
  for (const t of transfers) {
    const date = new Date(t.created_at);
    if (date.getFullYear() !== now.getFullYear() || date.getMonth() !== now.getMonth()) continue;
    if (t.direction === "credit") creditCents += t.amount_cents;
    else debitCents += t.amount_cents;
  }
  return { creditCents, debitCents };
}

const dayFormat = new Intl.DateTimeFormat("fr-FR", { weekday: "long", day: "numeric", month: "long" });

// Cette méthode permet de regrouper les mouvements (déjà triés du plus récent au plus ancien) par jour,
// avec un intitulé « Aujourd'hui », « Hier » ou la date en toutes lettres.
export function groupTransfersByDay(transfers: Transfer[], now = new Date()): { label: string; items: Transfer[] }[] {
  const groups: { key: string; label: string; items: Transfer[] }[] = [];
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  for (const t of transfers) {
    const date = new Date(t.created_at);
    const key = date.toDateString();
    let group = groups.at(-1);
    if (group?.key !== key) {
      const label =
        key === now.toDateString() ? "Aujourd'hui" : key === yesterday.toDateString() ? "Hier" : dayFormat.format(date);
      group = { key, label, items: [] };
      groups.push(group);
    }
    group.items.push(t);
  }
  return groups.map(({ label, items }) => ({ label, items }));
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
