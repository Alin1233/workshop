import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { loadSession, saveSession } from "./lib/api";
import { databaseUnavailable, json, makeAccount, makeSession, mockFetch, plain } from "./test/http";

// État simulé de la plateforme : l'API de paiement (et sa base) peut tomber puis revenir.
let paymentsUp = true;
let tokenAccepted = true;

function installPlatform() {
  const payments = (body: () => Response) => () =>
    !tokenAccepted ? json(401, { detail: "Jeton invalide ou expiré" }) : paymentsUp ? body() : databaseUnavailable();
  return mockFetch({
    "GET /api/auth/health": () => json(200, { status: "ok" }),
    "GET /api/payments/health": () => (paymentsUp ? json(200, { status: "ok" }) : databaseUnavailable()),
    "POST /api/auth/login": ({ body }) =>
      json(200, {
        access_token: crypto.randomUUID(),
        expires_in: 900,
        user: { id: crypto.randomUUID(), email: (body as { email: string }).email, full_name: "Alice Martin", role: "client" },
      }),
    "GET /api/payments/accounts/me": payments(() => json(200, makeAccount({ balance_cents: 123_456 }))),
    "GET /api/payments/transfers": payments(() => json(200, [])),
    "GET /api/auth/mfa": () => json(200, { enabled: false, required: false, recovery_codes_remaining: 0 }),
  });
}

// Cette méthode permet d'avancer l'horloge simulée en laissant arriver les réponses, dans act().
async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

const status = () => screen.getByTestId("service-status");

beforeEach(() => {
  paymentsUp = true;
  tokenAccepted = true;
});

describe("App : session", () => {
  it("connecte le client, mémorise la session de l'onglet et affiche son espace", async () => {
    installPlatform();
    const user = userEvent.setup();
    render(<App />);

    await user.type(screen.getByLabelText(/^Email/), "alice@exemple.fr");
    await user.type(screen.getByLabelText(/^Mot de passe/), crypto.randomUUID());
    await user.click(screen.getByRole("button", { name: "Se connecter" }));

    expect(await screen.findByRole("button", { name: "Déconnexion" })).toBeInTheDocument();
    expect(screen.getByText("AM")).toHaveAttribute("title", "Alice Martin");
    expect(plain((await screen.findByTestId("balance")).textContent)).toBe("1 234,56 €");
    expect(loadSession()?.user.email).toBe("alice@exemple.fr");
  });

  it("reprend une session encore valide, mais pas une session expirée", () => {
    installPlatform();
    saveSession(makeSession());
    const { unmount } = render(<App />);
    expect(screen.getByRole("button", { name: "Déconnexion" })).toBeInTheDocument();
    unmount();

    saveSession(makeSession({ expiresAt: Date.now() - 1 }));
    render(<App />);
    expect(screen.getByRole("button", { name: "Se connecter" })).toBeInTheDocument();
  });

  it("efface la session à la déconnexion", async () => {
    installPlatform();
    saveSession(makeSession());
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Déconnexion" }));

    expect(screen.getByRole("button", { name: "Se connecter" })).toBeInTheDocument();
    expect(loadSession()).toBeNull();
  });

  it("revient à l'écran de connexion quand l'API refuse le jeton (401)", async () => {
    installPlatform();
    tokenAccepted = false;
    saveSession(makeSession());
    render(<App />);

    expect(await screen.findByRole("button", { name: "Se connecter" })).toBeInTheDocument();
    expect(loadSession()).toBeNull();
  });
});

describe("App : paramètres du compte", () => {
  it("ouvre la section Sécurité avec la double authentification, puis revient aux comptes", async () => {
    installPlatform();
    saveSession(makeSession());
    const user = userEvent.setup();
    render(<App />);
    expect(screen.queryByTestId("mfa-settings")).not.toBeInTheDocument(); // plus sur le tableau de bord

    await user.click(screen.getByRole("button", { name: "Paramètres" }));

    expect(screen.getByRole("heading", { name: "Paramètres du compte" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Sécurité" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Activer" })).toBeInTheDocument();
    expect(screen.queryByTestId("balance")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "← Retour à mes comptes" }));
    expect(await screen.findByTestId("balance")).toBeInTheDocument();
  });

  it("repart du tableau de bord après une déconnexion depuis les paramètres", async () => {
    installPlatform();
    saveSession(makeSession());
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Paramètres" }));
    await user.click(screen.getByRole("button", { name: "Déconnexion" }));
    await user.type(screen.getByLabelText(/^Email/), "alice@exemple.fr");
    await user.type(screen.getByLabelText(/^Mot de passe/), crypto.randomUUID());
    await user.click(screen.getByRole("button", { name: "Se connecter" }));

    expect(await screen.findByTestId("balance")).toBeInTheDocument();
  });
});

describe("App : incident sur les paiements", () => {
  it("passe d'opérationnel à dégradé puis revient seul à la normale", async () => {
    vi.useFakeTimers();
    installPlatform();
    saveSession(makeSession());
    render(<App />);
    expect(status()).toHaveAttribute("data-state", "checking");

    await advance(0);
    expect(status()).toHaveAttribute("data-state", "ok");
    expect(status()).toHaveTextContent("Tous les services opérationnels");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(plain(screen.getByTestId("balance").textContent)).toBe("1 234,56 €");

    // PostgreSQL de l'API de paiement coupé : /health et les routes métier en 503 database_unavailable.
    paymentsUp = false;
    await advance(5_000);
    await advance(0);
    expect(status()).toHaveAttribute("data-state", "degraded");
    expect(status()).toHaveTextContent("Service dégradé");
    const alerts = screen.getAllByRole("alert");
    expect(alerts).toHaveLength(1); // le bandeau seul, pas de message d'erreur en doublon
    expect(alerts[0]).toHaveTextContent("Les paiements sont perturbés");
    expect(alerts[0]).toHaveTextContent(/Solde affiché à jour de \d{2}:\d{2}\./);
    expect(plain(screen.getByTestId("balance").textContent)).toBe("1 234,56 €"); // dernier solde connu conservé

    paymentsUp = true;
    await advance(5_000);
    await advance(0);
    expect(status()).toHaveAttribute("data-state", "ok");
    expect(status()).toHaveTextContent("Tous les services opérationnels");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument(); // ni bandeau, ni erreur périmée
  });

  it("recharge solde et historique dès le retour à la normale : l'erreur de la panne ne reste pas affichée", async () => {
    vi.useFakeTimers();
    const http = installPlatform();
    const reloads = () => http.callsTo("GET /api/payments/accounts/me").length;
    saveSession(makeSession());
    render(<App />);
    await advance(0);
    expect(reloads()).toBe(1);

    // Panne qui couvre un rechargement (t = 10 s) : il échoue, le bandeau explique la panne.
    paymentsUp = false;
    await advance(10_000);
    expect(reloads()).toBe(2);
    expect(screen.getAllByRole("alert")).toHaveLength(1);

    // Base revenue : le sondage de t = 15 s voit « ok » et relance aussitôt le rechargement, sans attendre t = 20 s.
    paymentsUp = true;
    await advance(5_000);
    await advance(0);
    expect(status()).toHaveAttribute("data-state", "ok");
    expect(reloads()).toBe(3);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("App : cadence de rechargement", () => {
  it("recharge solde et historique toutes les 10 s, indépendamment du sondage /health (5 s)", async () => {
    vi.useFakeTimers();
    const http = installPlatform();
    saveSession(makeSession());
    render(<App />);
    await advance(0);

    for (let i = 0; i < 4; i++) await advance(5_000);

    expect(http.callsTo("GET /api/auth/health")).toHaveLength(5); // t = 0, 5, 10, 15, 20 s
    expect(http.callsTo("GET /api/payments/accounts/me")).toHaveLength(3); // t = 0, 10, 20 s
    expect(http.callsTo("GET /api/payments/transfers")).toHaveLength(3);
  });
});
