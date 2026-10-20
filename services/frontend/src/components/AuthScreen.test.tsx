import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { ServiceHealth } from "../lib/useServiceHealth";
import { deferred, json, mockFetch, networkDown } from "../test/http";
import AuthScreen from "./AuthScreen";

const LOGIN = "POST /api/auth/login";
const REGISTER = "POST /api/auth/register";
const HEALTHY: ServiceHealth = { state: "ok", auth: true, payments: true };

// Cette méthode permet de fabriquer la réponse de login de l'auth-service, avec un jeton généré.
function loginResponse(email = "alice@exemple.fr") {
  return json(200, {
    access_token: crypto.randomUUID(),
    expires_in: 900,
    user: { id: crypto.randomUUID(), email, full_name: "Alice Martin", role: "client" },
  });
}

function setup(health: ServiceHealth = HEALTHY) {
  const onLogin = vi.fn();
  render(<AuthScreen onLogin={onLogin} health={health} />);
  return { user: userEvent.setup(), onLogin, password: crypto.randomUUID() };
}

const emailInput = () => screen.getByLabelText(/^Email/);
const passwordInput = () => screen.getByLabelText(/^Mot de passe/);
const fullNameInput = () => screen.getByLabelText(/^Nom complet/);

describe("AuthScreen : connexion", () => {
  it("ouvre la session et la transmet", async () => {
    const http = mockFetch({ [LOGIN]: () => loginResponse() });
    const { user, onLogin, password } = setup();

    await user.type(emailInput(), "  alice@exemple.fr ");
    await user.type(passwordInput(), password);
    await user.click(screen.getByRole("button", { name: "Se connecter" }));

    await vi.waitFor(() => expect(onLogin).toHaveBeenCalledTimes(1));
    expect(http.calls[0].body).toEqual({ email: "alice@exemple.fr", password });
    expect(onLogin.mock.calls[0][0]).toMatchObject({ user: { email: "alice@exemple.fr" } });
    expect(onLogin.mock.calls[0][0].token).toEqual(expect.any(String));
  });

  it("exige email et mot de passe avant tout appel", async () => {
    const http = mockFetch({ [LOGIN]: () => loginResponse() });
    const { user } = setup();

    await user.click(screen.getByRole("button", { name: "Se connecter" }));

    expect(screen.getByText("Email requis.")).toBeInTheDocument();
    expect(screen.getByText("Mot de passe requis.")).toBeInTheDocument();
    expect(emailInput()).toHaveAttribute("aria-invalid", "true");
    expect(http.calls).toHaveLength(0);

    await user.type(emailInput(), "a");
    expect(screen.queryByText("Email requis.")).not.toBeInTheDocument();
    expect(screen.getByText("Mot de passe requis.")).toBeInTheDocument();
  });

  it("affiche le refus de l'auth-service et laisse réessayer", async () => {
    mockFetch({ [LOGIN]: () => json(401, { detail: "Identifiants invalides" }) });
    const { user, onLogin, password } = setup();

    await user.type(emailInput(), "alice@exemple.fr");
    await user.type(passwordInput(), password);
    await user.click(screen.getByRole("button", { name: "Se connecter" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Identifiants invalides");
    expect(screen.getByRole("button", { name: "Se connecter" })).toBeEnabled();
    expect(onLogin).not.toHaveBeenCalled();
  });

  it("signale un service injoignable", async () => {
    mockFetch({ [LOGIN]: networkDown });
    const { user, password } = setup();

    await user.type(emailInput(), "alice@exemple.fr");
    await user.type(passwordInput(), password);
    await user.click(screen.getByRole("button", { name: "Se connecter" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Service injoignable. Réessayez dans quelques instants.");
  });

  it("désactive le bouton pendant la requête (pas de double connexion)", async () => {
    const pending = deferred<Response>();
    const http = mockFetch({ [LOGIN]: () => pending.promise });
    const { user, onLogin, password } = setup();
    await user.type(emailInput(), "alice@exemple.fr");
    await user.type(passwordInput(), password);

    await user.click(screen.getByRole("button", { name: "Se connecter" }));
    const busy = screen.getByRole("button", { name: "Patientez…" });
    expect(busy).toBeDisabled();
    await user.click(busy);

    expect(http.calls).toHaveLength(1);
    await act(async () => pending.resolve(loginResponse()));
    expect(onLogin).toHaveBeenCalledTimes(1);
  });
});

describe("AuthScreen : création de compte", () => {
  it("inscrit le client puis le connecte dans la foulée", async () => {
    const http = mockFetch({ [REGISTER]: () => json(201, { id: crypto.randomUUID() }), [LOGIN]: () => loginResponse() });
    const { user, onLogin, password } = setup();
    await user.click(screen.getByRole("tab", { name: "Créer un compte" }));

    await user.type(fullNameInput(), " Alice Martin ");
    await user.type(emailInput(), "alice@exemple.fr");
    await user.type(passwordInput(), password);
    await user.click(screen.getByRole("button", { name: "Créer mon compte" }));

    await vi.waitFor(() => expect(onLogin).toHaveBeenCalledTimes(1));
    expect(http.calls.map((c) => `${c.method} ${c.path}`)).toEqual([REGISTER, LOGIN]);
    expect(http.calls[0].body).toEqual({ email: "alice@exemple.fr", full_name: "Alice Martin", password });
    expect(http.calls[1].body).toEqual({ email: "alice@exemple.fr", password });
  });

  it("applique les règles d'inscription (nom, email, mot de passe de 10 caractères)", async () => {
    const http = mockFetch({ [REGISTER]: () => json(201, {}), [LOGIN]: () => loginResponse() });
    const { user, password } = setup();
    await user.click(screen.getByRole("tab", { name: "Créer un compte" }));
    expect(screen.getByRole("tab", { name: "Créer un compte" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("10 caractères minimum.")).toBeInTheDocument(); // aide affichée avant toute erreur

    await user.type(fullNameInput(), "A");
    await user.type(emailInput(), "alice@exemple");
    await user.type(passwordInput(), password.slice(0, 9));
    await user.click(screen.getByRole("button", { name: "Créer mon compte" }));

    expect(screen.getByText("Nom complet : 2 caractères minimum.")).toBeInTheDocument();
    expect(screen.getByText("Adresse email invalide.")).toBeInTheDocument();
    expect(passwordInput()).toHaveAttribute("aria-invalid", "true");
    expect(http.calls).toHaveLength(0);
  });

  it("n'essaie pas de se connecter si l'inscription est refusée", async () => {
    const http = mockFetch({ [REGISTER]: () => json(409, { detail: "Un compte existe déjà avec cet email" }), [LOGIN]: () => loginResponse() });
    const { user, onLogin, password } = setup();
    await user.click(screen.getByRole("tab", { name: "Créer un compte" }));
    await user.type(fullNameInput(), "Alice Martin");
    await user.type(emailInput(), "alice@exemple.fr");
    await user.type(passwordInput(), password);

    await user.click(screen.getByRole("button", { name: "Créer mon compte" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Un compte existe déjà avec cet email");
    expect(http.callsTo(LOGIN)).toHaveLength(0);
    expect(onLogin).not.toHaveBeenCalled();
  });

  it("efface erreurs et messages en changeant d'onglet", async () => {
    mockFetch({});
    const { user } = setup();
    await user.click(screen.getByRole("button", { name: "Se connecter" }));
    expect(screen.getByText("Email requis.")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Créer un compte" }));
    expect(screen.queryByText("Email requis.")).not.toBeInTheDocument();
    expect(fullNameInput()).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Connexion" }));
    expect(screen.queryByLabelText(/^Nom complet/)).not.toBeInTheDocument();
  });
});

describe("AuthScreen : état des services avant connexion", () => {
  it.each<[string, ServiceHealth, string[]]>([
    ["en vérification", { state: "checking", auth: null, payments: null }, ["Authentification…", "Paiements…"]],
    ["opérationnels", HEALTHY, ["Authentificationopérationnel", "Paiementsopérationnel"]],
    ["paiements perturbés", { state: "degraded", auth: true, payments: false }, ["Authentificationopérationnel", "Paiementsperturbé"]],
    ["tout perturbé", { state: "down", auth: false, payments: false }, ["Authentificationperturbé", "Paiementsperturbé"]],
  ])("affiche chaque service %s", (_, health, labels) => {
    setup(health);

    const panel = screen.getByTestId("auth-service-status");
    expect(Array.from(panel.children, (chip) => chip.textContent)).toEqual(labels);
  });
});
