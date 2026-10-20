import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ServiceHealth } from "../lib/useServiceHealth";
import { elapse, mockCamera, restoreCamera } from "../test/camera";
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

describe("AuthScreen : double authentification", () => {
  const MFA = "POST /api/auth/login/mfa";
  const challenge = () => json(200, { mfa_required: true, mfa_token: crypto.randomUUID(), expires_in: 300 });
  const codeInput = () => screen.getByLabelText(/^Code de vérification/);

  // Cette méthode permet de passer l'étape du mot de passe d'un compte protégé par la double authentification.
  async function passPassword(routes: Parameters<typeof mockFetch>[0]) {
    const http = mockFetch({ [LOGIN]: challenge, ...routes });
    const ctx = setup();
    await ctx.user.type(emailInput(), "alice@exemple.fr");
    await ctx.user.type(passwordInput(), ctx.password);
    await ctx.user.click(screen.getByRole("button", { name: "Se connecter" }));
    await screen.findByText("Double authentification");
    return { http, ...ctx };
  }

  it("demande le code puis ouvre la session avec le jeton d'étape", async () => {
    const { http, user, onLogin } = await passPassword({ [MFA]: () => loginResponse() });
    expect(onLogin).not.toHaveBeenCalled();
    expect(screen.queryByLabelText(/^Mot de passe/)).not.toBeInTheDocument();

    await user.type(codeInput(), "123 456");
    await user.click(screen.getByRole("button", { name: "Vérifier" }));

    await vi.waitFor(() => expect(onLogin).toHaveBeenCalledTimes(1));
    const [call] = http.callsTo(MFA);
    expect(call.body).toEqual({ mfa_token: expect.stringMatching(/.+/), code: "123456" });
  });

  it("accepte un code de secours et refuse une saisie mal formée sans appel", async () => {
    const { http, user, onLogin } = await passPassword({ [MFA]: () => loginResponse() });

    await user.type(codeInput(), "12");
    await user.click(screen.getByRole("button", { name: "Vérifier" }));
    expect(screen.getByText("6 chiffres, ou un code de secours (xxxxx-xxxxx).")).toBeInTheDocument();
    expect(http.callsTo(MFA)).toHaveLength(0);

    await user.clear(codeInput());
    await user.type(codeInput(), "abcde-fghjk");
    await user.click(screen.getByRole("button", { name: "Vérifier" }));
    await vi.waitFor(() => expect(onLogin).toHaveBeenCalledTimes(1));
  });

  it("affiche un code refusé et laisse réessayer", async () => {
    const { user, onLogin } = await passPassword({
      [MFA]: () => json(401, { code: "mfa_invalid_code", detail: "Code invalide." }),
    });

    await user.type(codeInput(), "000000");
    await user.click(screen.getByRole("button", { name: "Vérifier" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Code invalide.");
    expect(codeInput()).toHaveValue("");
    expect(onLogin).not.toHaveBeenCalled();
  });

  it("revient au mot de passe quand l'étape a expiré", async () => {
    const { user } = await passPassword({
      [MFA]: () => json(401, { code: "mfa_challenge_expired", detail: "Trop d'essais, reconnectez-vous." }),
    });

    await user.type(codeInput(), "000000");
    await user.click(screen.getByRole("button", { name: "Vérifier" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Trop d'essais, reconnectez-vous.");
    expect(passwordInput()).toHaveValue("");
    expect(screen.getByRole("button", { name: "Se connecter" })).toBeInTheDocument();
  });
});

describe("AuthScreen : connexion par reconnaissance faciale", () => {
  const FACE_CHALLENGE = "POST /api/auth/login/mfa/face/challenge";
  const FACE = "POST /api/auth/login/mfa/face";
  const MFA_TOKEN = crypto.randomUUID();
  const challenge = () => json(200, { mfa_required: true, mfa_token: MFA_TOKEN, expires_in: 300, methods: ["totp", "face"] });
  const poses = () => json(200, { challenge_id: "c-1", poses: ["center", "left"], expires_in: 120 });

  afterEach(restoreCamera);

  // Cette méthode permet de passer le mot de passe d'un compte avec visage enregistré, caméra simulée et horloge simulée.
  async function passPassword(routes: Parameters<typeof mockFetch>[0]) {
    mockCamera();
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const http = mockFetch({ [LOGIN]: challenge, [FACE_CHALLENGE]: poses, ...routes });
    const onLogin = vi.fn();
    render(<AuthScreen onLogin={onLogin} health={HEALTHY} />);
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.type(emailInput(), "alice@exemple.fr");
    await user.type(passwordInput(), crypto.randomUUID());
    await user.click(screen.getByRole("button", { name: "Se connecter" }));
    await screen.findByText("Double authentification");
    return { http, user, onLogin };
  }

  // Cette méthode permet de lancer la caméra puis de laisser passer les comptes à rebours (de face puis un côté).
  async function captureFace(user: ReturnType<typeof userEvent.setup>) {
    await user.click(screen.getByRole("button", { name: "Utiliser la caméra" }));
    await user.click(await screen.findByRole("button", { name: "Démarrer" }));
    await elapse(9000);
  }

  it("propose le visage en premier et ouvre la session avec deux captures (de face puis un côté)", async () => {
    const { http, user, onLogin } = await passPassword({ [FACE]: () => loginResponse() });
    expect(screen.getByRole("tab", { name: "Visage" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText(/deux photos : de face, puis la tête tournée d'un côté/)).toBeInTheDocument();

    await captureFace(user);

    await vi.waitFor(() => expect(onLogin).toHaveBeenCalledTimes(1));
    expect(http.callsTo(FACE_CHALLENGE)[0].body).toEqual({ mfa_token: MFA_TOKEN });
    const form = http.callsTo(FACE)[0].form!;
    expect(form.get("mfa_token")).toBe(MFA_TOKEN);
    expect(form.get("challenge_id")).toBe("c-1");
    expect(form.getAll("frames")).toHaveLength(2);
    expect(http.callsTo(FACE)[0].headers.get("Content-Type")).toBeNull(); // frontière multipart posée par le navigateur
  });

  it("affiche un visage refusé et laisse recommencer avec un nouveau défi", async () => {
    const { http, user, onLogin } = await passPassword({
      [FACE]: () => json(401, { code: "face_no_match", detail: "Visage non reconnu." }),
    });

    await captureFace(user);

    expect(await screen.findByRole("alert")).toHaveTextContent("Visage non reconnu.");
    await user.click(screen.getByRole("button", { name: "Réessayer" }));
    await screen.findByRole("button", { name: "Démarrer" });
    expect(http.callsTo(FACE_CHALLENGE)).toHaveLength(2);
    expect(onLogin).not.toHaveBeenCalled();
  });

  it("permet de revenir au code", async () => {
    const { user } = await passPassword({});

    await user.click(screen.getByRole("tab", { name: "Code" }));
    expect(screen.getByLabelText(/^Code de vérification/)).toBeInTheDocument();
  });

  it("n'affiche pas le choix sans visage enregistré", async () => {
    mockFetch({ [LOGIN]: () => json(200, { mfa_required: true, mfa_token: MFA_TOKEN, expires_in: 300, methods: ["totp"] }) });
    const { user, password } = setup();
    await user.type(emailInput(), "alice@exemple.fr");
    await user.type(passwordInput(), password);
    await user.click(screen.getByRole("button", { name: "Se connecter" }));

    expect(await screen.findByLabelText(/^Code de vérification/)).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Visage" })).not.toBeInTheDocument();
  });
});
