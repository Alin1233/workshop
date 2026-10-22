import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { databaseUnavailable, deferred, json, makeTransfer, mockFetch, networkDown } from "../test/http";
import TransferForm from "./TransferForm";

const TRANSFERS = "POST /api/payments/transfers";

// Cette méthode permet d'afficher le formulaire avec un jeton généré et des rappels espionnés.
function setup() {
  const token = crypto.randomUUID();
  const onDone = vi.fn();
  const onSessionExpired = vi.fn();
  render(<TransferForm token={token} onDone={onDone} onSessionExpired={onSessionExpired} />);
  return { user: userEvent.setup(), token, onDone, onSessionExpired };
}

const amountInput = () => screen.getByLabelText(/^Montant/);
const accountInput = () => screen.getByLabelText(/^Compte bénéficiaire/);
const labelInput = () => screen.getByLabelText(/^Libellé/);
const submitButton = () => screen.getByRole("button", { name: /^(Envoyer|Envoi…|Réessayer l'envoi)/ });
const feedback = () => screen.getByRole("status");

// Réponse 201 de l'API : le virement créé, au montant demandé.
const created = ({ body }: { body: unknown }) => json(201, makeTransfer({ amount_cents: (body as { amount_cents: number }).amount_cents }));

// Cette méthode permet de saisir un virement valide (12,50 € vers RA 0123 4567 89).
async function fillValid(user: ReturnType<typeof userEvent.setup>, label = "") {
  await user.type(amountInput(), "12,50");
  await user.type(accountInput(), "RA 0123 4567 89");
  if (label) await user.type(labelInput(), label);
}

describe("TransferForm : validation", () => {
  it("affiche un message sous chaque champ invalide et n'envoie rien", async () => {
    const http = mockFetch({ [TRANSFERS]: created });
    const { user } = setup();

    await user.click(submitButton());

    expect(amountInput()).toHaveAttribute("aria-invalid", "true");
    expect(amountInput()).toHaveAccessibleDescription("Montant invalide (ex. 12,50).");
    expect(accountInput()).toHaveAttribute("aria-invalid", "true");
    expect(accountInput()).toHaveAccessibleDescription("Compte bénéficiaire requis.");
    expect(labelInput()).toHaveAttribute("aria-invalid", "false");
    expect(http.calls).toHaveLength(0);
  });

  it("refuse un compte mal formé et un montant au-delà du plafond", async () => {
    const http = mockFetch({ [TRANSFERS]: created });
    const { user } = setup();

    await user.type(amountInput(), "10 000,01");
    await user.type(accountInput(), "FR12 3456 7890");
    await user.click(submitButton());

    expect(screen.getByText("Montant maximum : 10 000,00 €.")).toBeInTheDocument();
    expect(screen.getByText("Format attendu : RA suivi de 10 chiffres.")).toBeInTheDocument();
    expect(http.calls).toHaveLength(0);
  });

  it("efface le message d'un champ dès qu'on le corrige, sans toucher aux autres", async () => {
    mockFetch({ [TRANSFERS]: created });
    const { user } = setup();
    await user.click(submitButton());

    await user.type(amountInput(), "5");

    expect(amountInput()).toHaveAttribute("aria-invalid", "false");
    expect(screen.queryByText("Montant invalide (ex. 12,50).")).not.toBeInTheDocument();
    expect(screen.getByText("Compte bénéficiaire requis.")).toBeInTheDocument();
  });

  it("limite le libellé à 60 caractères, compteur à l'appui", async () => {
    mockFetch({ [TRANSFERS]: created });
    const { user } = setup();
    expect(screen.getByText("0/60")).toBeInTheDocument();

    await user.type(labelInput(), "Loyer");
    expect(screen.getByText("5/60")).toBeInTheDocument();

    await user.type(labelInput(), "x".repeat(70));
    expect(labelInput()).toHaveValue(`Loyer${"x".repeat(55)}`);
    expect(screen.getByText("60/60")).toHaveClass("text-brick");
  });

  it("annonce le montant sur le bouton, y compris via les montants rapides", async () => {
    mockFetch({ [TRANSFERS]: created });
    const { user } = setup();
    expect(submitButton()).toHaveTextContent(/^Envoyer$/);

    await user.type(amountInput(), "12,5");
    expect(submitButton()).toHaveTextContent("Envoyer 12,50 €");

    await user.click(screen.getByRole("button", { name: "20 €" }));
    expect(amountInput()).toHaveValue("20");
    expect(submitButton()).toHaveTextContent("Envoyer 20,00 €");
  });
});

describe("TransferForm : envoi", () => {
  it("envoie la saisie normalisée avec le jeton et une clé d'idempotence, puis repart d'un formulaire vide", async () => {
    const http = mockFetch({ [TRANSFERS]: created });
    const { user, token, onDone } = setup();
    await fillValid(user, "  Resto du jeudi  ");

    await user.click(submitButton());

    expect(await screen.findByText("Virement de 12,50 € effectué.", { normalizer: (t) => t.replace(/\s+/g, " ") })).toBeInTheDocument();
    const [call] = http.calls;
    expect(call.body).toEqual({ to_account_number: "RA0123456789", amount_cents: 1250, label: "Resto du jeudi" });
    expect(call.headers.get("Authorization")).toBe(`Bearer ${token}`);
    expect(call.headers.get("Idempotency-Key")).toMatch(/^[0-9a-f-]{36}$/);
    expect(onDone).toHaveBeenCalledTimes(1);
    expect(amountInput()).toHaveValue("");
    expect(accountInput()).toHaveValue("");
    expect(labelInput()).toHaveValue("");
  });

  it("bloque un second clic tant que le virement est en vol", async () => {
    const pending = deferred<Response>();
    const http = mockFetch({ [TRANSFERS]: () => pending.promise });
    const { user } = setup();
    await fillValid(user);

    await user.click(submitButton());
    expect(submitButton()).toBeDisabled();
    expect(submitButton()).toHaveTextContent("Envoi…");
    await user.click(submitButton());
    await user.click(submitButton());

    expect(http.calls).toHaveLength(1);
    await act(async () => pending.resolve(json(201, makeTransfer({ amount_cents: 1250 }))));
    expect(feedback()).toHaveTextContent("Virement de 12,50 € effectué.");
    expect(submitButton()).toBeEnabled();
  });

  it("donne la même clé d'idempotence à toute soumission en double : le serveur ne débite qu'une fois", async () => {
    const pending = deferred<Response>();
    const http = mockFetch({ [TRANSFERS]: () => pending.promise });
    const { user } = setup();
    await fillValid(user);
    const form = screen.getByTestId("transfer-form");

    // Soumission du formulaire sans passer par le bouton (désactivé après la première).
    fireEvent.submit(form);
    fireEvent.submit(form);
    await act(async () => pending.resolve(json(201, makeTransfer({ amount_cents: 1250 }))));

    const keys = http.calls.map((c) => c.headers.get("Idempotency-Key"));
    expect(keys.length).toBeGreaterThanOrEqual(1);
    expect(new Set(keys).size).toBe(1);
  });

  it("utilise une nouvelle clé pour le virement suivant", async () => {
    const http = mockFetch({ [TRANSFERS]: created });
    const { user } = setup();
    await fillValid(user);
    await user.click(submitButton());
    await screen.findByText(/effectué/);

    await fillValid(user);
    await user.click(submitButton());
    await vi.waitFor(() => expect(http.calls).toHaveLength(2));

    const [first, second] = http.calls.map((c) => c.headers.get("Idempotency-Key"));
    expect(second).not.toBe(first);
  });
});

describe("TransferForm : incident et nouvel essai", () => {
  it.each([
    ["coupure réseau", networkDown, "Service injoignable. Réessayez dans quelques instants."],
    ["base indisponible (503 database_unavailable)", databaseUnavailable, "Service momentanément indisponible. Réessayez dans quelques instants."],
  ])("après une %s, propose un renvoi sûr avec la même clé d'idempotence", async (_, failure, reason) => {
    let attempts = 0;
    const http = mockFetch({ [TRANSFERS]: (call) => (++attempts === 1 ? failure() : created(call)) });
    const { user, onDone } = setup();
    await fillValid(user);

    await user.click(submitButton());

    expect(await screen.findByText(/Envoi non confirmé/)).toHaveTextContent(
      `Envoi non confirmé. ${reason} Le renvoi est sûr : il ne sera jamais débité deux fois.`,
    );
    expect(feedback()).toHaveClass("bg-amber-soft");
    expect(submitButton()).toHaveTextContent("Réessayer l'envoi");
    expect(amountInput()).toHaveValue("12,50"); // la saisie est conservée pour le renvoi
    expect(onDone).not.toHaveBeenCalled();

    await user.click(submitButton());

    expect(await screen.findByText(/effectué/)).toBeInTheDocument();
    const keys = http.calls.map((c) => c.headers.get("Idempotency-Key"));
    expect(keys).toHaveLength(2);
    expect(keys[1]).toBe(keys[0]);
    expect(onDone).toHaveBeenCalledTimes(1);
  });

  it("change de clé si la saisie change après l'échec : c'est un autre virement", async () => {
    let attempts = 0;
    const http = mockFetch({ [TRANSFERS]: (call) => (++attempts === 1 ? databaseUnavailable() : created(call)) });
    const { user } = setup();
    await fillValid(user);
    await user.click(submitButton());
    await screen.findByText(/Envoi non confirmé/);

    await user.clear(amountInput());
    await user.type(amountInput(), "13");

    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(submitButton()).toHaveTextContent("Envoyer 13,00 €");
    await user.click(submitButton());
    await screen.findByText(/effectué/);
    const [first, second] = http.calls.map((c) => c.headers.get("Idempotency-Key"));
    expect(second).not.toBe(first);
    expect(http.calls[1].body).toMatchObject({ amount_cents: 1300 });
  });

  it("garde la clé quand on reclique sur le montant rapide déjà choisi (la saisie ne change pas)", async () => {
    let attempts = 0;
    const http = mockFetch({ [TRANSFERS]: (call) => (++attempts === 1 ? networkDown() : created(call)) });
    const { user } = setup();
    await user.click(screen.getByRole("button", { name: "20 €" }));
    await user.type(accountInput(), "RA0123456789");
    await user.click(submitButton());
    await screen.findByText(/Envoi non confirmé/);

    await user.click(screen.getByRole("button", { name: "20 €" }));

    expect(submitButton()).toHaveTextContent("Réessayer l'envoi");
    await user.click(submitButton());
    await screen.findByText(/effectué/);
    const [first, second] = http.calls.map((c) => c.headers.get("Idempotency-Key"));
    expect(second).toBe(first);
  });

  it("affiche un refus métier sans proposer de renvoi", async () => {
    mockFetch({ [TRANSFERS]: () => json(422, { code: "insufficient_funds", detail: "Solde insuffisant" }) });
    const { user, onDone } = setup();
    await fillValid(user);

    await user.click(submitButton());

    expect(await screen.findByText("Solde insuffisant")).toHaveClass("bg-brick-soft");
    expect(submitButton()).toHaveTextContent("Envoyer 12,50 €");
    expect(onDone).not.toHaveBeenCalled();
  });

  it("renvoie vers la connexion quand le jeton a expiré (401)", async () => {
    mockFetch({ [TRANSFERS]: () => json(401, { detail: "Jeton invalide ou expiré" }) });
    const { user, onSessionExpired, onDone } = setup();
    await fillValid(user);

    await user.click(submitButton());

    await vi.waitFor(() => expect(onSessionExpired).toHaveBeenCalledTimes(1));
    expect(onDone).not.toHaveBeenCalled();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});
