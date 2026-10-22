import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { Account, Transfer } from "../lib/api";
import type { ServiceHealth } from "../lib/useServiceHealth";
import { databaseUnavailable, json, makeAccount, makeSession, makeTransfer, mockFetch, plain } from "../test/http";
import Dashboard from "./Dashboard";

const HEALTHY: ServiceHealth = { state: "ok", auth: true, payments: true };
const PAYMENTS_DOWN: ServiceHealth = { state: "degraded", auth: true, payments: false };

// Cette méthode permet de simuler l'API de paiement (compte + historique) puis d'afficher l'espace client.
function setup({
  account = makeAccount(),
  transfers = [] as Transfer[],
  health = HEALTHY,
  failure,
}: { account?: Account; transfers?: Transfer[]; health?: ServiceHealth; failure?: () => Response } = {}) {
  const http = mockFetch({
    "GET /api/payments/accounts/me": () => failure?.() ?? json(200, account),
    "GET /api/payments/transfers": () => failure?.() ?? json(200, transfers),
    "POST /api/payments/transfers": () => json(201, makeTransfer({ amount_cents: 1250 })),
  });
  const session = makeSession();
  const onSessionExpired = vi.fn();
  const user = userEvent.setup();
  render(<Dashboard session={session} health={health} onSessionExpired={onSessionExpired} />);
  return { http, session, onSessionExpired, user };
}

describe("Dashboard", () => {
  it("charge compte et historique avec le jeton de la session", async () => {
    const { http, session } = setup();

    await screen.findByText("Aucun mouvement pour le moment");

    const payments = http.calls.filter((c) => c.path.startsWith("/api/payments/"));
    expect(payments.map((c) => [c.path, c.headers.get("Authorization")])).toEqual([
      ["/api/payments/accounts/me", `Bearer ${session.token}`],
      ["/api/payments/transfers?limit=20", `Bearer ${session.token}`],
    ]);
  });

  it("affiche le solde et le numéro de compte lisibles", async () => {
    setup({ account: makeAccount({ balance_cents: 123_456, account_number: "RA0123456789" }) });

    const balance = await screen.findByTestId("balance");
    expect(plain(balance.textContent)).toBe("1 234,56 €");
    expect(screen.getByTestId("account-number")).toHaveTextContent("RA 0123 4567 89");
    expect(screen.getByTestId("account-number")).toHaveAttribute("data-value", "RA0123456789");
  });

  it("liste les mouvements du jour avec leur sens et totalise le mois", async () => {
    setup({
      transfers: [
        makeTransfer({ direction: "credit", amount_cents: 5_000, label: "", counterparty_name: "Bob Durand" }),
        makeTransfer({ direction: "debit", amount_cents: 1_250, label: "Resto", counterparty_name: "Chloé Petit" }),
      ],
    });

    const list = await screen.findByTestId("transfer-list");
    expect(list).toHaveTextContent("Aujourd'hui");
    const [credit, debit] = within(list).getAllByRole("listitem").map((li) => plain(li.textContent));
    expect(credit).toMatch(/^↓Virement reçuDe Bob Durand · \d{2}:\d{2}\+ 50,00 €$/);
    expect(debit).toMatch(/^↑RestoVers Chloé Petit · \d{2}:\d{2}− 12,50 €$/);
    // Totaux du mois sous le solde.
    expect(screen.getByText("+ 50,00 €", { normalizer: plain, selector: "dd" })).toBeInTheDocument();
    expect(screen.getByText("− 12,50 €", { normalizer: plain, selector: "dd" })).toBeInTheDocument();
  });

  it("copie le numéro de compte brut", async () => {
    const { user } = setup();
    await screen.findByText("RA 0123 4567 89");

    await user.click(screen.getByRole("button", { name: "Copier" }));

    expect(await navigator.clipboard.readText()).toBe("RA0123456789");
    expect(screen.getByRole("button", { name: "Copié ✓" })).toBeInTheDocument();
  });

  it("montre l'échec du rafraîchissement quand aucun incident n'est en cours", async () => {
    setup({ failure: databaseUnavailable });

    expect(await screen.findByRole("alert")).toHaveTextContent("Service momentanément indisponible. Réessayez dans quelques instants.");
  });

  it("laisse le bandeau d'incident expliquer la panne, sans doublon d'erreur", async () => {
    const { http } = setup({ failure: databaseUnavailable, health: PAYMENTS_DOWN });
    await vi.waitFor(() => expect(http.calls.filter((c) => c.path.startsWith("/api/payments/"))).toHaveLength(2));

    const alerts = await screen.findAllByRole("alert");
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toHaveTextContent("Les paiements sont perturbés");
    expect(screen.queryByText(/Service momentanément indisponible/)).not.toBeInTheDocument();
  });

  it("renvoie vers la connexion quand le jeton n'est plus accepté (401)", async () => {
    const { onSessionExpired } = setup({ failure: () => json(401, { detail: "Jeton invalide ou expiré" }) });

    await vi.waitFor(() => expect(onSessionExpired).toHaveBeenCalled());
  });

  it("recharge le solde après un virement réussi", async () => {
    const { http, user } = setup();
    await screen.findByText("Aucun mouvement pour le moment");

    await user.type(screen.getByLabelText(/^Montant/), "12,50");
    await user.type(screen.getByLabelText(/^Compte bénéficiaire/), "RA9876543210");
    await user.click(screen.getByRole("button", { name: /^Envoyer/ }));

    await vi.waitFor(() => expect(http.callsTo("GET /api/payments/accounts/me")).toHaveLength(2));
    expect(http.callsTo("GET /api/payments/transfers")).toHaveLength(2);
  });
});
