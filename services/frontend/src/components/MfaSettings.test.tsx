import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { MfaStatus } from "../lib/api";
import { json, mockFetch } from "../test/http";
import MfaSettings from "./MfaSettings";

const STATUS = "GET /api/auth/mfa";
const SETUP = "POST /api/auth/mfa/setup";
const ACTIVATE = "POST /api/auth/mfa/activate";
const DISABLE = "POST /api/auth/mfa/disable";
const FACE_STATUS = "GET /api/auth/mfa/face";
const RECOVERY_CODES = Array.from({ length: 10 }, (_, i) => `abcd${i}-efgh${i}`);
const OFF: MfaStatus = { enabled: false, required: false, recovery_codes_remaining: 0, face_enrolled: false };
const ON: MfaStatus = { enabled: true, required: false, recovery_codes_remaining: 10, face_enrolled: false };

// Cette méthode permet d'afficher le panneau avec un état initial donné ; les routes reçoivent de quoi faire évoluer
// l'état renvoyé ensuite par GET /mfa, comme le ferait l'auth-service après une action.
function setup(initial: MfaStatus, routes: (setStatus: (next: MfaStatus) => void) => Parameters<typeof mockFetch>[0] = () => ({})) {
  let status = initial;
  const http = mockFetch({
    [STATUS]: () => json(200, status),
    [FACE_STATUS]: () => json(200, { enrolled: false, enrolled_at: null, consented_at: null, image: null }),
    ...routes((next) => (status = next)),
  });
  const onSessionExpired = vi.fn();
  const token = crypto.randomUUID();
  render(<MfaSettings token={token} onSessionExpired={onSessionExpired} />);
  return { http, token, onSessionExpired, user: userEvent.setup() };
}

const SETUP_RESPONSE = { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/x", qr_code: "data:image/svg+xml;base64,PHN2Zy8+" };

describe("MfaSettings", () => {
  it("active la double authentification : QR code, premier code, codes de secours", async () => {
    const { http, token, user } = setup(OFF, (setStatus) => ({
      [SETUP]: () => json(200, SETUP_RESPONSE),
      [ACTIVATE]: () => {
        setStatus(ON);
        return json(200, { recovery_codes: RECOVERY_CODES });
      },
    }));

    await user.click(await screen.findByRole("button", { name: "Activer" }));
    expect(await screen.findByAltText(/QR code/)).toHaveAttribute("src", SETUP_RESPONSE.qr_code);
    expect(screen.getByTestId("mfa-secret")).toHaveTextContent("JBSW Y3DP EHPK 3PXP");

    await user.click(screen.getByRole("button", { name: "Confirmer l'activation" }));
    expect(screen.getByText("Saisissez le code à 6 chiffres affiché par l'application.")).toBeInTheDocument();
    expect(http.callsTo(ACTIVATE)).toHaveLength(0);

    await user.type(screen.getByLabelText(/^Code de l'application/), "123456");
    await user.click(screen.getByRole("button", { name: "Confirmer l'activation" }));

    expect((await screen.findByTestId("recovery-codes")).children).toHaveLength(10);
    const [call] = http.callsTo(ACTIVATE);
    expect(call.body).toEqual({ code: "123456" });
    expect(call.headers.get("Authorization")).toBe(`Bearer ${token}`);

    await user.click(screen.getByRole("button", { name: "J'ai noté mes codes" }));
    expect(screen.queryByTestId("recovery-codes")).not.toBeInTheDocument();
    expect(screen.getByText("Activée")).toBeInTheDocument();
    expect(screen.getByText(/10 codes de secours restants/)).toBeInTheDocument();
  });

  it("affiche le refus du premier code sans quitter l'activation", async () => {
    const { user } = setup(OFF, () => ({
      [SETUP]: () => json(200, SETUP_RESPONSE),
      [ACTIVATE]: () => json(400, { code: "mfa_invalid_code", detail: "Code invalide. Vérifiez l'heure de votre téléphone." }),
    }));

    await user.click(await screen.findByRole("button", { name: "Activer" }));
    await user.type(await screen.findByLabelText(/^Code de l'application/), "000000");
    await user.click(screen.getByRole("button", { name: "Confirmer l'activation" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Vérifiez l'heure de votre téléphone");
    expect(screen.getByAltText(/QR code/)).toBeInTheDocument();
  });

  it("désactive après confirmation du mot de passe et d'un code", async () => {
    const { http, user } = setup(ON, (setStatus) => ({
      [DISABLE]: () => {
        setStatus(OFF);
        return new Response(null, { status: 204 });
      },
    }));
    const password = crypto.randomUUID();

    await user.click(await screen.findByRole("button", { name: "Désactiver" }));
    await user.click(screen.getByRole("button", { name: "Confirmer la désactivation" }));
    expect(screen.getByText("Mot de passe requis.")).toBeInTheDocument();

    await user.type(screen.getByLabelText(/^Mot de passe/), password);
    await user.type(screen.getByLabelText(/^Code de vérification/), "654321");
    await user.click(screen.getByRole("button", { name: "Confirmer la désactivation" }));

    expect(await screen.findByRole("button", { name: "Activer" })).toBeInTheDocument();
    expect(http.callsTo(DISABLE)[0].body).toEqual({ password, code: "654321" });
  });

  it("ne propose pas la désactivation quand elle est obligatoire (admin)", async () => {
    setup({ enabled: true, required: true, recovery_codes_remaining: 2, face_enrolled: false });

    expect(await screen.findByText("Obligatoire pour le compte administrateur.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Désactiver" })).not.toBeInTheDocument();
    expect(screen.getByText(/2 codes de secours restants/)).toHaveClass("text-brick");
  });

  it("renvoie à la connexion quand la session a expiré", async () => {
    mockFetch({ [STATUS]: () => json(401, { detail: "Jeton invalide ou expiré" }) });
    const onSessionExpired = vi.fn();
    render(<MfaSettings token={crypto.randomUUID()} onSessionExpired={onSessionExpired} />);

    await vi.waitFor(() => expect(onSessionExpired).toHaveBeenCalledTimes(1));
  });
});
