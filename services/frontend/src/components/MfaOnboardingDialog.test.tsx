import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { MfaStatus } from "../lib/api";
import { json, makeSession, mockFetch } from "../test/http";
import MfaOnboardingDialog from "./MfaOnboardingDialog";

const OFF: MfaStatus = { enabled: false, required: false, recovery_codes_remaining: 0, face_enrolled: false };
const ON: MfaStatus = { enabled: true, required: false, recovery_codes_remaining: 10, face_enrolled: false };
const RECOVERY_CODES = Array.from({ length: 10 }, (_, i) => `abcd${i}-efgh${i}`);
const SETUP_RESPONSE = { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/x", qr_code: "data:image/svg+xml;base64,PHN2Zy8+" };

// Cette méthode permet d'afficher la modale pour un compte sans double authentification, l'activation faisant passer
// l'état renvoyé par GET /mfa à « activée » comme le ferait l'auth-service.
function setup() {
  let status = OFF;
  const http = mockFetch({
    "GET /api/auth/mfa": () => json(200, status),
    "GET /api/auth/mfa/face": () => json(200, { enrolled: false, enrolled_at: null, consented_at: null, image: null }),
    "POST /api/auth/mfa/setup": () => json(200, SETUP_RESPONSE),
    "POST /api/auth/mfa/activate": () => {
      status = ON;
      return json(200, { recovery_codes: RECOVERY_CODES });
    },
  });
  const onClose = vi.fn();
  render(<MfaOnboardingDialog session={makeSession()} onClose={onClose} onSessionExpired={vi.fn()} />);
  return { http, onClose, user: userEvent.setup() };
}

describe("MfaOnboardingDialog", () => {
  it("propose d'activer la double authentification, sans le panneau des paramètres", async () => {
    const { onClose, user } = setup();

    const dialog = screen.getByRole("dialog", { name: "Protégez votre compte" });
    expect(dialog).toHaveAttribute("open");
    expect(dialog).toHaveTextContent("Bienvenue Alice !");
    expect(await screen.findByRole("button", { name: "Activer maintenant" })).toBeInTheDocument();
    expect(screen.queryByText("Désactivée")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Plus tard" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("mène l'activation jusqu'aux codes de secours, puis se ferme une fois les codes notés", async () => {
    const { http, onClose, user } = setup();

    await user.click(await screen.findByRole("button", { name: "Activer maintenant" }));
    await user.type(await screen.findByLabelText(/^Code de l'application/), "123456");
    await user.click(screen.getByRole("button", { name: "Confirmer l'activation" }));
    expect((await screen.findByTestId("recovery-codes")).children).toHaveLength(10);
    expect(onClose).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "J'ai noté mes codes" }));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(http.callsTo("GET /api/auth/mfa/face")).toHaveLength(0); // pas de reconnaissance faciale dans la modale
  });

  it("ne se ferme pas sur Échap, pour ne pas perdre les codes de secours affichés une seule fois", () => {
    const { onClose } = setup();
    const dialog = screen.getByRole("dialog", { name: "Protégez votre compte" });

    expect(fireEvent(dialog, new Event("cancel", { cancelable: true }))).toBe(false);
    expect(onClose).not.toHaveBeenCalled();
  });
});
