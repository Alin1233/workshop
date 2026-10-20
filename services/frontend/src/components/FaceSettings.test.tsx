import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { FaceStatus } from "../lib/api";
import { elapse, mockCamera, restoreCamera } from "../test/camera";
import { json, mockFetch } from "../test/http";
import FaceSettings from "./FaceSettings";

const STATUS = "GET /api/auth/mfa/face";
const CHALLENGE = "POST /api/auth/mfa/face/challenge";
const ENROLL = "POST /api/auth/mfa/face";
const REMOVE = "DELETE /api/auth/mfa/face";
const NONE: FaceStatus = { enrolled: false, enrolled_at: null, consented_at: null };
const ENROLLED: FaceStatus = {
  enrolled: true,
  enrolled_at: "2026-10-20T08:00:00Z",
  consented_at: "2026-10-20T08:00:00Z",
};

afterEach(restoreCamera);

// Cette méthode permet d'afficher le panneau avec un état initial, une caméra simulée et une horloge simulée.
function setup(initial: FaceStatus, routes: Parameters<typeof mockFetch>[0] = {}) {
  mockCamera();
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const http = mockFetch({
    [STATUS]: () => json(200, initial),
    [CHALLENGE]: () => json(200, { challenge_id: "c-9", poses: ["center", "right", "left"], expires_in: 120 }),
    ...routes,
  });
  const onSessionExpired = vi.fn();
  render(<FaceSettings token="jeton" onSessionExpired={onSessionExpired} />);
  return { http, onSessionExpired, user: userEvent.setup({ advanceTimers: vi.advanceTimersByTime }) };
}

// Cette méthode permet de remplir le consentement et le code dans la modale, puis de les faire vérifier.
async function confirmWith(user: ReturnType<typeof userEvent.setup>, code: string) {
  await user.click(screen.getByRole("checkbox"));
  await user.type(screen.getByLabelText(/^Code de l'application/), code);
  await user.click(screen.getByRole("button", { name: "Continuer" }));
}

// Cette méthode permet de filmer le défi jusqu'au bout (compte à rebours : pas de détecteur sous jsdom).
async function film(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "Démarrer" }));
  await elapse(9000);
}

describe("FaceSettings", () => {
  it("vérifie consentement et code dans une modale avant la caméra, puis indique la configuration sans photo", async () => {
    const { http, user } = setup(NONE, { [ENROLL]: () => json(200, ENROLLED) });

    await user.click(await screen.findByRole("button", { name: "Configurer" }));
    const dialog = screen.getByRole("dialog", { name: "Enregistrer votre visage" });
    expect(dialog).toHaveAttribute("open");
    expect(screen.getByText(/gardées 7 jours pour l'équipe sécurité/)).toBeInTheDocument();
    expect(screen.queryByText(/photo de référence/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Continuer" }));
    expect(screen.getByText("Cochez la case pour continuer.")).toBeInTheDocument();
    expect(http.callsTo(CHALLENGE)).toHaveLength(0);

    await confirmWith(user, "123 456");
    const [opened] = http.callsTo(CHALLENGE);
    expect(opened.headers.get("Authorization")).toBe("Bearer jeton");
    expect(opened.body).toEqual({ code: "123456", consent: true });
    await film(user);

    expect(await screen.findByText("Configurée le 20 octobre 2026.")).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(screen.getByText("Enregistrée")).toBeInTheDocument();
    expect(dialog).not.toHaveAttribute("open");
    const [call] = http.callsTo(ENROLL);
    expect(call.form!.get("challenge_id")).toBe("c-9");
    expect(call.form!.has("code")).toBe(false);
    expect(call.form!.getAll("frames")).toHaveLength(3);
  });

  it("refuse un code faux avant d'ouvrir la caméra", async () => {
    const { http, user } = setup(NONE, {
      [CHALLENGE]: () => json(400, { code: "mfa_invalid_code", detail: "Code invalide." }),
    });

    await user.click(await screen.findByRole("button", { name: "Configurer" }));
    await confirmWith(user, "000000");

    expect(await screen.findByText("Code invalide.")).toBeInTheDocument();
    expect(screen.getByLabelText(/^Code de l'application/)).toHaveAttribute("aria-invalid", "true");
    expect(screen.queryByTestId("face-capture")).not.toBeInTheDocument();
    expect(http.callsTo(ENROLL)).toHaveLength(0);
  });

  it("laisse réessayer le défi de pose sans redemander le code", async () => {
    const answers = [json(400, { code: "face_liveness_failed", detail: "Mouvement non reconnu." }), json(200, ENROLLED)];
    const { http, user } = setup(NONE, { [ENROLL]: () => answers.shift()! });

    await user.click(await screen.findByRole("button", { name: "Configurer" }));
    await confirmWith(user, "123456");
    await film(user);

    expect(await screen.findByRole("alert")).toHaveTextContent("Mouvement non reconnu.");
    await user.click(screen.getByRole("button", { name: "Réessayer" }));
    await film(user);

    expect(await screen.findByText(/Configurée le/)).toBeInTheDocument();
    expect(http.callsTo(CHALLENGE)).toHaveLength(1);
    expect(http.callsTo(ENROLL).map((c) => c.form!.get("challenge_id"))).toEqual(["c-9", "c-9"]);
  });

  it("redemande un code quand le défi a expiré", async () => {
    const { user } = setup(NONE, {
      [ENROLL]: () => json(409, { code: "face_challenge_expired", detail: "Défi expiré, recommencez la vérification." }),
    });

    await user.click(await screen.findByRole("button", { name: "Configurer" }));
    await confirmWith(user, "123456");
    await film(user);

    expect(await screen.findByRole("alert")).toHaveTextContent("Défi expiré, recommencez la vérification. Saisissez un nouveau code.");
    expect(screen.getByLabelText(/^Code de l'application/)).toHaveValue("");
    expect(screen.getByRole("checkbox")).toBeChecked();
  });

  it("supprime le visage enregistré", async () => {
    let status = ENROLLED;
    const { http, user } = setup(ENROLLED, {
      [STATUS]: () => json(200, status),
      [REMOVE]: () => {
        status = NONE;
        return new Response(null, { status: 204 });
      },
    });

    expect(await screen.findByText("Configurée le 20 octobre 2026.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Supprimer" }));

    expect(await screen.findByText("Non configurée")).toBeInTheDocument();
    expect(http.callsTo(REMOVE)).toHaveLength(1);
  });

  it("réinitialise le visage enregistré par la même modale (consentement, code puis capture)", async () => {
    const { http, user } = setup(ENROLLED, { [ENROLL]: () => json(200, ENROLLED) });

    await user.click(await screen.findByRole("button", { name: "Réinitialiser" }));
    expect(screen.getByRole("dialog", { name: "Réinitialiser la reconnaissance faciale" })).toHaveAttribute("open");
    await confirmWith(user, "123456");
    await film(user);

    await vi.waitFor(() => expect(http.callsTo(ENROLL)).toHaveLength(1));
    expect(http.callsTo(ENROLL)[0].form!.getAll("frames")).toHaveLength(3);
  });
});
