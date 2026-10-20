import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { json, mockFetch } from "../test/http";
import RejectedCaptures from "./RejectedCaptures";

const LIST = "GET /api/auth/admin/face-captures";
const CAPTURE = {
  id: "9b2f6a8e-0000-4000-8000-000000000001",
  email: "alice@exemple.fr",
  captured_at: "2026-10-20T09:15:00Z",
  reason: "face_no_match",
  score: 0.12,
  client_ip: "192.168.137.50",
};

describe("RejectedCaptures", () => {
  it("liste les captures refusées et affiche l'image demandée", async () => {
    const http = mockFetch({
      [LIST]: () => json(200, [CAPTURE]),
      [`${LIST}/${CAPTURE.id}`]: () => json(200, { ...CAPTURE, image: "data:image/jpeg;base64,/9j/" }),
    });
    render(<RejectedCaptures token="jeton-admin" onSessionExpired={vi.fn()} />);
    const user = userEvent.setup();

    expect(await screen.findByText("alice@exemple.fr")).toBeInTheDocument();
    expect(screen.getByText(/Visage non reconnu · similarité 0\.12 · 192\.168\.137\.50/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Voir" }));
    expect(await screen.findByAltText("Capture refusée pour alice@exemple.fr")).toHaveAttribute("src", "data:image/jpeg;base64,/9j/");
    expect(http.callsTo(`${LIST}/${CAPTURE.id}`)[0].headers.get("Authorization")).toBe("Bearer jeton-admin");

    await user.click(screen.getByRole("button", { name: "Masquer" }));
    expect(screen.queryByAltText(/Capture refusée/)).not.toBeInTheDocument();
  });

  it("indique l'absence de capture", async () => {
    mockFetch({ [LIST]: () => json(200, []) });
    render(<RejectedCaptures token="jeton-admin" onSessionExpired={vi.fn()} />);

    expect(await screen.findByText("Aucune capture refusée.")).toBeInTheDocument();
  });
});
