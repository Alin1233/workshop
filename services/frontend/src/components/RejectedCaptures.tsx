import { useCallback, useEffect, useState } from "react";
import { api, ApiError, type RejectedCapture } from "../lib/api";

const REASONS: Record<string, string> = {
  face_no_match: "Visage non reconnu",
  face_liveness_failed: "Défi de pose échoué",
  face_not_detected: "Aucun visage",
  face_multiple: "Plusieurs visages",
};
const timeFormat = new Intl.DateTimeFormat("fr-FR", { dateStyle: "short", timeStyle: "medium" });
const secondaryButton = "rounded-lg border border-line bg-white px-3 py-1 text-xs text-ink transition hover:bg-chip disabled:opacity-60";

type Props = { token: string; onSessionExpired: () => void };

// Cette méthode permet à l'admin (SOC) de passer en revue les captures refusées à la connexion par reconnaissance
// faciale (7 derniers jours) et d'afficher l'image d'une tentative ; chaque affichage est journalisé par l'auth-service.
export default function RejectedCaptures({ token, onSessionExpired }: Props) {
  const [captures, setCaptures] = useState<RejectedCapture[] | null>(null);
  const [shown, setShown] = useState<(RejectedCapture & { image: string }) | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Cette méthode permet de traiter un échec d'appel : session expirée renvoyée à la connexion, sinon message affiché.
  const fail = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) return onSessionExpired();
      setError(err instanceof ApiError ? err.message : "Erreur inattendue.");
    },
    [onSessionExpired],
  );

  useEffect(() => {
    api.rejectedCaptures(token).then(setCaptures, fail);
  }, [token, fail]);

  // Cette méthode permet d'afficher l'image d'une capture refusée, ou de la masquer si elle est déjà affichée.
  const toggle = async (id: string) => {
    if (shown?.id === id) return setShown(null);
    setBusy(true);
    setError(null);
    try {
      setShown(await api.rejectedCapture(token, id));
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="rounded-2xl border border-line bg-white p-5" data-testid="rejected-captures">
      <h2 className="font-semibold">Captures refusées</h2>
      <p className="mt-1 text-sm text-muted">
        Connexions par reconnaissance faciale refusées ces 7 derniers jours. Images chiffrées, effacées au-delà ; chaque
        consultation est journalisée.
      </p>
      {captures === null && !error && <span className="skeleton mt-3 block h-4 w-2/3" aria-busy />}
      {captures?.length === 0 && <p className="mt-3 text-sm text-muted">Aucune capture refusée.</p>}
      {captures && captures.length > 0 && (
        <ul className="mt-3 divide-y divide-line text-sm">
          {captures.map((capture) => (
            <li key={capture.id} className="py-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <p className="truncate font-medium">{capture.email}</p>
                  <p className="text-xs text-muted">
                    {timeFormat.format(new Date(capture.captured_at))} · {REASONS[capture.reason] ?? capture.reason}
                    {capture.score !== null && ` · similarité ${capture.score.toFixed(2)}`}
                    {capture.client_ip && ` · ${capture.client_ip}`}
                  </p>
                </div>
                <button onClick={() => toggle(capture.id)} disabled={busy} className={secondaryButton}>
                  {shown?.id === capture.id ? "Masquer" : "Voir"}
                </button>
              </div>
              {shown?.id === capture.id && (
                <img
                  src={shown.image}
                  alt={`Capture refusée pour ${capture.email}`}
                  className="mt-2 max-h-60 rounded-lg border border-line"
                />
              )}
            </li>
          ))}
        </ul>
      )}
      {error && (
        <p className="mt-3 rounded-lg border border-brick-line bg-brick-soft px-3 py-2 text-sm text-brick" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
