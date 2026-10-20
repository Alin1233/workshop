import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, ApiError, type FaceChallenge, type FaceStatus } from "../lib/api";
import { mfaCodeSchema, validate } from "../lib/validation";
import FaceCapture from "./FaceCapture";

const inputClass =
  "w-full rounded-lg border border-line bg-field px-3 py-2 text-sm text-ink placeholder:text-faint transition focus:border-teal focus:bg-white focus:ring-3 focus:ring-teal/15 focus:outline-none";
const invalidClass = "border-brick focus:border-brick focus:ring-brick/15";
const primaryButton =
  "rounded-lg bg-ink px-4 py-2 text-sm font-semibold text-white transition hover:bg-ink-2 disabled:opacity-60";
const secondaryButton = "rounded-lg border border-line bg-white px-4 py-2 text-sm text-ink transition hover:bg-chip disabled:opacity-60";
const dateFormat = new Intl.DateTimeFormat("fr-FR", { dateStyle: "long" });

type Step = "idle" | "consent" | "capture";
type Props = { token: string; onSessionExpired: () => void };

// Cette méthode permet de gérer le visage de référence, alternative au code à la connexion : dans une modale,
// consentement et code vérifiés d'abord, puis défi de pose filmé ; date de configuration, réinitialisation ou suppression.
export default function FaceSettings({ token, onSessionExpired }: Props) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [status, setStatus] = useState<FaceStatus | null>(null);
  const [step, setStep] = useState<Step>("idle");
  const [consent, setConsent] = useState(false);
  const [code, setCode] = useState("");
  const [challenge, setChallenge] = useState<FaceChallenge | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [captureError, setCaptureError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<{ consent?: string; code?: string }>({});
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

  // Cette méthode permet de relire l'état du visage enregistré auprès de l'auth-service.
  const load = useCallback(async () => {
    try {
      setStatus(await api.faceStatus(token));
    } catch (err) {
      fail(err);
    }
  }, [token, fail]);

  useEffect(() => {
    load();
  }, [load]);

  // La modale s'ouvre dès qu'un enregistrement commence et se ferme au retour à l'état de repos.
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (step !== "idle" && !dialog.open) dialog.showModal();
    if (step === "idle" && dialog.open) dialog.close();
  }, [step]);

  // Cette méthode permet de changer d'étape en effaçant le défi et les messages ; le retour au repos vide le formulaire.
  const reset = (next: Step = "idle") => {
    setStep(next);
    setChallenge(null);
    setCaptureError(null);
    setFieldErrors({});
    setError(null);
    if (next === "idle") {
      setConsent(false);
      setCode("");
    }
  };

  // Cette méthode permet d'exécuter une action réseau en gérant l'indicateur d'attente et les erreurs.
  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  // Cette méthode permet de faire vérifier le consentement et le code par le serveur, puis d'ouvrir la caméra
  // sur le défi de pose obtenu (le code n'a plus à survivre au temps de la capture).
  const begin = async (event: FormEvent) => {
    event.preventDefault();
    const checked = validate(mfaCodeSchema, { code });
    const errors = { consent: consent ? undefined : "Cochez la case pour continuer.", code: checked.errors?.code };
    if (errors.consent || errors.code) {
      setFieldErrors(errors);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setChallenge(await api.faceEnrollChallenge(token, checked.data?.code ?? code));
      setAttempt(0);
      setCaptureError(null);
      setStep("capture");
    } catch (err) {
      if (err instanceof ApiError && err.code === "mfa_invalid_code") setFieldErrors({ code: err.message });
      else fail(err);
    } finally {
      setBusy(false);
    }
  };

  // Cette méthode permet d'envoyer les captures ; un refus laisse réessayer sur le même défi, un défi épuisé ou
  // expiré renvoie au code.
  const enroll = async (frames: Blob[]) => {
    if (!challenge) return;
    setBusy(true);
    try {
      setStatus(await api.faceEnroll(token, challenge.challenge_id, frames));
      reset();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onSessionExpired();
      const message = err instanceof ApiError ? err.message : "Erreur inattendue.";
      if (err instanceof ApiError && err.code === "face_challenge_expired") {
        reset("consent");
        setCode("");
        setError(`${message} Saisissez un nouveau code.`);
      } else {
        setCaptureError(message);
      }
    } finally {
      setBusy(false);
    }
  };

  // Cette méthode permet de relancer la caméra sur le même défi après un refus des captures.
  const retry = () => {
    setCaptureError(null);
    setAttempt((value) => value + 1);
  };

  // Cette méthode permet de supprimer le visage enregistré ; la connexion revient au seul code.
  const remove = () =>
    run(async () => {
      await api.faceRemove(token);
      await load();
    });

  return (
    <div className="mt-4 space-y-3 border-t border-line pt-4" data-testid="face-settings">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-sm font-semibold">Reconnaissance faciale</h3>
        {status && (
          <span
            className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${status.enrolled ? "bg-teal-soft text-teal" : "bg-chip text-muted"}`}
          >
            {status.enrolled ? "Enregistrée" : "Non configurée"}
          </span>
        )}
      </div>

      {status && !status.enrolled && (
        <div className="space-y-3">
          <p className="text-sm text-muted">
            Connectez-vous avec votre visage plutôt qu'avec un code : la caméra de l'appareil prend trois photos, de face
            puis de profil. Le code reste utilisable à tout moment.
          </p>
          <button onClick={() => reset("consent")} className={primaryButton}>
            Configurer
          </button>
        </div>
      )}

      {status?.enrolled && (
        <div className="space-y-2">
          <p className="text-sm text-muted">
            Configurée{status.enrolled_at ? ` le ${dateFormat.format(new Date(status.enrolled_at))}` : ""}.
          </p>
          <div className="flex gap-2">
            <button onClick={() => reset("consent")} className={secondaryButton}>
              Réinitialiser
            </button>
            <button onClick={remove} disabled={busy} className={secondaryButton}>
              Supprimer
            </button>
          </div>
        </div>
      )}

      {step === "idle" && error && <ErrorMessage text={error} />}

      <dialog
        ref={dialogRef}
        aria-labelledby="face-dialog-title"
        onClose={() => step !== "idle" && reset()}
        className="m-auto max-h-[calc(100dvh-2rem)] w-[min(30rem,calc(100vw-2rem))] overflow-y-auto rounded-2xl border border-line bg-white p-5 text-ink shadow-xl backdrop:bg-ink/50"
      >
        <h3 id="face-dialog-title" className="mb-4 text-base font-semibold">
          {status?.enrolled ? "Réinitialiser la reconnaissance faciale" : "Enregistrer votre visage"}
        </h3>

        {step === "consent" && (
          <form onSubmit={begin} noValidate className="space-y-4">
            <div className="rounded-lg border border-line bg-field px-3 py-2 text-sm text-muted">
              <p className="font-medium text-ink">Ce qui est conservé</p>
              <ul className="mt-1 list-disc space-y-0.5 pl-5">
                <li>une empreinte numérique de votre visage, chiffrée (aucune photo n'est gardée) ;</li>
                <li>les photos d'une connexion refusée, gardées 7 jours pour l'équipe sécurité puis effacées.</li>
              </ul>
              <p className="mt-1">Vous pouvez supprimer votre visage à tout moment depuis cette page.</p>
            </div>
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                checked={consent}
                onChange={(e) => {
                  setConsent(e.target.checked);
                  setFieldErrors((prev) => ({ ...prev, consent: undefined }));
                }}
                className="mt-0.5"
                aria-invalid={!!fieldErrors.consent}
              />
              <span>J'accepte que mon visage soit enregistré pour me connecter.</span>
            </label>
            {fieldErrors.consent && <span className="block text-xs text-brick">{fieldErrors.consent}</span>}
            <label className="block space-y-1.5 text-sm">
              <span className="font-medium text-muted">Code de l'application (ou de secours)</span>
              <input
                className={`${inputClass} font-mono tracking-widest ${fieldErrors.code ? invalidClass : ""}`}
                autoComplete="one-time-code"
                placeholder="123456"
                value={code}
                onChange={(e) => {
                  setCode(e.target.value);
                  setFieldErrors((prev) => ({ ...prev, code: undefined }));
                }}
                maxLength={32}
                aria-invalid={!!fieldErrors.code}
              />
              {fieldErrors.code && <span className="block text-xs text-brick">{fieldErrors.code}</span>}
            </label>
            {error && <ErrorMessage text={error} />}
            <div className="flex gap-2">
              <button type="submit" disabled={busy} className={primaryButton}>
                {busy ? "Vérification…" : "Continuer"}
              </button>
              <button type="button" onClick={() => reset()} className={secondaryButton}>
                Annuler
              </button>
            </div>
          </form>
        )}

        {step === "capture" && challenge && !captureError && (
          <FaceCapture
            key={`${challenge.challenge_id}-${attempt}`}
            poses={challenge.poses}
            onCaptured={enroll}
            onCancel={() => reset()}
            busy={busy}
          />
        )}

        {step === "capture" && captureError && (
          <div className="space-y-3">
            <ErrorMessage text={captureError} />
            <div className="flex gap-2">
              <button type="button" onClick={retry} className={primaryButton}>
                Réessayer
              </button>
              <button type="button" onClick={() => reset()} className={secondaryButton}>
                Annuler
              </button>
            </div>
          </div>
        )}
      </dialog>
    </div>
  );
}

// Cette méthode permet d'afficher un message d'erreur annoncé aux lecteurs d'écran.
function ErrorMessage({ text }: { text: string }) {
  return (
    <p className="rounded-lg border border-brick-line bg-brick-soft px-3 py-2 text-sm text-brick" role="alert">
      {text}
    </p>
  );
}
