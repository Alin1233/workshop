import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, ApiError, type MfaSetup, type MfaStatus } from "../lib/api";
import { mfaCodeSchema, mfaDisableSchema, PASSWORD_MAX, validate } from "../lib/validation";
import FaceSettings from "./FaceSettings";

const inputClass =
  "w-full rounded-lg border border-line bg-field px-3 py-2 text-sm text-ink placeholder:text-faint transition focus:border-teal focus:bg-white focus:ring-3 focus:ring-teal/15 focus:outline-none";
const invalidClass = "border-brick focus:border-brick focus:ring-brick/15";
const primaryButton =
  "rounded-lg bg-ink px-4 py-2 text-sm font-semibold text-white transition hover:bg-ink-2 disabled:opacity-60";
const secondaryButton = "rounded-lg border border-line bg-white px-4 py-2 text-sm text-ink transition hover:bg-chip disabled:opacity-60";

type Step = "idle" | "setup" | "codes" | "disable";
type Props = { token: string; onSessionExpired: () => void };

// Cette méthode permet de grouper la clé TOTP par 4 caractères pour la saisir sans erreur dans une appli.
function groupSecret(secret: string): string {
  return secret.match(/.{1,4}/g)?.join(" ") ?? secret;
}

// Cette méthode permet de gérer la double authentification du compte : activation par QR code et premier code,
// affichage unique des codes de secours, désactivation confirmée par mot de passe et code (sauf compte admin) ;
// une fois active, le visage peut être enregistré comme alternative au code.
export default function MfaSettings({ token, onSessionExpired }: Props) {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [step, setStep] = useState<Step>("idle");
  const [setup, setSetup] = useState<MfaSetup | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [fieldErrors, setFieldErrors] = useState<{ code?: string; password?: string }>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  // Cette méthode permet de traiter un échec d'appel : session expirée renvoyée à la connexion, sinon message affiché.
  const fail = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) return onSessionExpired();
      setError(err instanceof ApiError ? err.message : "Erreur inattendue.");
    },
    [onSessionExpired],
  );

  // Cette méthode permet de relire l'état de la double authentification auprès de l'auth-service.
  const load = useCallback(async () => {
    try {
      setStatus(await api.mfaStatus(token));
    } catch (err) {
      fail(err);
    }
  }, [token, fail]);

  useEffect(() => {
    load();
  }, [load]);

  // Cette méthode permet de revenir à l'état de repos en effaçant toute saisie en cours.
  const reset = (next: Step = "idle") => {
    setStep(next);
    setCode("");
    setPassword("");
    setFieldErrors({});
    setError(null);
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

  // Cette méthode permet de demander un nouveau secret et d'afficher le QR code à scanner.
  const startSetup = () =>
    run(async () => {
      setSetup(await api.mfaSetup(token));
      reset("setup");
    });

  // Cette méthode permet de confirmer l'activation avec le premier code de l'appli, puis d'afficher les codes de secours.
  const activate = (event: FormEvent) => {
    event.preventDefault();
    const checked = validate(mfaCodeSchema, { code });
    if (!checked.data || !/^\d{6}$/.test(checked.data.code)) {
      setFieldErrors({ code: "Saisissez le code à 6 chiffres affiché par l'application." });
      return;
    }
    const value = checked.data.code;
    return run(async () => {
      setRecoveryCodes(await api.mfaActivate(token, value));
      setSetup(null);
      reset("codes");
      await load();
    });
  };

  // Cette méthode permet de désactiver la double authentification après confirmation du mot de passe et d'un code.
  const disable = (event: FormEvent) => {
    event.preventDefault();
    const checked = validate(mfaDisableSchema, { password, code });
    if (!checked.data) {
      setFieldErrors(checked.errors);
      return;
    }
    const { password: confirmed, code: value } = checked.data;
    return run(async () => {
      await api.mfaDisable(token, confirmed, value);
      reset();
      await load();
    });
  };

  // Cette méthode permet de copier les codes de secours pour les ranger dans un gestionnaire de mots de passe.
  const copyCodes = async () => {
    await navigator.clipboard?.writeText(recoveryCodes.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const codeField = (label: string, autoFocus = false) => (
    <label className="block space-y-1.5 text-sm">
      <span className="font-medium text-muted">{label}</span>
      <input
        className={`${inputClass} font-mono tracking-widest ${fieldErrors.code ? invalidClass : ""}`}
        autoComplete="one-time-code"
        autoFocus={autoFocus}
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
  );

  return (
    <section className="rounded-2xl border border-line bg-white p-5" data-testid="mfa-settings">
      <div className="flex items-center justify-between gap-3">
        <h2 className="font-semibold">Double authentification</h2>
        {status && (
          <span
            className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${status.enabled ? "bg-teal-soft text-teal" : "bg-chip text-muted"}`}
          >
            {status.enabled ? "Activée" : "Désactivée"}
          </span>
        )}
      </div>

      {status === null && !error && <span className="skeleton mt-3 block h-4 w-2/3" aria-busy />}

      {status && step === "idle" && !status.enabled && (
        <div className="mt-2 space-y-3">
          <p className="text-sm text-muted">
            En plus du mot de passe, un code à usage unique généré par une application d'authentification (Google
            Authenticator, Microsoft Authenticator, FreeOTP…) sera demandé à chaque connexion.
          </p>
          <button onClick={startSetup} disabled={busy} className={primaryButton}>
            Activer
          </button>
        </div>
      )}

      {status && step === "idle" && status.enabled && (
        <div className="mt-2 space-y-3">
          <p className="text-sm text-muted">
            Un code est demandé à chaque connexion.{" "}
            <span className={status.recovery_codes_remaining <= 2 ? "font-medium text-brick" : ""}>
              {status.recovery_codes_remaining} code{status.recovery_codes_remaining > 1 ? "s" : ""} de secours restant
              {status.recovery_codes_remaining > 1 ? "s" : ""}.
            </span>
          </p>
          {status.required ? (
            <p className="text-xs text-muted">Obligatoire pour le compte administrateur.</p>
          ) : (
            <button onClick={() => reset("disable")} className={secondaryButton}>
              Désactiver
            </button>
          )}
          <FaceSettings token={token} onSessionExpired={onSessionExpired} />
        </div>
      )}

      {step === "setup" && setup && (
        <form onSubmit={activate} noValidate className="mt-3 space-y-4">
          <ol className="list-decimal space-y-1 pl-5 text-sm text-muted">
            <li>Scannez ce QR code avec votre application d'authentification.</li>
            <li>Saisissez le code à 6 chiffres qu'elle affiche.</li>
          </ol>
          <div className="flex flex-wrap items-center gap-4">
            <img src={setup.qr_code} alt="QR code à scanner avec l'application d'authentification" className="h-40 w-40 rounded-lg border border-line" />
            <div className="min-w-0 text-xs text-muted">
              <p>Impossible de scanner ? Saisissez cette clé :</p>
              <p className="mt-1 font-mono text-sm break-all text-ink" data-testid="mfa-secret">
                {groupSecret(setup.secret)}
              </p>
            </div>
          </div>
          {codeField("Code de l'application", true)}
          {error && <ErrorMessage text={error} />}
          <div className="flex gap-2">
            <button type="submit" disabled={busy} className={primaryButton}>
              {busy ? "Patientez…" : "Confirmer l'activation"}
            </button>
            <button type="button" onClick={() => reset()} className={secondaryButton}>
              Annuler
            </button>
          </div>
        </form>
      )}

      {step === "codes" && (
        <div className="mt-3 space-y-3">
          <p className="rounded-lg border border-amber-line bg-amber-soft px-3 py-2 text-sm text-amber-ink">
            Notez ces codes de secours maintenant : ils ne seront plus affichés. Chacun permet une connexion si vous perdez
            votre téléphone.
          </p>
          <ul className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-sm" data-testid="recovery-codes">
            {recoveryCodes.map((value) => (
              <li key={value}>{value}</li>
            ))}
          </ul>
          <div className="flex gap-2">
            <button onClick={() => reset()} className={primaryButton}>
              J'ai noté mes codes
            </button>
            {navigator.clipboard && (
              <button onClick={copyCodes} className={secondaryButton}>
                {copied ? "Copiés ✓" : "Copier"}
              </button>
            )}
          </div>
        </div>
      )}

      {step === "disable" && (
        <form onSubmit={disable} noValidate className="mt-3 space-y-4">
          <p className="text-sm text-muted">
            Confirmez avec votre mot de passe et un code de l'application (ou de secours).
            {status?.face_enrolled && " Votre visage enregistré sera aussi supprimé."}
          </p>
          <label className="block space-y-1.5 text-sm">
            <span className="font-medium text-muted">Mot de passe</span>
            <input
              className={`${inputClass} ${fieldErrors.password ? invalidClass : ""}`}
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                setFieldErrors((prev) => ({ ...prev, password: undefined }));
              }}
              maxLength={PASSWORD_MAX}
              aria-invalid={!!fieldErrors.password}
            />
            {fieldErrors.password && <span className="block text-xs text-brick">{fieldErrors.password}</span>}
          </label>
          {codeField("Code de vérification")}
          {error && <ErrorMessage text={error} />}
          <div className="flex gap-2">
            <button type="submit" disabled={busy} className={primaryButton}>
              {busy ? "Patientez…" : "Confirmer la désactivation"}
            </button>
            <button type="button" onClick={() => reset()} className={secondaryButton}>
              Annuler
            </button>
          </div>
        </form>
      )}

      {step === "idle" && error && <div className="mt-3"><ErrorMessage text={error} /></div>}
    </section>
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
