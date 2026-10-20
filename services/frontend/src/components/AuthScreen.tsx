import { useState, type FormEvent } from "react";
import { api, ApiError, type Session } from "../lib/api";
import type { ServiceHealth } from "../lib/useServiceHealth";
import Brand from "./Brand";
import { StatusDot } from "./ServiceStatus";
import {
  EMAIL_MAX,
  FULL_NAME_MAX,
  loginSchema,
  mfaCodeSchema,
  PASSWORD_MAX,
  registerSchema,
  validate,
  type FieldErrors,
} from "../lib/validation";

const inputClass =
  "w-full rounded-lg border border-line bg-field px-3 py-2.5 text-sm text-ink placeholder:text-faint transition focus:border-teal focus:bg-white focus:ring-3 focus:ring-teal/15 focus:outline-none";

type Errors = FieldErrors<{ fullName: string; email: string; password: string }>;

const invalidClass = "border-brick focus:border-brick focus:ring-brick/15";

type Props = { onLogin: (session: Session) => void; health: ServiceHealth };

// Cette méthode permet de se connecter ou de créer un compte, puis de transmettre la session obtenue ;
// le panneau de marque affiche l'état des services avant même la connexion.
export default function AuthScreen({ onLogin, health }: Props) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Errors>({});
  const [challenge, setChallenge] = useState<string | null>(null);

  // Cette méthode permet de mettre à jour un champ et d'effacer son message d'erreur.
  const edit = (field: keyof Errors, setter: (value: string) => void) => (value: string) => {
    setter(value);
    setFieldErrors((prev) => ({ ...prev, [field]: undefined }));
  };

  // Cette méthode permet de soumettre le formulaire ; une inscription réussie enchaîne directement sur la connexion.
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    const register = mode === "register" ? validate(registerSchema, { fullName, email, password }) : null;
    const login = validate(loginSchema, { email, password });
    const errors = register ? register.errors : login.errors;
    if (errors || !login.data) {
      setFieldErrors(errors ?? {});
      return;
    }
    setBusy(true);
    try {
      if (register?.data) await api.register(register.data.email, register.data.fullName, register.data.password);
      const result = await api.login(login.data.email, login.data.password);
      if ("mfaToken" in result) {
        setPassword("");
        setChallenge(result.mfaToken);
      } else {
        onLogin(result);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Erreur inattendue.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid w-full max-w-3xl overflow-hidden rounded-2xl border border-line bg-white shadow-[0_20px_50px_-30px_rgb(14_26_36/0.45)] md:grid-cols-2">
      <aside className="flex flex-col justify-between gap-8 bg-[radial-gradient(120%_120%_at_0%_100%,var(--color-ink-glow)_0%,var(--color-ink)_60%)] p-7 text-white md:min-h-105">
        <Brand onDark />
        <div>
          <h1 className="text-2xl leading-tight font-semibold tracking-tight text-balance">
            Vos virements tiennent, même quand le réseau flanche.
          </h1>
          <p className="mt-3 text-sm leading-relaxed text-mist">Démonstrateur fictif : n'utilisez aucune donnée réelle.</p>
        </div>
        <div className="flex flex-wrap gap-2 text-xs text-[#cfe0ea]" data-testid="auth-service-status">
          {([["Authentification", health.auth], ["Paiements", health.payments]] as const).map(([label, ok]) => (
            <span key={label} className="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/5 px-3 py-1">
              <StatusDot ok={ok} />
              {label}
              <span className="text-mist">{ok === null ? "…" : ok ? "opérationnel" : "perturbé"}</span>
            </span>
          ))}
        </div>
      </aside>

      {challenge ? (
        <MfaStep
          mfaToken={challenge}
          onLogin={onLogin}
          onCancel={(message) => {
            setChallenge(null);
            setError(message);
          }}
        />
      ) : (
        <div className="p-7">
          <div className="mb-6 grid grid-cols-2 rounded-lg bg-chip p-1 text-sm" role="tablist">
            {(["login", "register"] as const).map((value) => (
              <button
                key={value}
                type="button"
                role="tab"
                aria-selected={mode === value}
                onClick={() => {
                  setMode(value);
                  setError(null);
                  setFieldErrors({});
                }}
                className={`rounded-md py-1.5 transition ${mode === value ? "bg-white font-semibold text-ink shadow-sm" : "text-muted hover:text-ink"}`}
              >
                {value === "login" ? "Connexion" : "Créer un compte"}
              </button>
            ))}
          </div>
          <form onSubmit={submit} noValidate className="space-y-4">
            {mode === "register" && (
              <label className="block space-y-1.5 text-sm">
                <span className="font-medium text-muted">Nom complet</span>
                <input
                  className={`${inputClass} ${fieldErrors.fullName ? invalidClass : ""}`}
                  value={fullName}
                  onChange={(e) => edit("fullName", setFullName)(e.target.value)}
                  maxLength={FULL_NAME_MAX}
                  aria-invalid={!!fieldErrors.fullName}
                />
                {fieldErrors.fullName && <span className="block text-xs text-brick">{fieldErrors.fullName}</span>}
              </label>
            )}
            <label className="block space-y-1.5 text-sm">
              <span className="font-medium text-muted">Email</span>
              <input
                className={`${inputClass} ${fieldErrors.email ? invalidClass : ""}`}
                type="email"
                autoComplete="username"
                placeholder="vous@exemple.fr"
                value={email}
                onChange={(e) => edit("email", setEmail)(e.target.value)}
                maxLength={EMAIL_MAX}
                aria-invalid={!!fieldErrors.email}
              />
              {fieldErrors.email && <span className="block text-xs text-brick">{fieldErrors.email}</span>}
            </label>
            <label className="block space-y-1.5 text-sm">
              <span className="font-medium text-muted">Mot de passe</span>
              <input
                className={`${inputClass} ${fieldErrors.password ? invalidClass : ""}`}
                type="password"
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                value={password}
                onChange={(e) => edit("password", setPassword)(e.target.value)}
                maxLength={PASSWORD_MAX}
                aria-invalid={!!fieldErrors.password}
              />
              {fieldErrors.password ? (
                <span className="block text-xs text-brick">{fieldErrors.password}</span>
              ) : (
                mode === "register" && <span className="text-xs text-muted">10 caractères minimum.</span>
              )}
            </label>
            {error && (
              <p className="rounded-lg border border-brick-line bg-brick-soft px-3 py-2 text-sm text-brick" role="alert">
                {error}
              </p>
            )}
            <button
              type="submit"
              disabled={busy}
              className="w-full rounded-lg bg-ink py-2.5 text-sm font-semibold text-white transition hover:bg-ink-2 disabled:opacity-60"
            >
              {busy ? "Patientez…" : mode === "login" ? "Se connecter" : "Créer mon compte"}
            </button>
          </form>
        </div>
      )}
    </div>
  );
}

type MfaStepProps = { mfaToken: string; onLogin: (session: Session) => void; onCancel: (message: string | null) => void };

// Cette méthode permet de saisir le second facteur (code de l'appli ou code de secours) après un mot de passe valide ;
// une étape expirée (5 minutes ou 5 essais) ramène au formulaire de connexion avec le motif.
function MfaStep({ mfaToken, onLogin, onCancel }: MfaStepProps) {
  const [code, setCode] = useState("");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Cette méthode permet de vérifier le code saisi puis d'ouvrir la session.
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    const checked = validate(mfaCodeSchema, { code });
    if (!checked.data) {
      setFieldError(checked.errors.code ?? null);
      return;
    }
    setBusy(true);
    try {
      onLogin(await api.verifyMfa(mfaToken, checked.data.code));
    } catch (err) {
      if (err instanceof ApiError && err.code === "mfa_challenge_expired") return onCancel(err.message);
      setError(err instanceof ApiError ? err.message : "Erreur inattendue.");
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="p-7">
      <h2 className="text-lg font-semibold">Double authentification</h2>
      <p className="mt-1 mb-6 text-sm text-muted">
        Saisissez le code à 6 chiffres affiché par votre application d'authentification, ou l'un de vos codes de secours.
      </p>
      <form onSubmit={submit} noValidate className="space-y-4">
        <label className="block space-y-1.5 text-sm">
          <span className="font-medium text-muted">Code de vérification</span>
          <input
            className={`${inputClass} font-mono tracking-widest ${fieldError ? invalidClass : ""}`}
            autoComplete="one-time-code"
            autoFocus
            placeholder="123456"
            value={code}
            onChange={(e) => {
              setCode(e.target.value);
              setFieldError(null);
            }}
            maxLength={32}
            aria-invalid={!!fieldError}
          />
          {fieldError && <span className="block text-xs text-brick">{fieldError}</span>}
        </label>
        {error && (
          <p className="rounded-lg border border-brick-line bg-brick-soft px-3 py-2 text-sm text-brick" role="alert">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-lg bg-ink py-2.5 text-sm font-semibold text-white transition hover:bg-ink-2 disabled:opacity-60"
        >
          {busy ? "Patientez…" : "Vérifier"}
        </button>
        <button type="button" onClick={() => onCancel(null)} className="w-full text-sm text-muted hover:text-ink">
          ← Retour à la connexion
        </button>
      </form>
    </div>
  );
}
