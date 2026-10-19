import { useState, type FormEvent } from "react";
import { api, ApiError, type Session } from "../lib/api";
import type { ServiceHealth } from "../lib/useServiceHealth";
import Brand from "./Brand";
import { StatusDot } from "./ServiceStatus";

const inputClass =
  "w-full rounded-lg border border-line bg-field px-3 py-2.5 text-sm text-ink placeholder:text-faint transition focus:border-teal focus:bg-white focus:ring-3 focus:ring-teal/15 focus:outline-none";

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

  // Cette méthode permet de soumettre le formulaire ; une inscription réussie enchaîne directement sur la connexion.
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "register") await api.register(email, fullName, password);
      onLogin(await api.login(email, password));
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
              }}
              className={`rounded-md py-1.5 transition ${mode === value ? "bg-white font-semibold text-ink shadow-sm" : "text-muted hover:text-ink"}`}
            >
              {value === "login" ? "Connexion" : "Créer un compte"}
            </button>
          ))}
        </div>
        <form onSubmit={submit} className="space-y-4">
          {mode === "register" && (
            <label className="block space-y-1.5 text-sm">
              <span className="font-medium text-muted">Nom complet</span>
              <input className={inputClass} value={fullName} onChange={(e) => setFullName(e.target.value)} required minLength={2} maxLength={80} />
            </label>
          )}
          <label className="block space-y-1.5 text-sm">
            <span className="font-medium text-muted">Email</span>
            <input className={inputClass} type="email" autoComplete="username" placeholder="vous@exemple.fr" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </label>
          <label className="block space-y-1.5 text-sm">
            <span className="font-medium text-muted">Mot de passe</span>
            <input
              className={inputClass}
              type="password"
              autoComplete={mode === "login" ? "current-password" : "new-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={mode === "register" ? 10 : 1}
            />
            {mode === "register" && <span className="text-xs text-muted">10 caractères minimum.</span>}
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
    </div>
  );
}
