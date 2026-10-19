import { useState, type FormEvent } from "react";
import { api, ApiError, type Session } from "../lib/api";

const inputClass =
  "w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200";

// Cette méthode permet de se connecter ou de créer un compte, puis de transmettre la session obtenue.
export default function AuthScreen({ onLogin }: { onLogin: (session: Session) => void }) {
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
    <div className="mx-auto max-w-sm rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="mb-6 grid grid-cols-2 rounded-lg bg-slate-100 p-1 text-sm">
        {(["login", "register"] as const).map((value) => (
          <button
            key={value}
            type="button"
            onClick={() => {
              setMode(value);
              setError(null);
            }}
            className={`rounded-md py-1.5 ${mode === value ? "bg-white font-medium shadow-sm" : "text-slate-600"}`}
          >
            {value === "login" ? "Connexion" : "Créer un compte"}
          </button>
        ))}
      </div>
      <form onSubmit={submit} className="space-y-4">
        {mode === "register" && (
          <label className="block space-y-1 text-sm">
            <span className="text-slate-700">Nom complet</span>
            <input className={inputClass} value={fullName} onChange={(e) => setFullName(e.target.value)} required minLength={2} maxLength={80} />
          </label>
        )}
        <label className="block space-y-1 text-sm">
          <span className="text-slate-700">Email</span>
          <input className={inputClass} type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </label>
        <label className="block space-y-1 text-sm">
          <span className="text-slate-700">Mot de passe</span>
          <input
            className={inputClass}
            type="password"
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={mode === "register" ? 10 : 1}
          />
          {mode === "register" && <span className="text-xs text-slate-500">10 caractères minimum.</span>}
        </label>
        {error && <p className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700" role="alert">{error}</p>}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-md bg-indigo-600 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
        >
          {busy ? "Patientez…" : mode === "login" ? "Se connecter" : "Créer mon compte"}
        </button>
      </form>
      <p className="mt-4 text-center text-xs text-slate-500">Environnement fictif : n'utilisez aucune donnée réelle.</p>
    </div>
  );
}
