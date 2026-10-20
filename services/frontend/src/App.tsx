import { useCallback, useState } from "react";
import { loadSession, saveSession, type Session } from "./lib/api";
import { useServiceHealth } from "./lib/useServiceHealth";
import AccountSettings from "./components/AccountSettings";
import AuthScreen from "./components/AuthScreen";
import Brand from "./components/Brand";
import Dashboard from "./components/Dashboard";
import ServiceStatus from "./components/ServiceStatus";

// Cette méthode permet de calculer les initiales affichées dans l'avatar à partir du nom complet.
function initials(fullName: string): string {
  return fullName
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join("");
}

// Cette méthode permet d'afficher l'écran de connexion ou l'espace client selon l'état de la session.
export default function App() {
  const [session, setSession] = useState<Session | null>(loadSession);
  const [view, setView] = useState<"dashboard" | "settings">("dashboard");
  const health = useServiceHealth();

  // Cette méthode permet de mettre à jour la session en mémoire et dans le stockage de l'onglet ;
  // toute nouvelle session (ou déconnexion) revient au tableau de bord.
  const updateSession = useCallback((next: Session | null) => {
    saveSession(next);
    setSession(next);
    setView("dashboard");
  }, []);
  // Rappel stable : l'App se réaffiche à chaque sondage /health (5 s) ; un rappel recréé à chaque rendu relançait
  // le rechargement du tableau de bord à chaque sondage au lieu de toutes les 10 s.
  const expireSession = useCallback(() => updateSession(null), [updateSession]);

  if (!session) {
    return (
      <main className="grid min-h-screen place-items-center px-4 py-10">
        <AuthScreen onLogin={updateSession} health={health} />
      </main>
    );
  }

  return (
    <div className="min-h-screen">
      <header className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-4 pt-5 pb-2">
        <Brand />
        <div className="flex items-center gap-3">
          <ServiceStatus state={health.state} />
          <span className="hidden text-sm text-muted md:inline">{session.user.full_name}</span>
          <span
            className="grid h-8 w-8 place-items-center rounded-full bg-ink-2 text-xs font-semibold text-white"
            aria-hidden
            title={session.user.full_name}
          >
            {initials(session.user.full_name)}
          </span>
          <button
            onClick={() => setView("settings")}
            aria-current={view === "settings" ? "page" : undefined}
            className={`rounded-lg border border-line px-3 py-1.5 text-sm text-ink transition-colors hover:bg-chip ${view === "settings" ? "bg-chip" : "bg-white"}`}
          >
            Paramètres
          </button>
          <button
            onClick={() => updateSession(null)}
            className="rounded-lg border border-line bg-white px-3 py-1.5 text-sm text-ink transition-colors hover:bg-chip"
          >
            Déconnexion
          </button>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-4 py-6">
        {view === "settings" ? (
          <AccountSettings session={session} onBack={() => setView("dashboard")} onSessionExpired={expireSession} />
        ) : (
          <Dashboard session={session} health={health} onSessionExpired={expireSession} />
        )}
      </main>
    </div>
  );
}
