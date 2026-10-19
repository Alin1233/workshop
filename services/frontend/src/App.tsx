import { useState } from "react";
import { loadSession, saveSession, type Session } from "./lib/api";
import AuthScreen from "./components/AuthScreen";
import Dashboard from "./components/Dashboard";
import ServiceStatus from "./components/ServiceStatus";

// Cette méthode permet d'afficher l'écran de connexion ou l'espace client selon l'état de la session.
export default function App() {
  const [session, setSession] = useState<Session | null>(loadSession);

  // Cette méthode permet de mettre à jour la session en mémoire et dans le stockage de l'onglet.
  const updateSession = (next: Session | null) => {
    saveSession(next);
    setSession(next);
  };

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-4 py-3">
          <div className="flex items-center gap-2">
            <img src="/favicon.svg" alt="" className="h-8 w-8" />
            <div>
              <p className="font-semibold leading-tight">Resilience Pay</p>
              <p className="text-xs text-slate-500">Plateforme de paiement fictive — démonstrateur</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <ServiceStatus />
            {session && (
              <div className="flex items-center gap-3 text-sm">
                <span className="hidden text-slate-600 sm:inline">{session.user.full_name}</span>
                <button
                  onClick={() => updateSession(null)}
                  className="rounded-md border border-slate-300 px-3 py-1.5 hover:bg-slate-100"
                >
                  Déconnexion
                </button>
              </div>
            )}
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-4 py-8">
        {session ? (
          <Dashboard session={session} onSessionExpired={() => updateSession(null)} />
        ) : (
          <AuthScreen onLogin={updateSession} />
        )}
      </main>
    </div>
  );
}
