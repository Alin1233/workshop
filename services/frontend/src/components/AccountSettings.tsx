import type { Session } from "../lib/api";
import MfaSettings from "./MfaSettings";
import RejectedCaptures from "./RejectedCaptures";

type Props = { session: Session; onBack: () => void; onSessionExpired: () => void };

// Cette méthode permet d'afficher la vue de paramétrage du compte (identité, puis section Sécurité avec la double
// authentification et, pour l'admin, les captures refusées par la reconnaissance faciale), accessible depuis l'en-tête.
export default function AccountSettings({ session, onBack, onSessionExpired }: Props) {
  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <button onClick={onBack} className="text-sm font-medium text-teal hover:text-teal-dark">
          ← Retour à mes comptes
        </button>
        <h1 className="mt-3 text-2xl font-semibold tracking-tight">Paramètres du compte</h1>
        <p className="mt-1 text-sm text-muted">
          {session.user.full_name} · {session.user.email}
        </p>
      </div>

      <section aria-labelledby="settings-security" className="space-y-3">
        <h2 id="settings-security" className="text-[11px] font-medium tracking-wider text-muted uppercase">
          Sécurité
        </h2>
        <MfaSettings token={session.token} onSessionExpired={onSessionExpired} />
      </section>

      {session.user.role === "admin" && (
        <section aria-labelledby="settings-soc" className="space-y-3">
          <h2 id="settings-soc" className="text-[11px] font-medium tracking-wider text-muted uppercase">
            Supervision
          </h2>
          <RejectedCaptures token={session.token} onSessionExpired={onSessionExpired} />
        </section>
      )}
    </div>
  );
}
