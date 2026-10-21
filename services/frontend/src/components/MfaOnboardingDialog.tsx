import { useEffect, useRef } from "react";
import type { Session } from "../lib/api";
import MfaSettings from "./MfaSettings";

type Props = { session: Session; onClose: () => void; onSessionExpired: () => void };

// Cette méthode permet de proposer l'activation de la double authentification dans une modale à la première connexion
// d'un compte qui ne l'a pas : parcours complet sur place, fermé par « Plus tard » ou une fois les codes de secours notés.
export default function MfaOnboardingDialog({ session, onClose, onSessionExpired }: Props) {
  const dialogRef = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog && !dialog.open) dialog.showModal();
  }, []);

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby="mfa-onboarding-title"
      // Échap ne ferme pas : les codes de secours affichés une seule fois seraient perdus ; « Plus tard » reste proposé.
      onCancel={(event) => event.preventDefault()}
      className="m-auto max-h-[calc(100dvh-2rem)] w-[min(30rem,calc(100vw-2rem))] overflow-y-auto rounded-2xl border border-line bg-white p-5 text-ink shadow-xl backdrop:bg-ink/50"
    >
      <h2 id="mfa-onboarding-title" className="text-base font-semibold">
        Protégez votre compte
      </h2>
      <p className="mt-1 text-sm text-muted">
        Bienvenue {session.user.full_name.split(/\s+/)[0]} ! Activez la double authentification pour qu'un mot de passe
        dérobé ne suffise pas à accéder à vos comptes. Vous pourrez aussi le faire plus tard depuis les Paramètres.
      </p>
      <MfaSettings token={session.token} onSessionExpired={onSessionExpired} onClose={onClose} />
    </dialog>
  );
}
