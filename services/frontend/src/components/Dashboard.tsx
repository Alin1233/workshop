import { useCallback, useEffect, useState } from "react";
import { api, ApiError, formatCents, type Account, type Session, type Transfer } from "../lib/api";
import TransferForm from "./TransferForm";

type Props = { session: Session; onSessionExpired: () => void };

// Cette méthode permet d'afficher l'espace client : solde, numéro de compte, formulaire de virement et historique.
export default function Dashboard({ session, onSessionExpired }: Props) {
  const [account, setAccount] = useState<Account | null>(null);
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Cette méthode permet de recharger compte et historique, et de déconnecter si le jeton n'est plus valide.
  const refresh = useCallback(async () => {
    try {
      const [acc, list] = await Promise.all([api.account(session.token), api.transfers(session.token)]);
      setAccount(acc);
      setTransfers(list);
      setError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onSessionExpired();
      setError(err instanceof ApiError ? err.message : "Erreur inattendue.");
    }
  }, [session.token, onSessionExpired]);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 10000);
    return () => clearInterval(timer);
  }, [refresh]);

  // Cette méthode permet de copier son numéro de compte pour le communiquer à un autre utilisateur.
  const copyAccountNumber = async () => {
    if (!account) return;
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(account.account_number);
    } else {
      // Hors contexte sécurisé (HTTP sur IP), l'API Clipboard n'existe pas : repli sur execCommand.
      const field = document.createElement("textarea");
      field.value = account.account_number;
      document.body.appendChild(field);
      field.select();
      document.execCommand("copy");
      field.remove();
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-6">
      {error && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800" role="alert">
          {error}
        </div>
      )}
      <section className="grid gap-6 md:grid-cols-2">
        <div className="rounded-xl bg-gradient-to-br from-indigo-600 to-indigo-800 p-6 text-white shadow-sm">
          <p className="text-sm text-indigo-200">Solde disponible</p>
          <p className="mt-1 text-4xl font-semibold tabular-nums" data-testid="balance">
            {account ? formatCents(account.balance_cents) : "—"}
          </p>
          <div className="mt-6 flex items-center justify-between text-sm">
            <div>
              <p className="text-indigo-200">Numéro de compte</p>
              <p className="font-mono tracking-wider" data-testid="account-number">{account?.account_number ?? "—"}</p>
            </div>
            <button onClick={copyAccountNumber} className="rounded-md bg-white/15 px-3 py-1.5 hover:bg-white/25">
              {copied ? "Copié ✓" : "Copier"}
            </button>
          </div>
        </div>
        <TransferForm token={session.token} onDone={refresh} onSessionExpired={onSessionExpired} />
      </section>

      <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3">
          <h2 className="font-medium">Derniers mouvements</h2>
          <button onClick={refresh} className="text-sm text-indigo-600 hover:underline">Actualiser</button>
        </div>
        {transfers.length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-slate-500">Aucun mouvement pour le moment.</p>
        ) : (
          <ul className="divide-y divide-slate-100" data-testid="transfer-list">
            {transfers.map((t) => (
              <li key={t.id} className="flex items-center justify-between gap-4 px-5 py-3 text-sm">
                <div className="min-w-0">
                  <p className="truncate font-medium">{t.label || (t.direction === "debit" ? "Virement émis" : "Virement reçu")}</p>
                  <p className="truncate text-xs text-slate-500">
                    {t.direction === "debit" ? "Vers" : "De"} {t.counterparty_name} · {t.counterparty_account_number} ·{" "}
                    {new Date(t.created_at).toLocaleString("fr-FR")}
                  </p>
                </div>
                <span className={`shrink-0 font-semibold tabular-nums ${t.direction === "debit" ? "text-slate-900" : "text-emerald-600"}`}>
                  {t.direction === "debit" ? "−" : "+"}
                  {formatCents(t.amount_cents)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
