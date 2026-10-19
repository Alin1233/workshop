import { useCallback, useEffect, useState } from "react";
import {
  api,
  ApiError,
  formatAccountNumber,
  formatCents,
  groupTransfersByDay,
  monthTotals,
  splitCents,
  type Account,
  type Session,
  type Transfer,
} from "../lib/api";
import type { ServiceHealth } from "../lib/useServiceHealth";
import IncidentBanner from "./IncidentBanner";
import TransferForm from "./TransferForm";

type Props = { session: Session; health: ServiceHealth; onSessionExpired: () => void };

const timeFormat = new Intl.DateTimeFormat("fr-FR", { hour: "2-digit", minute: "2-digit" });
const monthFormat = new Intl.DateTimeFormat("fr-FR", { month: "short" });

// Cette méthode permet d'afficher l'espace client : bandeau d'incident, solde, numéro de compte,
// formulaire de virement et historique groupé par jour.
export default function Dashboard({ session, health, onSessionExpired }: Props) {
  const [account, setAccount] = useState<Account | null>(null);
  const [transfers, setTransfers] = useState<Transfer[] | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Cette méthode permet de recharger compte et historique, et de déconnecter si le jeton n'est plus valide.
  const refresh = useCallback(async () => {
    try {
      const [acc, list] = await Promise.all([api.account(session.token), api.transfers(session.token)]);
      setAccount(acc);
      setTransfers(list);
      setLastUpdated(new Date());
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

  const balance = account ? splitCents(account.balance_cents) : null;
  const totals = transfers ? monthTotals(transfers) : null;
  const month = monthFormat.format(new Date()).replace(".", "");
  // Le bandeau d'incident explique déjà une panne : l'erreur de rafraîchissement n'est montrée seule que hors incident.
  const showError = error && (health.state === "ok" || health.state === "checking");

  return (
    <div className="space-y-4">
      <IncidentBanner health={health} lastUpdated={lastUpdated} />
      {showError && (
        <div className="rounded-xl border border-amber-line bg-amber-soft px-4 py-3 text-sm text-amber-ink" role="alert">
          {error}
        </div>
      )}

      {/* minmax(0, …) : sans plancher à 0, un libellé long sans espace élargit la colonne au-delà de l'écran. */}
      <div className="grid items-start gap-4 md:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-4">
          <section className="relative overflow-hidden rounded-2xl bg-[radial-gradient(120%_140%_at_100%_0%,var(--color-ink-glow)_0%,var(--color-ink)_55%)] p-6 text-white">
            <span aria-hidden className="absolute -right-12 -bottom-16 h-52 w-52 rounded-full border-[32px] border-mint/8" />
            <p className="text-[11px] font-medium tracking-wider text-mist uppercase">Solde disponible</p>
            <p className="mt-1 text-4xl font-semibold tracking-tight tabular-nums" data-testid="balance">
              {balance ? (
                <>
                  {balance.units}
                  <span className="text-xl font-medium text-mist">{balance.decimals}</span>
                </>
              ) : (
                <span className="skeleton inline-block h-9 w-44 bg-white/10 align-middle" />
              )}
            </p>
            <dl className="mt-4 flex gap-6 text-xs tabular-nums">
              <div>
                <dt className="tracking-wider text-mist uppercase">Entrées · {month}</dt>
                <dd className="mt-0.5 text-sm font-semibold text-mint">{totals ? `+ ${formatCents(totals.creditCents)}` : "…"}</dd>
              </div>
              <div>
                <dt className="tracking-wider text-mist uppercase">Sorties · {month}</dt>
                <dd className="mt-0.5 text-sm font-semibold">{totals ? `− ${formatCents(totals.debitCents)}` : "…"}</dd>
              </div>
            </dl>
            <div className="relative mt-5 flex items-center justify-between gap-3 rounded-lg bg-white/[0.06] px-3 py-2.5">
              <div className="min-w-0">
                <p className="text-[11px] tracking-wider text-mist uppercase">N° de compte</p>
                <p className="truncate font-mono tracking-widest" data-testid="account-number" data-value={account?.account_number}>
                  {account ? formatAccountNumber(account.account_number) : "…"}
                </p>
              </div>
              <button
                onClick={copyAccountNumber}
                disabled={!account}
                className="shrink-0 rounded-md bg-white/10 px-3 py-1.5 text-xs font-medium transition hover:bg-white/20 disabled:opacity-50"
              >
                {copied ? "Copié ✓" : "Copier"}
              </button>
            </div>
          </section>

          <section className="rounded-2xl border border-line bg-white p-5">
            <div className="flex items-center justify-between">
              <h2 className="font-semibold">Derniers mouvements</h2>
              <button onClick={refresh} className="text-sm font-medium text-teal hover:text-teal-dark">
                Actualiser ↻
              </button>
            </div>
            <TransferHistory transfers={transfers} />
          </section>
        </div>

        <div className="min-w-0 md:sticky md:top-4">
          <TransferForm token={session.token} onDone={refresh} onSessionExpired={onSessionExpired} />
        </div>
      </div>
    </div>
  );
}

// Cette méthode permet d'afficher l'historique groupé par jour, avec des squelettes pendant le premier chargement.
function TransferHistory({ transfers }: { transfers: Transfer[] | null }) {
  if (transfers === null) {
    return (
      <div className="mt-4 space-y-4" aria-busy>
        {[0, 1, 2].map((i) => (
          <div key={i} className="flex items-center gap-3">
            <span className="skeleton h-8 w-8 rounded-full" />
            <div className="flex-1 space-y-1.5">
              <span className="skeleton block h-3 w-2/3" />
              <span className="skeleton block h-2.5 w-1/3" />
            </div>
          </div>
        ))}
      </div>
    );
  }
  if (transfers.length === 0) {
    return (
      <div className="py-10 text-center">
        <p className="text-sm font-medium">Aucun mouvement pour le moment</p>
        <p className="mt-1 text-xs text-muted">Partagez votre numéro de compte ou envoyez votre premier virement.</p>
      </div>
    );
  }
  return (
    <div data-testid="transfer-list">
      {groupTransfersByDay(transfers).map((group) => (
        <div key={group.label}>
          <p className="mt-4 mb-1 text-[11px] font-medium tracking-wider text-muted uppercase">{group.label}</p>
          <ul>
            {group.items.map((t) => {
              const credit = t.direction === "credit";
              return (
                <li key={t.id} className="flex items-center gap-3 border-t border-line-soft py-2.5 text-sm">
                  <span
                    aria-hidden
                    className={`grid h-8 w-8 shrink-0 place-items-center rounded-full font-bold ${credit ? "bg-teal-soft text-teal" : "bg-chip text-ink"}`}
                  >
                    {credit ? "↓" : "↑"}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-medium" title={t.label || undefined}>{t.label || (credit ? "Virement reçu" : "Virement émis")}</p>
                    <p className="truncate text-xs text-muted" title={t.counterparty_account_number}>
                      {credit ? "De" : "Vers"} {t.counterparty_name} · {timeFormat.format(new Date(t.created_at))}
                    </p>
                  </div>
                  <span className={`shrink-0 font-semibold whitespace-nowrap tabular-nums ${credit ? "text-teal" : "text-ink"}`}>
                    {credit ? "+ " : "− "}
                    {formatCents(t.amount_cents)}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </div>
  );
}
