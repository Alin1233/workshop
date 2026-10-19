import { useState, type FormEvent } from "react";
import { api, ApiError, formatCents, newIdempotencyKey, parseEuros } from "../lib/api";

type Props = { token: string; onDone: () => void; onSessionExpired: () => void };

const inputClass =
  "w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200";

// Cette méthode permet de saisir et d'envoyer un virement, en réutilisant la même clé d'idempotence
// tant que la saisie ne change pas (un nouvel essai après incident ne débite donc jamais deux fois).
export default function TransferForm({ token, onDone, onSessionExpired }: Props) {
  const [toAccount, setToAccount] = useState("");
  const [amount, setAmount] = useState("");
  const [label, setLabel] = useState("");
  const [idempotencyKey, setIdempotencyKey] = useState(newIdempotencyKey);
  const [feedback, setFeedback] = useState<{ kind: "success" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  // Cette méthode permet de mettre à jour un champ et de générer une nouvelle clé, puisqu'il s'agit d'un autre virement.
  const edit = (setter: (value: string) => void) => (value: string) => {
    setter(value);
    setIdempotencyKey(newIdempotencyKey());
    setFeedback(null);
  };

  // Cette méthode permet de valider la saisie puis d'appeler l'API de virement.
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const cents = parseEuros(amount);
    if (cents === null) {
      setFeedback({ kind: "error", text: "Montant invalide (ex. 12,50)." });
      return;
    }
    setBusy(true);
    setFeedback(null);
    try {
      const transfer = await api.transfer(token, idempotencyKey, toAccount.trim().toUpperCase(), cents, label);
      setFeedback({ kind: "success", text: `Virement de ${formatCents(transfer.amount_cents)} effectué.` });
      setToAccount("");
      setAmount("");
      setLabel("");
      setIdempotencyKey(newIdempotencyKey());
      onDone();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onSessionExpired();
      const retryable = err instanceof ApiError && (err.status === 0 || err.status >= 500);
      const text = err instanceof ApiError ? err.message : "Erreur inattendue.";
      setFeedback({ kind: "error", text: retryable ? `${text} Vous pouvez renvoyer sans risque de double débit.` : text });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-3 rounded-xl border border-slate-200 bg-white p-6 shadow-sm" data-testid="transfer-form">
      <h2 className="font-medium">Nouveau virement</h2>
      <label className="block space-y-1 text-sm">
        <span className="text-slate-700">Compte bénéficiaire</span>
        <input
          className={`${inputClass} font-mono uppercase`}
          placeholder="RA0123456789"
          value={toAccount}
          onChange={(e) => edit(setToAccount)(e.target.value)}
          pattern="[Rr][Aa]\d{10}"
          title="RA suivi de 10 chiffres"
          required
        />
      </label>
      <div className="grid grid-cols-3 gap-3">
        <label className="col-span-1 block space-y-1 text-sm">
          <span className="text-slate-700">Montant (€)</span>
          <input className={inputClass} inputMode="decimal" placeholder="25,00" value={amount} onChange={(e) => edit(setAmount)(e.target.value)} required />
        </label>
        <label className="col-span-2 block space-y-1 text-sm">
          <span className="text-slate-700">Libellé</span>
          <input className={inputClass} maxLength={140} placeholder="Remboursement resto" value={label} onChange={(e) => edit(setLabel)(e.target.value)} />
        </label>
      </div>
      {feedback && (
        <p
          role="status"
          className={`rounded-md px-3 py-2 text-sm ${feedback.kind === "success" ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700"}`}
        >
          {feedback.text}
        </p>
      )}
      <button
        type="submit"
        disabled={busy}
        className="w-full rounded-md bg-indigo-600 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
      >
        {busy ? "Envoi…" : "Envoyer"}
      </button>
    </form>
  );
}
