import { useState, type FormEvent } from "react";
import { api, ApiError, formatCents, newIdempotencyKey, parseEuros } from "../lib/api";
import { LABEL_MAX, transferSchema, validate, type FieldErrors } from "../lib/validation";

type Props = { token: string; onDone: () => void; onSessionExpired: () => void };
type Feedback = { kind: "success" | "error" | "retry"; text: string };
type Errors = FieldErrors<{ amount: string; toAccount: string; label: string }>;

const inputClass =
  "w-full min-w-0 rounded-lg border border-line bg-field px-3 py-2.5 text-sm text-ink placeholder:text-faint transition focus:border-teal focus:bg-white focus:ring-3 focus:ring-teal/15 focus:outline-none";

const QUICK_AMOUNTS = ["10", "20", "50"];

const invalidClass = "border-brick focus:border-brick focus:ring-brick/15";

// Cette méthode permet d'afficher le message d'erreur Zod d'un champ, s'il y en a un.
function FieldError({ id, message }: { id: string; message?: string }) {
  return message ? (
    <span id={id} className="block text-xs text-brick">
      {message}
    </span>
  ) : null;
}

const FEEDBACK_STYLES: Record<Feedback["kind"], string> = {
  success: "border-teal/20 bg-teal-soft text-teal-dark",
  error: "border-brick-line bg-brick-soft text-brick",
  retry: "border-amber-line bg-amber-soft text-amber-ink",
};

// Cette méthode permet de saisir et d'envoyer un virement, en réutilisant la même clé d'idempotence
// tant que la saisie ne change pas (un nouvel essai après incident ne débite donc jamais deux fois).
export default function TransferForm({ token, onDone, onSessionExpired }: Props) {
  const [toAccount, setToAccount] = useState("");
  const [amount, setAmount] = useState("");
  const [label, setLabel] = useState("");
  const [idempotencyKey, setIdempotencyKey] = useState(newIdempotencyKey);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<Errors>({});

  // Cette méthode permet de mettre à jour un champ et de générer une nouvelle clé, puisqu'il s'agit d'un autre virement.
  const edit = (field: keyof Errors, setter: (value: string) => void) => (value: string) => {
    setter(value);
    setErrors((prev) => ({ ...prev, [field]: undefined }));
    setIdempotencyKey(newIdempotencyKey());
    setFeedback(null);
  };

  // Cette méthode permet de valider la saisie puis d'appeler l'API de virement.
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const { data, errors: invalid } = validate(transferSchema, { amount, toAccount, label });
    if (!data) {
      setErrors(invalid);
      return;
    }
    setBusy(true);
    setFeedback(null);
    try {
      const transfer = await api.transfer(token, idempotencyKey, data.toAccount, data.amount, data.label);
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
      setFeedback(
        retryable
          ? { kind: "retry", text: `Envoi non confirmé. ${text} Le renvoi est sûr : il ne sera jamais débité deux fois.` }
          : { kind: "error", text },
      );
    } finally {
      setBusy(false);
    }
  };

  const cents = parseEuros(amount);
  const retry = feedback?.kind === "retry";
  const submitLabel = busy ? "Envoi…" : retry ? "Réessayer l'envoi" : cents ? `Envoyer ${formatCents(cents)}` : "Envoyer";

  return (
    <form onSubmit={submit} noValidate className="rounded-2xl border border-line bg-white p-5" data-testid="transfer-form">
      <h2 className="mb-4 font-semibold">Nouveau virement</h2>

      <label className="block space-y-1.5 text-sm">
        <span className="font-medium text-muted">Montant</span>
        <span className="relative block">
          <input
            className={`${inputClass} pr-14 text-2xl font-semibold tabular-nums ${errors.amount ? invalidClass : ""}`}
            inputMode="decimal"
            placeholder="0,00"
            value={amount}
            onChange={(e) => edit("amount", setAmount)(e.target.value)}
            aria-invalid={!!errors.amount}
            aria-describedby={errors.amount ? "amount-error" : undefined}
          />
          <span className="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 text-sm text-muted">EUR</span>
        </span>
        <FieldError id="amount-error" message={errors.amount} />
      </label>
      <div className="mt-2 mb-4 flex flex-wrap gap-1.5">
        {QUICK_AMOUNTS.map((value) => (
          <button
            key={value}
            type="button"
            // Montant déjà choisi : la saisie ne change pas, la clé (et un éventuel renvoi en attente) non plus.
            onClick={() => value !== amount && edit("amount", setAmount)(value)}
            className={`rounded-full border px-2.5 py-0.5 text-xs transition ${amount === value ? "border-teal bg-teal-soft text-teal-dark" : "border-line text-muted hover:border-faint hover:text-ink"}`}
          >
            {value} €
          </button>
        ))}
      </div>

      <div className="space-y-4">
        <label className="block space-y-1.5 text-sm">
          <span className="font-medium text-muted">Compte bénéficiaire</span>
          <input
            className={`${inputClass} font-mono tracking-wider uppercase ${errors.toAccount ? invalidClass : ""}`}
            placeholder="RA 0123 4567 89"
            value={toAccount}
            onChange={(e) => edit("toAccount", setToAccount)(e.target.value)}
            autoComplete="off"
            aria-invalid={!!errors.toAccount}
            aria-describedby={errors.toAccount ? "to-account-error" : undefined}
          />
          <FieldError id="to-account-error" message={errors.toAccount} />
        </label>
        <label className="block space-y-1.5 text-sm">
          <span className="flex items-baseline justify-between gap-2">
            <span className="font-medium text-muted">
              Libellé <span className="font-normal text-faint">· facultatif</span>
            </span>
            <span className={`text-xs tabular-nums ${label.length >= LABEL_MAX ? "text-brick" : "text-faint"}`} aria-live="polite">
              {label.length}/{LABEL_MAX}
            </span>
          </span>
          <input
            className={`${inputClass} ${errors.label ? invalidClass : ""}`}
            maxLength={LABEL_MAX}
            placeholder="Remboursement resto"
            value={label}
            onChange={(e) => edit("label", setLabel)(e.target.value)}
            aria-invalid={!!errors.label}
            aria-describedby={errors.label ? "label-error" : undefined}
          />
          <FieldError id="label-error" message={errors.label} />
        </label>
      </div>

      {feedback && (
        <p role="status" className={`mt-4 rounded-lg border px-3 py-2 text-sm leading-relaxed ${FEEDBACK_STYLES[feedback.kind]}`}>
          {feedback.text}
        </p>
      )}

      <button
        type="submit"
        disabled={busy}
        className={`mt-4 w-full rounded-lg py-2.5 text-sm font-semibold text-white transition disabled:opacity-60 ${retry ? "bg-amber-ink hover:bg-[#573600]" : "bg-teal hover:bg-teal-dark"}`}
      >
        {submitLabel}
      </button>
      <p className="mt-2.5 text-center text-xs text-muted">🔒 Protégé contre le double débit</p>
    </form>
  );
}
