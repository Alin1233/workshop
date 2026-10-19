import type { ServiceHealth } from "../lib/useServiceHealth";
import { StatusDot } from "./ServiceStatus";

const timeFormat = new Intl.DateTimeFormat("fr-FR", { hour: "2-digit", minute: "2-digit" });

// Cette méthode permet d'expliquer un incident en cours (quel service, quel impact pour le client) dès qu'un /health échoue ;
// elle ne rend rien quand tout va bien.
export default function IncidentBanner({ health, lastUpdated }: { health: ServiceHealth; lastUpdated: Date | null }) {
  if (health.state === "ok" || health.state === "checking") return null;

  const since = lastUpdated ? ` Solde affiché à jour de ${timeFormat.format(lastUpdated)}.` : "";
  const { title, text } =
    health.state === "down"
      ? { title: "Services momentanément indisponibles", text: `Nos équipes rétablissent le service.${since} Aucun virement ne sera débité deux fois.` }
      : health.payments === false
        ? { title: "Les paiements sont perturbés", text: `${since} Vous pouvez renvoyer un virement : il ne sera jamais débité deux fois.`.trim() }
        : { title: "La connexion est perturbée", text: "Votre session reste active : seules les nouvelles connexions sont touchées." };
  const tone =
    health.state === "down" ? "border-brick-line bg-brick-soft text-brick" : "border-amber-line bg-amber-soft text-amber-ink";

  return (
    <div className={`flex items-start gap-3 rounded-xl border px-4 py-3 text-sm ${tone}`} role="alert" data-testid="incident-banner">
      <span aria-hidden className="text-base leading-5">⚠</span>
      <div className="min-w-0 leading-relaxed">
        <p className="font-semibold">{title}</p>
        <p>{text}</p>
        <div className="mt-2 flex flex-wrap gap-1.5 text-xs">
          {([["Authentification", health.auth], ["Paiements", health.payments]] as const).map(([label, ok]) => (
            <span key={label} className="inline-flex items-center gap-1.5 rounded-full border border-current/20 bg-white px-2 py-0.5 text-ink">
              <StatusDot ok={ok} />
              {label}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
