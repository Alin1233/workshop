import { useEffect, useState } from "react";
import { api } from "../lib/api";

type State = "checking" | "ok" | "degraded" | "down";

const STYLES: Record<State, { dot: string; label: string }> = {
  checking: { dot: "bg-slate-400", label: "Vérification…" },
  ok: { dot: "bg-emerald-500", label: "Services opérationnels" },
  degraded: { dot: "bg-amber-500", label: "Service dégradé" },
  down: { dot: "bg-red-500 animate-pulse", label: "Service indisponible" },
};

// Cette méthode permet d'afficher en continu l'état des services (rendu visible avant, pendant et après un incident).
export default function ServiceStatus() {
  const [state, setState] = useState<State>("checking");

  useEffect(() => {
    let cancelled = false;
    // Cette méthode permet d'interroger les deux /health et d'en déduire un état global.
    const poll = async () => {
      const [auth, payments] = await Promise.all([api.health("auth"), api.health("payments")]);
      if (cancelled) return;
      setState(auth && payments ? "ok" : auth || payments ? "degraded" : "down");
    };
    poll();
    const timer = setInterval(poll, 5000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  const style = STYLES[state];
  return (
    <div className="flex items-center gap-2 text-xs text-slate-600" data-testid="service-status" data-state={state}>
      <span className={`h-2.5 w-2.5 rounded-full ${style.dot}`} />
      {style.label}
    </div>
  );
}
