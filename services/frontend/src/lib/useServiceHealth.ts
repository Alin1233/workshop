import { useEffect, useState } from "react";
import { api } from "./api";

export type HealthState = "checking" | "ok" | "degraded" | "down";
export type ServiceHealth = { state: HealthState; auth: boolean | null; payments: boolean | null };

// Cette méthode permet de suivre en continu l'état des services auth et paiements (sondage /health toutes les 5 s),
// pour l'afficher dans l'en-tête, sur l'écran de connexion et dans le bandeau d'incident.
export function useServiceHealth(): ServiceHealth {
  const [health, setHealth] = useState<ServiceHealth>({ state: "checking", auth: null, payments: null });

  useEffect(() => {
    let cancelled = false;
    // Cette méthode permet d'interroger les deux /health et d'en déduire un état global.
    const poll = async () => {
      const [auth, payments] = await Promise.all([api.health("auth"), api.health("payments")]);
      if (cancelled) return;
      setHealth({ state: auth && payments ? "ok" : auth || payments ? "degraded" : "down", auth, payments });
    };
    poll();
    const timer = setInterval(poll, 5000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return health;
}
