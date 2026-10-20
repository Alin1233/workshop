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
    // Numéros de sondage : une réponse lente (jusqu'au délai de 8 s) peut arriver après celle d'un sondage plus récent ;
    // elle est alors ignorée. On n'ignore pas pour autant un sondage simplement dépassé par le suivant encore en vol :
    // si le service ne répond plus qu'au bout du délai, chaque réponse doit continuer à mettre l'état à jour.
    let started = 0;
    let applied = 0;
    // Cette méthode permet d'interroger les deux /health et d'en déduire un état global.
    const poll = async () => {
      const seq = ++started;
      const [auth, payments] = await Promise.all([api.health("auth"), api.health("payments")]);
      if (cancelled || seq < applied) return;
      applied = seq;
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
