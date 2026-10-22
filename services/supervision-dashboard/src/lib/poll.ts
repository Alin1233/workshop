import { createContext, useContext, useEffect, useRef, useState } from "react";
import type { Envelope } from "./types";

export interface Poll<T> {
  data: T | null;
  error: string | null;
  updatedAt: number | null;
}

const REQUEST_TIMEOUT_MS = 5000;

// Cette méthode permet de lire la période de rafraîchissement (?refresh=ms dans l'URL, 2 s par défaut, entre 1 et 10 s).
export function pollInterval(search = typeof window !== "undefined" ? window.location.search : ""): number {
  const value = Number(new URLSearchParams(search).get("refresh"));
  return Number.isFinite(value) && value >= 1000 && value <= 10000 ? value : 2000;
}

// Cette méthode permet d'interroger périodiquement une route du back-for-front (jamais deux requêtes en vol pour la
// même route) ; en cas d'échec, les dernières données restent affichées et l'erreur est signalée à côté.
export function usePoll<T extends Envelope>(url: string, intervalMs: number): Poll<T> {
  const [state, setState] = useState<Poll<T>>({ data: null, error: null, updatedAt: null });
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;

    const tick = async () => {
      controller = new AbortController();
      const abort = setTimeout(() => controller?.abort(), REQUEST_TIMEOUT_MS);
      try {
        const response = await fetch(url, { cache: "no-store", credentials: "same-origin", signal: controller.signal });
        if (!response.ok) {
          const message = response.status === 401 ? "identifiant requis : recharger la page" : `HTTP ${response.status}`;
          if (alive.current) setState((s) => ({ ...s, error: message }));
        } else {
          const data = (await response.json()) as T;
          if (alive.current) setState({ data, error: null, updatedAt: Date.now() });
        }
      } catch {
        if (alive.current) setState((s) => ({ ...s, error: "supervision injoignable" }));
      } finally {
        clearTimeout(abort);
        if (alive.current) timer = setTimeout(tick, intervalMs);
      }
    };
    void tick();
    return () => {
      alive.current = false;
      clearTimeout(timer);
      controller?.abort();
    };
  }, [url, intervalMs]);

  return state;
}

// Décalage entre l'horloge du serveur et celle du navigateur : chronomètres et TTL suivent l'heure du serveur.
export const ClockOffset = createContext(0);

// Cette méthode permet d'obtenir l'heure du serveur, rafraîchie chaque seconde (chronomètres, comptes à rebours).
export function useNow(periodMs = 1000): number {
  const offset = useContext(ClockOffset);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), periodMs);
    return () => clearInterval(id);
  }, [periodMs]);
  return now + offset;
}
