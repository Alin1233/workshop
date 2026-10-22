import { clockTime, toMs } from "../lib/format";
import { eventText } from "../lib/labels";
import { useNow } from "../lib/poll";
import type { EventItem } from "../lib/types";
import { Empty } from "./ui";

const TONES = { ok: "border-ok", bad: "border-bad", warn: "border-warn", info: "border-busy" };

// Cette méthode permet d'afficher le fil d'événements (journaux Loki en liste blanche), du plus récent au plus ancien,
// comme le panneau « logs » de Grafana : barre de niveau colorée, heure, message et détail sur une ligne. Les événements
// des dix dernières secondes sont surlignés pour que leur arrivée se voie dans la capture.
export default function EventFeed({ events }: { events: EventItem[] | null }) {
  const now = useNow(1000);
  if (events === null) return <Empty>En attente des journaux…</Empty>;
  if (events.length === 0) return <Empty>Aucun événement dans les 30 dernières minutes</Empty>;
  return (
    <ul className="flex flex-col" data-testid="event-feed">
      {events.map((event, i) => {
        const { title, detail, tone } = eventText(event);
        const ts = toMs(event.ts);
        const fresh = ts !== null && now - ts < 10_000;
        return (
          <li
            key={`${event.ts}-${event.event_type}-${i}`}
            className={`flex items-baseline gap-2 border-l-[3px] py-[3px] pr-1 pl-2 transition-colors duration-700 ${TONES[tone]} ${fresh ? "bg-white/[0.07]" : "hover:bg-white/[0.03]"}`}
            data-testid="event-item"
          >
            <span className="shrink-0 tabular text-[12.5px] text-fog">{clockTime(event.ts)}</span>
            <p className="min-w-0 flex-1 truncate text-[13.5px] leading-snug" title={detail ? `${title} — ${detail}` : title}>
              <span className="text-snow">{title}</span>
              {detail ? <span className="text-fog"> · {detail}</span> : null}
            </p>
          </li>
        );
      })}
    </ul>
  );
}
