import { clockTime, toMs } from "../lib/format";
import { eventText } from "../lib/labels";
import { useNow } from "../lib/poll";
import type { EventItem } from "../lib/types";
import { Empty } from "./ui";

const TONES = { ok: "bg-ok", bad: "bg-bad", warn: "bg-warn", info: "bg-busy" };

// Cette méthode permet d'afficher le fil d'événements (journaux Loki en liste blanche), du plus récent au plus ancien ;
// les événements des dix dernières secondes sont surlignés pour que leur arrivée se voie dans la capture.
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
            className={`flex items-start gap-2.5 border-b border-edge/60 px-1.5 py-1 transition-colors duration-700 ${fresh ? "bg-white/10" : ""}`}
            data-testid="event-item"
          >
            <span className="w-[62px] shrink-0 text-[13px] text-fog tabular">{clockTime(event.ts)}</span>
            <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${TONES[tone]}`} aria-hidden />
            <div className="min-w-0 flex-1">
              <p className="truncate text-[14.5px] font-semibold leading-snug text-snow" title={title}>{title}</p>
              {detail ? <p className="truncate text-[12.5px] leading-snug text-mute" title={detail}>{detail}</p> : null}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
