import AlertsPanel from "./components/AlertsPanel";
import BlocksPanel from "./components/BlocksPanel";
import ComponentMap from "./components/ComponentMap";
import EventFeed from "./components/EventFeed";
import Header, { liveness } from "./components/Header";
import IncidentHistory from "./components/IncidentHistory";
import IncidentTimeline from "./components/IncidentTimeline";
import StatusBanner from "./components/StatusBanner";
import { Panel, Unavailable, sourceProblems, unavailable } from "./components/ui";
import { toMs } from "./lib/format";
import { ClockOffset, pollInterval, usePoll } from "./lib/poll";
import type { AlertsResponse, BlocksResponse, EventsResponse, IncidentResponse, IncidentsResponse, Overview } from "./lib/types";

// Cette méthode permet d'assembler l'écran de supervision (pensé pour une capture 1080p sans défilement) : chaque
// panneau interroge sa route du back-for-front toutes les 2 s et signale lui-même une source indisponible.
export default function App({ intervalMs = pollInterval() }: { intervalMs?: number }) {
  const overview = usePoll<Overview>("/api/overview", intervalMs);
  const alerts = usePoll<AlertsResponse>("/api/alerts", intervalMs);
  const current = usePoll<IncidentResponse>("/api/incidents/current", intervalMs);
  const blocks = usePoll<BlocksResponse>("/api/blocks", intervalMs);
  const events = usePoll<EventsResponse>("/api/events?limit=30", intervalMs);
  const history = usePoll<IncidentsResponse>("/api/incidents?limit=8", intervalMs);

  // Chronomètres et TTL suivent l'horloge du serveur (écart mesuré à la réception de la vue d'ensemble)
  const serverTime = toMs(overview.data?.server_time);
  const offset = serverTime !== null && overview.updatedAt !== null ? serverTime - overview.updatedAt : 0;
  const stale = liveness(overview.updatedAt, overview.error, intervalMs, Date.now()) !== "live" && overview.data !== null;
  const status = overview.data?.status ?? null;
  const preIncident = !!status && (status.phase === "incident" || status.phase === "remediation") && !status.incident_id;

  return (
    <ClockOffset.Provider value={offset}>
      <main className="flex min-h-full flex-col gap-3 p-4 lg:h-full lg:overflow-hidden">
        <Header updatedAt={overview.updatedAt} error={overview.error} intervalMs={intervalMs} />
        <StatusBanner status={status} stale={stale} />

        <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 lg:grid-cols-12 lg:grid-rows-[minmax(0,1.12fr)_minmax(0,1fr)]">
          <Panel
            title="Carte des composants"
            className="lg:col-span-7"
            problems={sourceProblems(overview, ["prometheus", "engine"])}
            aside="vert : opérationnel · ambre : dégradé · rouge : panne · bleu : en action"
            testId="panel-components"
          >
            <ComponentMap overview={overview.data} />
          </Panel>
          <Panel title="Chronologie de la reprise" className="lg:col-span-5" problems={sourceProblems(current, ["engine"])} aside="horodatée par le moteur" testId="panel-timeline">
            {unavailable(current, ["engine"]) && !preIncident
              ? <Unavailable what="Chronologie" />
              : <IncidentTimeline incident={current.data?.incident ?? null} status={status} />}
          </Panel>

          <Panel title="Alertes actives" className="lg:col-span-3" problems={sourceProblems(alerts, ["alertmanager", "prometheus"])} aside={alerts.data ? `${alerts.data.alerts.length}` : undefined} testId="panel-alerts">
            {unavailable(alerts, ["alertmanager", "prometheus"]) ? <Unavailable what="Liste des alertes" /> : <AlertsPanel alerts={alerts.data?.alerts ?? null} />}
          </Panel>
          <Panel title="IP bloquées au WAF" className="lg:col-span-2" problems={sourceProblems(blocks, ["engine"])} testId="panel-blocks">
            {unavailable(blocks, ["engine"]) ? <Unavailable what="État des blocages" /> : <BlocksPanel data={blocks.data} />}
          </Panel>
          <Panel title="Événements en direct" className="lg:col-span-4" problems={sourceProblems(events, ["loki"])} aside="journaux Loki" testId="panel-events">
            {unavailable(events, ["loki"]) ? <Unavailable what="Fil d'événements" /> : <EventFeed events={events.data?.events ?? null} />}
          </Panel>
          <Panel title="Derniers incidents" className="lg:col-span-3" problems={sourceProblems(history, ["engine"])} testId="panel-history">
            {unavailable(history, ["engine"])
              ? <Unavailable what="Historique" />
              : <IncidentHistory incidents={history.data?.incidents ?? null} focusId={status?.incident_id ?? null} />}
          </Panel>
        </div>
      </main>
    </ClockOffset.Provider>
  );
}
