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

// Cette méthode permet d'assembler l'écran de supervision, disposé comme un tableau de bord Grafana : grille de 24
// colonnes sur grand écran (tout tient sans défilement en 1080p, pour la capture du Clip Chrono), 12 sur tablette, une
// seule sur téléphone (la page défile). Chaque panneau interroge sa route du back-for-front toutes les 2 s et signale
// lui-même une source indisponible.
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
  // Listes longues : hauteur bornée quand la page défile, toute la hauteur du panneau sur l'écran mural. Sur l'écran
  // mural, la rangée du milieu ne descend jamais sous la hauteur de la carte des composants ; la chronologie, elle, ne
  // compte pas dans ce minimum (contain-size) et défile si l'écran est trop bas.
  const list = "max-h-[26rem] overflow-y-auto wall:max-h-none";

  return (
    <ClockOffset.Provider value={offset}>
      <div className="flex min-h-screen flex-col wall:h-screen wall:overflow-hidden">
        <Header updatedAt={overview.updatedAt} error={overview.error} intervalMs={intervalMs} />

        <main className="grid flex-1 grid-cols-1 content-start gap-2 p-2 sm:p-3 md:grid-cols-12 xl:grid-cols-24 wall:min-h-0 wall:content-stretch wall:grid-rows-[auto_minmax(min-content,1.35fr)_minmax(0,1fr)]">
          <StatusBanner status={status} stale={stale} />

          <Panel title="Carte des composants" className="md:col-span-12 xl:col-span-14" problems={sourceProblems(overview, ["prometheus", "engine"])} testId="panel-components">
            <ComponentMap overview={overview.data} />
          </Panel>
          <Panel
            title="Chronologie de la reprise"
            className="md:col-span-12 xl:col-span-10 wall:contain-size"
            bodyClassName="wall:overflow-y-auto"
            problems={sourceProblems(current, ["engine"])}
            aside="horodatée par le moteur"
            testId="panel-timeline"
          >
            {unavailable(current, ["engine"]) && !preIncident
              ? <Unavailable what="Chronologie" />
              : <IncidentTimeline incident={current.data?.incident ?? null} status={status} />}
          </Panel>

          <Panel
            title="Alertes actives"
            className="md:col-span-6 xl:col-span-5"
            bodyClassName={list}
            problems={sourceProblems(alerts, ["alertmanager", "prometheus"])}
            aside={alerts.data ? `${alerts.data.alerts.length}` : undefined}
            testId="panel-alerts"
          >
            {unavailable(alerts, ["alertmanager", "prometheus"]) ? <Unavailable what="Liste des alertes" /> : <AlertsPanel alerts={alerts.data?.alerts ?? null} />}
          </Panel>
          <Panel title="IP bloquées au WAF" className="md:col-span-6 xl:col-span-4" bodyClassName="wall:overflow-y-auto" problems={sourceProblems(blocks, ["engine"])} testId="panel-blocks">
            {unavailable(blocks, ["engine"]) ? <Unavailable what="État des blocages" /> : <BlocksPanel data={blocks.data} />}
          </Panel>
          <Panel title="Événements en direct" className="md:col-span-12 xl:col-span-6" bodyClassName={list} problems={sourceProblems(events, ["loki"])} aside="journaux Loki" testId="panel-events">
            {unavailable(events, ["loki"]) ? <Unavailable what="Fil d'événements" /> : <EventFeed events={events.data?.events ?? null} />}
          </Panel>
          <Panel title="Derniers incidents" className="md:col-span-12 xl:col-span-9" bodyClassName="wall:overflow-y-auto" problems={sourceProblems(history, ["engine"])} testId="panel-history">
            {unavailable(history, ["engine"])
              ? <Unavailable what="Historique" />
              : <IncidentHistory incidents={history.data?.incidents ?? null} focusId={status?.incident_id ?? null} />}
          </Panel>
        </main>
      </div>
    </ClockOffset.Provider>
  );
}
