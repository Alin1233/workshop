import { Fragment } from "react";
import { decimal } from "../lib/format";
import type { ComponentState, ComponentTile, Overview } from "../lib/types";
import { Empty, STATE_STYLES } from "./ui";

const CUSTOMER_PATH = ["waf", "frontend", "auth-service", "payment-api", "postgres"];
const RESILIENCE_CHAIN = ["observability", "anomaly-detector", "remediation-engine", "restore-bridge"];
const TILE_BG: Record<ComponentState, string> = {
  ok: "bg-ok/10",
  degraded: "bg-warn/15",
  down: "bg-bad/20",
  active: "bg-busy/15",
  unknown: "bg-white/5",
};

// Cette méthode permet d'afficher une tuile de composant : couleur d'état, nom, rôle et raison en clair.
function Tile({ tile }: { tile: ComponentTile }) {
  const style = STATE_STYLES[tile.state];
  return (
    <div
      className={`flex min-w-0 flex-1 basis-0 flex-col gap-0.5 rounded-lg border-2 px-3 py-2 transition-colors duration-300 ${style.ring} ${TILE_BG[tile.state]}`}
      data-testid={`component-${tile.id}`}
      data-state={tile.state}
      title={`${tile.label} — ${tile.role} : ${tile.reason}`}
    >
      <div className="flex items-center gap-2">
        <span className={`h-3.5 w-3.5 shrink-0 rounded-full ${style.dot}`} />
        <span className="truncate text-[17px] font-bold text-snow">{tile.label}</span>
      </div>
      <span className="truncate text-[12px] text-mute">
        <span className={`font-bold uppercase tracking-wider ${style.text}`}>{style.label}</span> · {tile.role}
      </span>
      <span className="line-clamp-2 text-[13.5px] leading-snug text-fog">{tile.reason}</span>
    </div>
  );
}

// Cette méthode permet d'afficher une rangée de tuiles reliées par des flèches (le sens du parcours).
function Row({ title, ids, tiles }: { title: string; ids: string[]; tiles: Map<string, ComponentTile> }) {
  const items = ids.map((id) => tiles.get(id)).filter(Boolean) as ComponentTile[];
  return (
    <div className="flex min-h-0 flex-col gap-1.5">
      <h3 className="text-[12px] font-semibold uppercase tracking-[0.14em] text-mute">{title}</h3>
      <div className="flex items-stretch gap-1.5">
        {items.map((tile, i) => (
          <Fragment key={tile.id}>
            {i > 0 ? <span aria-hidden className="self-center text-[20px] text-mute">→</span> : null}
            <Tile tile={tile} />
          </Fragment>
        ))}
      </div>
    </div>
  );
}

// Cette méthode permet d'afficher la carte des composants : parcours client (WAF → base) puis chaîne de résilience
// (observation → détection ML → moteur → pont de restauration), avec l'intégrité du registre et les scores ML.
export default function ComponentMap({ overview }: { overview: Overview | null }) {
  if (!overview) return <Empty>En attente de la première mesure…</Empty>;
  const tiles = new Map(overview.components.map((c) => [c.id, c]));
  const { integrity, anomaly } = overview;
  return (
    <div className="flex h-full flex-col justify-between gap-2">
      <Row title="Parcours client" ids={CUSTOMER_PATH} tiles={tiles} />
      <Row title="Chaîne de résilience" ids={RESILIENCE_CHAIN} tiles={tiles} />
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1 border-t border-edge pt-2 text-[14px] text-fog">
        <span data-testid="integrity">
          Registre :{" "}
          {integrity.ok === null ? <span className="text-unknown">non mesuré</span> : integrity.ok ? <strong className="text-ok">cohérent</strong> : <strong className="text-bad">incohérent</strong>}
          {integrity.last_check_age_s !== null ? <span className="text-mute"> (contrôle il y a {Math.round(integrity.last_check_age_s)} s)</span> : null}
        </span>
        <span>
          Scores ML{anomaly.threshold !== null ? ` (seuil ${decimal(anomaly.threshold)})` : ""} :{" "}
          {anomaly.scores.length === 0 ? <span className="text-unknown">—</span> : anomaly.scores.map((s) => {
            const over = s.score !== null && anomaly.threshold !== null && s.score >= anomaly.threshold;
            return (
              <span key={s.service} className={`mr-3 ${over ? "font-bold text-bad" : ""}`}>
                {s.service} {s.score === null ? "—" : decimal(s.score)}
              </span>
            );
          })}
        </span>
      </div>
    </div>
  );
}
