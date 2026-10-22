import { decimal } from "../lib/format";
import type { ComponentTile, Overview } from "../lib/types";
import { Empty, STATE_STYLES } from "./ui";

const CUSTOMER_PATH = ["waf", "frontend", "auth-service", "payment-api", "postgres"];
const RESILIENCE_CHAIN = ["observability", "anomaly-detector", "remediation-engine", "restore-bridge"];

// Cette méthode permet d'afficher une tuile de composant en fond plein (couleur d'état), avec nom, état, rôle et raison.
function Tile({ tile }: { tile: ComponentTile }) {
  const style = STATE_STYLES[tile.state];
  return (
    <div
      className={`flex min-w-0 flex-col justify-center gap-0.5 rounded-sm px-2.5 py-2 transition-colors duration-300 ${style.fill} ${style.on}`}
      data-testid={`component-${tile.id}`}
      data-state={tile.state}
      title={`${tile.label} — ${tile.role} : ${tile.reason}`}
    >
      <span className="truncate text-[15px] leading-tight font-semibold wall:text-[16px]">{tile.label}</span>
      <span className="truncate text-[12px] opacity-85">
        <span className="font-semibold">{style.label}</span> · {tile.role}
      </span>
      <span className="line-clamp-2 text-[12.5px] leading-snug opacity-90">{tile.reason}</span>
    </div>
  );
}

// Cette méthode permet d'afficher une rangée de tuiles, dans l'ordre du parcours (de gauche à droite) ; sur l'écran
// mural, la rangée s'étire pour remplir le panneau sans jamais descendre sous la hauteur de ses tuiles.
function Row({ title, ids, tiles, className }: { title: string; ids: string[]; tiles: Map<string, ComponentTile>; className: string }) {
  const items = ids.map((id) => tiles.get(id)).filter(Boolean) as ComponentTile[];
  return (
    <div className="flex flex-col gap-1 wall:flex-1">
      <h3 className="text-[12.5px] text-fog">{title}</h3>
      <div className={`grid gap-1 wall:flex-1 ${className}`}>
        {items.map((tile) => <Tile key={tile.id} tile={tile} />)}
      </div>
    </div>
  );
}

// Cette méthode permet d'afficher un score ML en jauge horizontale (fond, remplissage, repère du seuil), comme une
// « bar gauge » de Grafana : rouge au-dessus du seuil.
function ScoreGauge({ service, score, threshold }: { service: string; score: number | null; threshold: number | null }) {
  const over = score !== null && threshold !== null && score >= threshold;
  const scale = Math.max(1, threshold ?? 0, score ?? 0);
  return (
    <div className="grid min-w-0 grid-cols-[auto_1fr_2.5rem] items-center gap-2 text-[12.5px]">
      <span className="truncate text-snow">{service}</span>
      <div className="relative h-2.5 rounded-sm bg-panel-2" aria-hidden>
        {score !== null ? <div className={`h-full rounded-sm ${over ? "bg-bad" : "bg-ok"}`} style={{ width: `${(Math.max(0, score) / scale) * 100}%` }} /> : null}
        {threshold !== null ? <div className="absolute -top-0.5 -bottom-0.5 w-0.5 bg-warn" style={{ left: `${(threshold / scale) * 100}%` }} /> : null}
      </div>
      <span className={`text-right tabular ${over ? "font-semibold text-bad" : "text-snow"}`}>{score === null ? "—" : decimal(score)}</span>
    </div>
  );
}

// Cette méthode permet d'afficher la carte des composants : parcours client (WAF → base) puis chaîne de résilience
// (observation → détection ML → moteur → pont de restauration), avec l'intégrité du registre et les scores ML (chaque
// tuile écrit son état en toutes lettres : pas de légende).
export default function ComponentMap({ overview }: { overview: Overview | null }) {
  if (!overview) return <Empty>En attente de la première mesure…</Empty>;
  const tiles = new Map(overview.components.map((c) => [c.id, c]));
  const { integrity, anomaly } = overview;
  return (
    <div className="flex h-full flex-col gap-2">
      <Row title="Parcours client · de la requête à la base" ids={CUSTOMER_PATH} tiles={tiles} className="grid-cols-2 sm:grid-cols-3 md:grid-cols-5" />
      <Row title="Chaîne de résilience · de la détection à la reprise" ids={RESILIENCE_CHAIN} tiles={tiles} className="grid-cols-2 sm:grid-cols-4" />

      <div className="grid gap-x-6 gap-y-2 border-t border-edge-weak pt-2 sm:grid-cols-[auto_1fr]">
        <div className="flex flex-col justify-center gap-0.5" data-testid="integrity">
          <span className="text-[12.5px] text-fog">Intégrité du registre</span>
          <span className="text-[15px]">
            {integrity.ok === null ? <span className="text-unknown">non mesurée</span> : integrity.ok ? <strong className="font-semibold text-ok">cohérent</strong> : <strong className="font-semibold text-bad">incohérent</strong>}
            {integrity.last_check_age_s !== null ? <span className="text-[12.5px] text-mute"> · contrôle il y a {Math.round(integrity.last_check_age_s)} s</span> : null}
          </span>
        </div>
        <div className="flex min-w-0 flex-col gap-1">
          <span className="text-[12.5px] text-fog">Scores ML{anomaly.threshold !== null ? ` · seuil ${decimal(anomaly.threshold)}` : ""}</span>
          {anomaly.scores.length === 0
            ? <span className="text-[13px] text-unknown">—</span>
            : (
              <div className="grid grid-cols-1 gap-x-5 gap-y-1 sm:grid-cols-[repeat(auto-fill,minmax(13rem,1fr))]">
                {anomaly.scores.map((s) => <ScoreGauge key={s.service} service={s.service} score={s.score} threshold={anomaly.threshold} />)}
              </div>
            )}
        </div>
      </div>
    </div>
  );
}
