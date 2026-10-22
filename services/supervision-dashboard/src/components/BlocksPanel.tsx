import { chrono, clockTime, toMs } from "../lib/format";
import { useNow } from "../lib/poll";
import type { BlockItem, BlocksResponse } from "../lib/types";
import { Empty } from "./ui";

// Cette méthode permet de calculer le temps restant d'un blocage (secondes, jamais négatif) à l'heure du serveur.
export function remainingSeconds(block: BlockItem, now: number): number | null {
  const expires = toMs(block.expires_at);
  return expires === null ? null : Math.max(0, (expires - now) / 1000);
}

// Cette méthode permet d'afficher une IP bloquée : compte à rebours jusqu'à la levée automatique, jauge du TTL restant,
// motif et heure de levée.
function BlockRow({ block, now }: { block: BlockItem; now: number }) {
  const remaining = remainingSeconds(block, now);
  const ttl = block.ttl_s ?? null;
  const ratio = remaining !== null && ttl ? Math.min(1, remaining / ttl) : null;
  const expired = remaining !== null && remaining <= 0;
  return (
    <li className="border-b border-edge-weak py-1.5 last:border-b-0" data-testid="block-item">
      <div className="flex items-baseline justify-between gap-2">
        <span className="truncate tabular text-[15px] font-semibold text-snow">{block.ip}</span>
        <span className={`text-[24px] leading-none font-semibold tabular ${expired ? "text-ok" : "text-bad"}`} data-testid="block-ttl">
          {remaining === null ? "—" : expired ? "levée…" : chrono(remaining)}
        </span>
      </div>
      {ratio !== null ? (
        <div className="mt-1.5 h-2 rounded-sm bg-panel-2" aria-hidden>
          <div className="h-full rounded-sm bg-bad transition-[width] duration-1000 ease-linear" style={{ width: `${ratio * 100}%` }} />
        </div>
      ) : null}
      <p className="mt-1 truncate text-[12.5px] text-snow/90" title={block.reason}>
        {block.reason || "blocage de remédiation"}
      </p>
      <p className="text-[12px] text-fog">
        levée automatique à {clockTime(toMs(block.expires_at))}
        {ttl ? ` · TTL ${ttl} s` : ""}
      </p>
    </li>
  );
}

// Cette méthode permet d'afficher les IP bloquées au WAF par la remédiation et l'état des moyens de compromission
// (liste de blocage du WAF, pont de restauration de la base).
export default function BlocksPanel({ data }: { data: BlocksResponse | null }) {
  const now = useNow(1000);
  if (!data) return <Empty>En attente de l'état du WAF…</Empty>;
  const bridge = data.bridge;
  return (
    <div className="flex h-full flex-col gap-2">
      {data.blocks.length === 0 ? (
        <Empty tone="ok">Aucune IP bloquée</Empty>
      ) : (
        <ul className="flex flex-col">{data.blocks.map((block) => <BlockRow key={block.ip} block={block} now={now} />)}</ul>
      )}
      <dl className="mt-auto grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 border-t border-edge-weak pt-1.5 text-[12.5px]">
        <dt className="text-fog">Liste WAF</dt>
        <dd className={`text-right font-medium ${data.waf_blocklist === false ? "text-warn" : data.waf_blocklist ? "text-ok" : "text-unknown"}`}>
          {data.waf_blocklist === false ? "indisponible" : data.waf_blocklist ? "chargée" : "inconnue"}
        </dd>
        <dt className="text-fog">Pont de restauration</dt>
        <dd className={`text-right font-medium ${bridge?.busy ? "text-busy" : bridge?.available ? "text-ok" : "text-warn"}`}>
          {!bridge ? "inconnu" : !bridge.configured ? "non configuré" : bridge.busy ? "restauration en cours" : bridge.available ? `prêt (${bridge.runner ?? "hôte"})` : "runner absent"}
        </dd>
      </dl>
    </div>
  );
}
