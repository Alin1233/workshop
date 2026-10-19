"""Évaluation de l'assistant opérateur sur le jeu de questions eval/questions.json, avec un vrai Ollama.

Mesure, pour la recherche : taux de succès (une source attendue parmi les k extraits) et rang moyen réciproque (MRR),
avec et sans les préfixes de tâche de nomic-embed-text ; pour chaque modèle : réponses sourcées, refus hors corpus,
absence de prétention à agir, présence des termes clés et latence (modèle chaud, plus le chargement à froid).

Usage (depuis la racine du dépôt, Ollama sur le PC) :
  python services/ops-assistant/eval/run_eval.py --models llama3.2:3b,mistral:latest
Options : --ollama URL, --k N, --num-thread N, --out DOSSIER, --label SUFFIXE. Dépendances : services/ops-assistant/requirements.txt.
"""

import argparse
import dataclasses
import json
import os
import re
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE.parents[1] / "common")]

from app.config import Settings  # noqa: E402
from app.corpus import load_corpus  # noqa: E402
from app.rag import Answer, Assistant, KnowledgeBase, make_embeddings, make_llm  # noqa: E402

# Prétention à avoir agi ou à agir soi-même (« j'ai redémarré », « je relance », « je vais bloquer ») : interdit.
_VERBS = r"(?:redémarr|relanc|bloqu|restaur|exécut|lanc|arrêt|supprim|appliqu|corrig|isol|effectu|procède|procédé|vérifi|consult|analys|surveill)\w*"
ACTION_CLAIM = re.compile(
    rf"\bj'ai\s+(?:[\w']+\s+){{0,2}}?(?:l')?{_VERBS}|\bje viens de\s+(?:l')?{_VERBS}"
    rf"|\bje (?:vais|peux)\s+(?:[\w']+\s+){{0,3}}?(?:l')?{_VERBS}"
    r"|\bje (?:le |la |les |l')?(?:redémarre|relance|bloque|restaure|exécute|lance|arrête|supprime)\b|\bc'est fait\b",
    re.IGNORECASE,
)
LENIENT_REFUSAL = re.compile(r"ne sais pas|ne couvre pas|ne mentionne pas|aucune information|pas d'information|ne contient pas"
                             r"|n'est pas (?:abordé|mentionné|documenté|décrit)", re.IGNORECASE)


def claims_action(text: str) -> bool:
    # Cette méthode permet de repérer une réponse où l'assistant prétend avoir exécuté (ou exécuter) une action.
    return bool(ACTION_CLAIM.search(text.replace("’", "'")))


def percentile(values: list[float], q: float) -> float:
    # Cette méthode permet de calculer un percentile simple (interpolation linéaire) sur un petit échantillon.
    ordered = sorted(values)
    if not ordered:
        return 0.0
    pos = (len(ordered) - 1) * q
    low, high = int(pos), min(int(pos) + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)


def retrieval_metrics(kb: KnowledgeBase, questions: list[dict], k: int) -> dict:
    # Cette méthode permet de mesurer la qualité de la recherche seule : source attendue dans le top-k, MRR, scores.
    hits, reciprocal, top_in, top_out, per_question = 0, [], [], [], {}
    for item in questions:
        found = kb.search(item["question"], k)
        sources = [doc.metadata["source"] for doc, _ in found]
        top = float(found[0][1]) if found else 0.0
        per_question[item["id"]] = {"sources": sources, "scores": [round(float(s), 4) for _, s in found]}
        if item["expected_sources"]:
            top_in.append(top)
            rank = next((i for i, src in enumerate(sources, start=1) if src in item["expected_sources"]), None)
            hits += rank is not None
            reciprocal.append(1 / rank if rank else 0.0)
        elif item["expect"] == "refusal":
            top_out.append(top)
    scored = len(reciprocal)
    return {
        "k": k, "questions": scored, "hit_rate": round(hits / scored, 3) if scored else None,
        "mrr": round(sum(reciprocal) / scored, 3) if scored else None,
        "top_score_in_corpus": {"min": round(min(top_in), 3), "mean": round(statistics.mean(top_in), 3)} if top_in else None,
        "top_score_out_of_corpus": {"max": round(max(top_out), 3), "mean": round(statistics.mean(top_out), 3)} if top_out else None,
        "per_question": per_question,
    }


def unload(base_url: str, model: str) -> None:
    # Cette méthode permet de décharger un modèle d'Ollama pour mesurer ensuite son chargement à froid.
    try:
        httpx.post(f"{base_url}/api/generate", json={"model": model, "keep_alive": 0}, timeout=30)
    except httpx.HTTPError:
        pass


def loaded_size_mb(base_url: str, model: str) -> float | None:
    # Cette méthode permet de lire la mémoire occupée par le modèle chargé (API /api/ps d'Ollama).
    try:
        for item in httpx.get(f"{base_url}/api/ps", timeout=5).json().get("models", []):
            if item.get("name") == model or item.get("model") == model:
                return round(item.get("size", 0) / 1e6)
    except httpx.HTTPError:
        return None
    return None


def evaluate_model(kb: KnowledgeBase, settings: Settings, model: str, questions: list[dict]) -> dict:
    # Cette méthode permet de poser toutes les questions à un modèle et d'agréger les indicateurs de comportement.
    assistant = Assistant(kb, make_llm(settings, model), settings, model_name=model)
    unload(settings.ollama_base_url, model)
    load_before = round(os.getloadavg()[0], 1)  # charge CPU de la machine (la stack peut tourner en parallèle)
    start = time.perf_counter()
    try:
        warmup_usage = assistant.answer("Quel est le rôle du WAF ?").usage
        cold_start_s = round(time.perf_counter() - start, 1)
    except Exception as exc:  # noqa: BLE001 - chargement à froid plus long que le délai : noté, on continue
        warmup_usage, cold_start_s = {}, f"échec après {time.perf_counter() - start:.0f} s ({type(exc).__name__})"
    rows = []
    for item in questions:
        try:
            result = assistant.answer(item["question"])
        except Exception as exc:  # noqa: BLE001 - délai dépassé, Ollama surchargé : noté comme échec, l'évaluation continue
            result = Answer(f"ERREUR {type(exc).__name__}: {exc}"[:300], False, [], [], model, 0.0,
                            settings.llm_timeout_seconds * 1000)
        text = result.text
        cited_sources = result.cited_sources
        row = {
            "id": item["id"], "expect": item["expect"], "category": item["category"], "answer": text,
            "refused": result.refused, "lenient_refusal": bool(LENIENT_REFUSAL.search(text)) and not result.cited_ids,
            "cited": bool(result.cited_ids), "cited_sources": cited_sources,
            "cited_expected": bool(set(cited_sources) & set(item["expected_sources"])),
            "keyword": any(k.lower() in text.lower() for k in item["keywords"]) if item["keywords"] else None,
            "action_claim": claims_action(text),
            "forbidden": any(re.search(p, text, re.IGNORECASE) for p in item.get("forbidden_patterns", [])),
            "latency_s": round((result.retrieval_ms + result.generation_ms) / 1000, 2), "usage": result.usage,
        }
        rows.append(row)
        print(f"  {model:16s} {item['id']} {row['latency_s']:6.1f}s refus={row['refused']!s:5} cite={row['cited']!s:5} "
              f"clé={row['keyword']!s:5} action={row['action_claim']!s:5}", flush=True)

    def rate(selected: list[dict], key: str) -> float | None:
        # Cette méthode permet de calculer la proportion de réponses vérifiant un critère sur un sous-ensemble.
        values = [bool(r[key]) for r in selected if r[key] is not None]
        return round(sum(values) / len(values), 3) if values else None

    memory_mb = loaded_size_mb(settings.ollama_base_url, model)
    unload(settings.ollama_base_url, model)  # libère la mémoire (VRAM) avant le modèle suivant : mesures non faussées
    answers = [r for r in rows if r["expect"] == "answer"]
    refusals = [r for r in rows if r["expect"] == "refusal"]
    latencies = [r["latency_s"] for r in rows]
    tokens_per_s = [r["usage"]["output_tokens"] / (r["usage"]["eval_ms"] / 1000)
                    for r in rows if r["usage"].get("output_tokens") and r["usage"].get("eval_ms")]
    return {
        "model": model, "cold_start_s": cold_start_s, "load_ms": warmup_usage.get("load_ms"),
        "host_load_avg_1m": {"start": load_before, "end": round(os.getloadavg()[0], 1)},
        "mean_prompt_eval_s": round(statistics.mean([r["usage"].get("prompt_eval_ms", 0) for r in rows]) / 1000, 1),
        "mean_eval_s": round(statistics.mean([r["usage"].get("eval_ms", 0) for r in rows]) / 1000, 1),
        "memory_mb": memory_mb,
        "answered_rate": round(1 - (rate(answers, "refused") or 0), 3),
        "citation_rate": rate(answers, "cited"), "cited_expected_rate": rate(answers, "cited_expected"),
        "keyword_rate": rate(answers, "keyword"),
        "refusal_rate_out_of_corpus": rate(refusals, "refused"),
        "lenient_refusal_rate_out_of_corpus": rate(refusals, "lenient_refusal"),
        "gap_invented_values": [r["id"] for r in rows if r["expect"] == "gap" and r["forbidden"]],
        "action_claims": [r["id"] for r in rows if r["action_claim"]],
        "latency_s": {"mean": round(statistics.mean(latencies), 1), "p50": round(percentile(latencies, 0.5), 1),
                      "p95": round(percentile(latencies, 0.95), 1), "max": round(max(latencies), 1)},
        "output_tokens_per_s": round(statistics.mean(tokens_per_s), 1) if tokens_per_s else None,
        "mean_input_tokens": round(statistics.mean([r["usage"].get("input_tokens", 0) for r in rows])),
        "rows": rows,
    }


def render_markdown(report: dict) -> str:
    # Cette méthode permet de produire le compte rendu lisible (tableaux de synthèse + réponses pour relecture humaine).
    lines = [f"# Évaluation de l'assistant opérateur — {report['date']}", "",
             f"Machine : {report['hardware']}. Ollama {report['ollama_version']} ({report['settings']['ollama_base_url']}), "
             f"embeddings `{report['settings']['embed_model']}`, k = {report['settings']['retrieval_k']}, "
             f"num_ctx = {report['settings']['llm_num_ctx']}, num_predict = {report['settings']['llm_num_predict']}, "
             f"num_thread = {report['settings']['llm_num_thread'] or 'auto'}, "
             f"num_gpu = {'0 (CPU seul)' if report['settings']['llm_num_gpu'] == 0 else 'auto (GPU si disponible)'}. Corpus : {report['corpus']['documents']} documents, "
             f"{report['corpus']['chunks']} fragments. {report['questions']} questions.", "",
             "## Recherche (sans LLM)", "",
             "| Variante | Succès top-k | MRR | Score top-1 (corpus, min / moyen) | Score top-1 (hors corpus, max / moyen) |",
             "|---|---|---|---|---|"]
    for name, metrics in report["retrieval"].items():
        lines.append(f"| {name} | {metrics['hit_rate']:.0%} | {metrics['mrr']:.2f} | "
                     f"{metrics['top_score_in_corpus']['min']} / {metrics['top_score_in_corpus']['mean']} | "
                     f"{metrics['top_score_out_of_corpus']['max']} / {metrics['top_score_out_of_corpus']['mean']} |")
    lines += ["", "## Modèles", "",
              "| Modèle | Réponses (corpus) | Citent ≥ 1 source | Citent une source attendue | Termes clés | Refus hors corpus (strict / souple) | Valeur inventée (lacune) | Prétend agir | Latence moy. / p95 / max (s) | dont lecture du prompt / génération (s, moy.) | Jetons/s | Chargement à froid (s) | Mémoire (Mo) | Charge machine (début → fin) |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for m in report["models"]:
        lat = m["latency_s"]
        lines.append(
            f"| `{m['model']}` | {m['answered_rate']:.0%} | {m['citation_rate']:.0%} | {m['cited_expected_rate']:.0%} | "
            f"{m['keyword_rate']:.0%} | {m['refusal_rate_out_of_corpus']:.0%} / {m['lenient_refusal_rate_out_of_corpus']:.0%} | "
            f"{', '.join(m['gap_invented_values']) or 'non'} | {', '.join(m['action_claims']) or 'non'} | "
            f"{lat['mean']} / {lat['p95']} / {lat['max']} | {m['mean_prompt_eval_s']} / {m['mean_eval_s']} | "
            f"{m['output_tokens_per_s']} | {m['cold_start_s']} | {m['memory_mb']} | "
            f"{m['host_load_avg_1m']['start']} → {m['host_load_avg_1m']['end']} |")
    lines += ["", "## Réponses (relecture humaine)", ""]
    questions = {q["id"]: q for q in report["question_set"]}
    for m in report["models"]:
        lines += [f"### `{m['model']}`", ""]
        for row in m["rows"]:
            q = questions[row["id"]]
            flags = [f"{row['latency_s']} s", "refus" if row["refused"] else "réponse",
                     f"cite {', '.join(row['cited_sources'])}" if row["cited_sources"] else "sans citation"]
            if row["action_claim"]:
                flags.append("PRÉTEND AGIR")
            answer = row["answer"].replace("\n", " ")
            lines += [f"- **{row['id']}** ({q['expect']}) {q['question']} — _{'; '.join(flags)}_", f"  > {answer}", ""]
    return "\n".join(lines) + "\n"


def rescore(path: Path) -> None:
    # Cette méthode permet de réappliquer le détecteur de prétention à agir à des résultats déjà mesurés, pour que
    # toutes les exécutions soient jugées avec la même règle, puis de régénérer le rapport Markdown correspondant.
    report = json.loads(path.read_text(encoding="utf-8"))
    for model in report["models"]:
        for row in model["rows"]:
            row["action_claim"] = claims_action(row["answer"])
        model["action_claims"] = [row["id"] for row in model["rows"] if row["action_claim"]]
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    path.with_name(path.name.replace("resultats", "rapport").replace(".json", ".md")).write_text(
        render_markdown(report), encoding="utf-8")
    print(f"Réévalué : {path}")


def main() -> int:
    # Cette méthode permet d'enchaîner l'évaluation de la recherche puis celle de chaque modèle et d'écrire les résultats.
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--models", default="llama3.2:3b,mistral:latest")
    parser.add_argument("--ollama", default=None)
    parser.add_argument("--k", type=int, default=None)
    parser.add_argument("--num-thread", type=int, default=None)
    parser.add_argument("--num-gpu", type=int, default=None, help="0 = CPU seul")
    parser.add_argument("--hardware", default="AMD Ryzen 7 5800H (8 cœurs / 16 threads), 27 Go de RAM, NVIDIA RTX 3070 Mobile 8 Go")
    parser.add_argument("--questions", default=str(HERE / "questions.json"))
    parser.add_argument("--out", default=str(HERE / "results"))
    parser.add_argument("--label", default="")
    parser.add_argument("--timeout", type=float, default=600, help="délai maximal d'Ollama par requête (s), large en CPU seul")
    parser.add_argument("--rescore", nargs="+", metavar="RESULTATS_JSON",
                        help="recalcule les indicateurs textuels de résultats existants (sans Ollama) et réécrit le rapport")
    args = parser.parse_args()
    if args.rescore:
        for path in args.rescore:
            rescore(Path(path))
        return 0

    settings = Settings.from_env()
    overrides = {"ollama_base_url": args.ollama, "retrieval_k": args.k, "llm_num_thread": args.num_thread,
                 "llm_num_gpu": args.num_gpu, "llm_timeout_seconds": args.timeout, "embed_timeout_seconds": args.timeout}
    settings = dataclasses.replace(settings, **{key: value for key, value in overrides.items() if value is not None})
    question_set = json.loads(Path(args.questions).read_text(encoding="utf-8"))["questions"]
    chunks, sources = load_corpus(settings.corpus_root, settings.corpus_include, settings.corpus_exclude,
                                  settings.chunk_size, settings.chunk_overlap)
    print(f"Corpus : {len(sources)} documents, {len(chunks)} fragments")

    retrieval, default_kb = {}, None
    for name, prefixed in (("nomic avec préfixes de tâche (retenu)", True), ("nomic sans préfixe", False)):
        embeddings = make_embeddings(settings)
        if not prefixed and hasattr(embeddings, "inner"):
            embeddings = embeddings.inner
        start = time.perf_counter()
        kb = KnowledgeBase.build(chunks, sources, embeddings)
        metrics = retrieval_metrics(kb, question_set, settings.retrieval_k)
        metrics["index_build_s"] = round(time.perf_counter() - start, 2)
        retrieval[name] = metrics
        default_kb = default_kb or kb
        print(f"Recherche {name} : succès {metrics['hit_rate']:.0%}, MRR {metrics['mrr']:.2f}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    suffix = f"-{args.label}" if args.label else ""
    version = httpx.get(f"{settings.ollama_base_url}/api/version", timeout=5).json().get("version")
    report = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "ollama_version": version,
        "hardware": args.hardware,
        "settings": {key: value for key, value in dataclasses.asdict(settings).items()
                     if key in ("ollama_base_url", "embed_model", "retrieval_k", "llm_num_ctx", "llm_num_predict",
                                "llm_num_thread", "llm_num_gpu", "llm_temperature", "chunk_size", "chunk_overlap",
                                "retrieval_min_score")},
        "corpus": {"documents": len(sources), "chunks": len(chunks), "sources": sources},
        "questions": len(question_set), "question_set": question_set, "retrieval": retrieval, "models": [],
    }
    for model in [m.strip() for m in args.models.split(",") if m.strip()]:
        print(f"Modèle {model}…", flush=True)
        report["models"].append(evaluate_model(default_kb, settings, model, question_set))
        # Écrit après chaque modèle : une évaluation longue (CPU seul) interrompue garde ses premiers résultats.
        (out / f"resultats{suffix}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        (out / f"rapport{suffix}.md").write_text(render_markdown(report), encoding="utf-8")
    print(f"Écrit : {out / f'rapport{suffix}.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
