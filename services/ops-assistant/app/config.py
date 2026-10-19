"""Configuration de l'assistant, lue une fois au démarrage depuis les variables d'environnement."""

from dataclasses import dataclass, field
from pathlib import Path

from resilience_common.settings import env

# Corpus par défaut : procédures et gouvernance (docs/) + descriptions d'architecture et contrats (README).
# Exclus : docs/context/ (sujet et grille d'évaluation) et docs/TODO.md (suivi de projet), qui ne servent pas l'opérateur,
# ainsi que la documentation de l'assistant lui-même (résultats d'évaluation : elle biaiserait la recherche).
DEFAULT_INCLUDE = "docs/**/*.md,README.md,services/*/README.md,ansible/README.md"
DEFAULT_EXCLUDE = "docs/context/*,docs/TODO.md,services/ops-assistant/*"


def _csv(value: str) -> list[str]:
    # Cette méthode permet de découper une liste séparée par des virgules en ignorant les éléments vides.
    return [item.strip() for item in value.split(",") if item.strip()]


def _default_corpus_root() -> str:
    # Cette méthode permet de pointer la racine du dépôt en développement local (le conteneur fixe CORPUS_ROOT=/corpus).
    parents = Path(__file__).resolve().parents
    return str(parents[3]) if len(parents) > 3 else "/corpus"


@dataclass(frozen=True)
class Settings:
    service: str = "ops-assistant"
    log_level: str = "INFO"
    ollama_base_url: str = "http://127.0.0.1:11434"
    llm_model: str = "llama3.2:3b"
    embed_model: str = "nomic-embed-text"
    llm_num_ctx: int = 4096
    llm_num_predict: int = 400
    llm_num_thread: int = 0          # 0 = laisser Ollama choisir (tous les cœurs physiques)
    llm_num_gpu: int = -1            # -1 = laisser Ollama choisir ; 0 = forcer le CPU (mesure représentative du PC Hôte)
    llm_temperature: float = 0.1
    llm_keep_alive: int = 1800       # secondes : garde les modèles chargés, pas de rechargement de plusieurs secondes en pleine démo
    llm_timeout_seconds: float = 180      # attente maximale du premier jeton (chargement à froid d'un 7B en CPU)
    answer_timeout_seconds: float = 240
    llm_warmup: bool = True          # précharge le LLM dès l'index prêt : la 1re question ne paie pas le chargement
    embed_timeout_seconds: float = 120     # par lot de fragments ; large pour un CPU lent et un chargement à froid
    retrieval_k: int = 4
    retrieval_min_score: float = 0.5
    chunk_size: int = 1000
    chunk_overlap: int = 150
    corpus_root: str = field(default_factory=_default_corpus_root)
    corpus_include: tuple[str, ...] = tuple(_csv(DEFAULT_INCLUDE))
    corpus_exclude: tuple[str, ...] = tuple(_csv(DEFAULT_EXCLUDE))
    alertmanager_url: str = ""       # vide = contexte des alertes désactivé
    max_concurrent_questions: int = 1
    queue_timeout_seconds: float = 20
    index_retry_seconds: float = 15
    max_body_bytes: int = 4096

    @classmethod
    def from_env(cls) -> "Settings":
        # Cette méthode permet de construire la configuration à partir de l'environnement du conteneur,
        # chaque valeur ayant un défaut raisonnable pour un lancement local (uvicorn depuis le dépôt).
        d = cls()
        return cls(
            service=env("SERVICE_NAME", d.service),
            log_level=env("LOG_LEVEL", d.log_level),
            ollama_base_url=env("OLLAMA_BASE_URL", d.ollama_base_url).rstrip("/"),
            llm_model=env("LLM_MODEL", d.llm_model),
            embed_model=env("EMBED_MODEL", d.embed_model),
            llm_num_ctx=int(env("LLM_NUM_CTX", str(d.llm_num_ctx))),
            llm_num_predict=int(env("LLM_NUM_PREDICT", str(d.llm_num_predict))),
            llm_num_thread=int(env("LLM_NUM_THREAD", str(d.llm_num_thread))),
            llm_num_gpu=int(env("LLM_NUM_GPU", str(d.llm_num_gpu))),
            llm_temperature=float(env("LLM_TEMPERATURE", str(d.llm_temperature))),
            llm_keep_alive=int(env("LLM_KEEP_ALIVE_SECONDS", str(d.llm_keep_alive))),
            llm_timeout_seconds=float(env("LLM_TIMEOUT_SECONDS", str(d.llm_timeout_seconds))),
            answer_timeout_seconds=float(env("ANSWER_TIMEOUT_SECONDS", str(d.answer_timeout_seconds))),
            embed_timeout_seconds=float(env("EMBED_TIMEOUT_SECONDS", str(d.embed_timeout_seconds))),
            llm_warmup=env("LLM_WARMUP", "true").lower() in ("1", "true", "yes", "oui"),
            retrieval_k=int(env("RETRIEVAL_K", str(d.retrieval_k))),
            retrieval_min_score=float(env("RETRIEVAL_MIN_SCORE", str(d.retrieval_min_score))),
            chunk_size=int(env("CHUNK_SIZE", str(d.chunk_size))),
            chunk_overlap=int(env("CHUNK_OVERLAP", str(d.chunk_overlap))),
            corpus_root=env("CORPUS_ROOT", d.corpus_root),
            corpus_include=tuple(_csv(env("CORPUS_INCLUDE", DEFAULT_INCLUDE))),
            corpus_exclude=tuple(_csv(env("CORPUS_EXCLUDE", DEFAULT_EXCLUDE))),
            alertmanager_url=env("ALERTMANAGER_URL", d.alertmanager_url).rstrip("/"),
            max_concurrent_questions=max(1, int(env("MAX_CONCURRENT_QUESTIONS", str(d.max_concurrent_questions)))),
            queue_timeout_seconds=float(env("QUEUE_TIMEOUT_SECONDS", str(d.queue_timeout_seconds))),
            index_retry_seconds=float(env("INDEX_RETRY_SECONDS", str(d.index_retry_seconds))),
            max_body_bytes=int(env("MAX_BODY_BYTES", str(d.max_body_bytes))),
        )
