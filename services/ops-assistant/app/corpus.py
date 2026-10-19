"""Chargement du corpus Markdown et découpage par sections, avec la provenance de chaque fragment (fichier + titre)."""

import logging
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import MarkdownHeaderTextSplitter, RecursiveCharacterTextSplitter

logger = logging.getLogger(__name__)

HEADERS = [("#", "h1"), ("##", "h2"), ("###", "h3")]
MAX_FILE_BYTES = 512 * 1024  # un document plus gros n'est pas une procédure : on l'écarte plutôt que de saturer la RAM


@dataclass(frozen=True)
class CorpusFile:
    path: Path
    source: str  # chemin relatif à la racine du corpus, au format POSIX (cité dans les réponses)


def discover(root: str | Path, include: tuple[str, ...] | list[str], exclude: tuple[str, ...] | list[str]) -> list[CorpusFile]:
    # Cette méthode permet de lister les fichiers du corpus selon les motifs d'inclusion/exclusion,
    # en refusant tout fichier qui sortirait de la racine (lien symbolique) ou serait trop volumineux.
    base = Path(root).resolve()
    found: dict[str, CorpusFile] = {}
    for pattern in include:
        for path in base.glob(pattern):
            resolved = path.resolve()
            if not resolved.is_file() or not resolved.is_relative_to(base):
                continue
            source = path.relative_to(base).as_posix()
            if any(fnmatch(source, motif) for motif in exclude):
                continue
            if resolved.stat().st_size > MAX_FILE_BYTES:
                logger.warning("corpus_file_too_large", extra={"source": source})
                continue
            found[source] = CorpusFile(resolved, source)
    return [found[key] for key in sorted(found)]


def _title_from_source(source: str) -> str:
    # Cette méthode permet de donner un titre lisible à un fragment situé avant le premier titre Markdown.
    return Path(source).stem.replace("-", " ").replace("_", " ")


def split_markdown(text: str, source: str, chunk_size: int = 1000, chunk_overlap: int = 150) -> list[Document]:
    # Cette méthode permet de découper un document Markdown d'abord par titres (#, ##, ###), puis par taille,
    # chaque fragment portant le fichier source et le chemin de titres qui le situe (cités dans les réponses).
    sections = MarkdownHeaderTextSplitter(HEADERS, strip_headers=True).split_text(text)
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size, chunk_overlap=chunk_overlap, separators=["\n\n", "\n", ". ", " ", ""],
    )
    chunks: list[Document] = []
    for section in sections:
        headings = [section.metadata[key] for _, key in HEADERS if key in section.metadata]
        title = headings[0] if headings else _title_from_source(source)
        section_path = " > ".join(headings) if headings else title
        for piece in splitter.split_text(section.page_content):
            if not piece.strip():
                continue
            # Le chemin de titres est répété en tête du fragment : il porte souvent le sens (« Par alerte »),
            # ce qui améliore la recherche par similarité et donne au LLM le contexte de l'extrait.
            chunks.append(Document(
                page_content=f"{section_path}\n\n{piece.strip()}",
                metadata={"source": source, "section": section_path, "title": title,
                          "chunk_id": f"{source}#{len(chunks)}"},
            ))
    return chunks


def load_corpus(root: str | Path, include, exclude, chunk_size: int = 1000, chunk_overlap: int = 150) -> tuple[list[Document], list[str]]:
    # Cette méthode permet de lire et découper tout le corpus ; elle renvoie les fragments et la liste des fichiers indexés.
    chunks: list[Document] = []
    sources: list[str] = []
    for item in discover(root, include, exclude):
        try:
            text = item.path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            logger.warning("corpus_file_unreadable", extra={"source": item.source, "error": str(exc)})
            continue
        pieces = split_markdown(text, item.source, chunk_size, chunk_overlap)
        if pieces:
            sources.append(item.source)
            chunks.extend(pieces)
    return chunks, sources
