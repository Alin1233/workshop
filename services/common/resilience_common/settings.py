"""Lecture de la configuration : variables d'environnement et secrets montés en fichiers."""

import os


def env(name: str, default: str | None = None) -> str:
    # Cette méthode permet de lire une variable d'environnement obligatoire lorsque aucune valeur par défaut n'est fournie.
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Variable d'environnement manquante : {name}")
    return value


def secret(name: str) -> str:
    # Cette méthode permet de lire un secret depuis le fichier pointé par <NAME>_FILE (Docker secrets / Vault agent),
    # avec repli sur la variable <NAME> lorsque aucun fichier n'est fourni (dev local uniquement).
    path = os.getenv(f"{name}_FILE")
    if path:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    return env(name)


def database_url() -> str:
    # Cette méthode permet de construire la chaîne de connexion PostgreSQL à partir des variables DB_*
    # et du mot de passe lu en secret, pour ne jamais exposer celui-ci dans l'environnement du conteneur.
    from psycopg.conninfo import make_conninfo

    return make_conninfo(
        host=env("DB_HOST", "postgres"),
        port=env("DB_PORT", "5432"),
        dbname=env("DB_NAME"),
        user=env("DB_USER"),
        password=secret("DB_PASSWORD"),
        connect_timeout=5,
        application_name=env("SERVICE_NAME", "resilience-alpha"),
    )
