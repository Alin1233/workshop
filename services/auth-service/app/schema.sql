-- Schéma idempotent du service d'authentification (appliqué à chaque démarrage).
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY,
    email         TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'client' CHECK (role IN ('client', 'admin')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (lower(email));

-- Double authentification (TOTP RFC 6238) : secret actif, secret en attente d'activation, dernier pas de temps
-- accepté (un code ne sert qu'une fois).
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_pending_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT;

-- Codes de secours à usage unique, stockés hachés (SHA-256 : codes aléatoires de 50 bits, pas des mots de passe).
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    user_id   UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   TIMESTAMPTZ,
    PRIMARY KEY (user_id, code_hash)
);

-- Étape « second facteur » d'une connexion : jeton opaque (haché), durée de vie courte, essais comptés.
CREATE TABLE IF NOT EXISTS mfa_challenges (
    token_hash TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0
);

-- Reconnaissance faciale, alternative au code TOTP : seule l'empreinte SFace est gardée, chiffrée (AES-256-GCM, secret
-- face_encryption_key, contexte lié au titulaire), sans photo de référence ; consentement explicite horodaté (donnée
-- biométrique, RGPD art. 9). Supprimée avec la double authentification ou à la demande du titulaire.
CREATE TABLE IF NOT EXISTS face_references (
    user_id      UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    template_enc BYTEA NOT NULL,
    consented_at TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Défi de pose (détection du vivant) : suite de poses tirée au hasard, 2 minutes ; à usage unique à la connexion,
-- quelques essais à l'enregistrement (ouvert par un code déjà vérifié).
CREATE TABLE IF NOT EXISTS face_challenges (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL CHECK (purpose IN ('enroll', 'login')),
    poses      TEXT[] NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL
);

-- Captures refusées à la connexion, chiffrées, gardées FACE_CAPTURE_RETENTION_DAYS jours (7) pour l'enquête du SOC ;
-- les captures acceptées et celles des enregistrements ne sont jamais conservées.
CREATE TABLE IF NOT EXISTS face_rejected_captures (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason      TEXT NOT NULL,
    score       REAL,
    client_ip   TEXT,
    image_enc   BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS face_rejected_captures_time_idx ON face_rejected_captures (captured_at);
