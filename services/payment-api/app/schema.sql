-- Schéma idempotent de l'API de paiement (appliqué à chaque démarrage).
-- Comptabilité en partie double : chaque virement produit exactement deux écritures dont la somme vaut 0.
CREATE TABLE IF NOT EXISTS accounts (
    id             UUID PRIMARY KEY,
    account_number TEXT NOT NULL UNIQUE,
    owner_id       UUID UNIQUE,              -- NULL pour le compte système (trésorerie)
    owner_name     TEXT NOT NULL,
    owner_email    TEXT,
    currency       TEXT NOT NULL DEFAULT 'EUR',
    balance_cents  BIGINT NOT NULL DEFAULT 0,
    is_system      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT balance_non_negative CHECK (is_system OR balance_cents >= 0)
);

CREATE TABLE IF NOT EXISTS transfers (
    id              UUID PRIMARY KEY,
    from_account_id UUID NOT NULL REFERENCES accounts (id),
    to_account_id   UUID NOT NULL REFERENCES accounts (id),
    amount_cents    BIGINT NOT NULL CHECK (amount_cents > 0),
    label           TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'completed' CHECK (status IN ('completed')),
    initiated_by    UUID,                    -- sub du JWT ; NULL pour les opérations système
    idempotency_key TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT distinct_accounts CHECK (from_account_id <> to_account_id),
    CONSTRAINT idempotency_unique UNIQUE (initiated_by, idempotency_key)
);

CREATE TABLE IF NOT EXISTS ledger_entries (
    id           BIGSERIAL PRIMARY KEY,
    transfer_id  UUID NOT NULL REFERENCES transfers (id),
    account_id   UUID NOT NULL REFERENCES accounts (id),
    amount_cents BIGINT NOT NULL CHECK (amount_cents <> 0),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ledger_entries_account_idx ON ledger_entries (account_id);
CREATE INDEX IF NOT EXISTS ledger_entries_transfer_idx ON ledger_entries (transfer_id);
CREATE INDEX IF NOT EXISTS transfers_from_idx ON transfers (from_account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS transfers_to_idx ON transfers (to_account_id, created_at DESC);

-- Compte de trésorerie fictif qui finance les crédits de bienvenue (seul compte autorisé à être négatif).
INSERT INTO accounts (id, account_number, owner_name, is_system)
VALUES ('00000000-0000-0000-0000-000000000001', 'RA-TREASURY', 'Trésorerie Resilience-Alpha', TRUE)
ON CONFLICT (id) DO NOTHING;
