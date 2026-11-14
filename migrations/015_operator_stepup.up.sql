CREATE TABLE operator_stepup_challenges (
    token_hash        BYTEA PRIMARY KEY,
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_token_hash BYTEA NOT NULL,
    purpose           TEXT NOT NULL CHECK (purpose IN ('operator_role_change', 'operator_remove')),
    session_data      JSONB NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_operator_stepup_challenges_expiry ON operator_stepup_challenges(expires_at);

CREATE TABLE operator_stepup_grants (
    token_hash        BYTEA PRIMARY KEY,
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_token_hash BYTEA NOT NULL,
    purpose           TEXT NOT NULL CHECK (purpose IN ('operator_role_change', 'operator_remove')),
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_operator_stepup_grants_expiry ON operator_stepup_grants(expires_at);
