CREATE TABLE operator_stepup_lockouts (
    user_id           UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    failure_count     INTEGER NOT NULL CHECK (failure_count >= 0),
    window_started_at TIMESTAMPTZ NOT NULL,
    locked_until      TIMESTAMPTZ,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
