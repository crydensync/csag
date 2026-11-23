CREATE TABLE operator_invitations (
    token_hash       BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    email            TEXT NOT NULL,
    role             TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    created_by       UUID,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL,
    accepted_at      TIMESTAMPTZ,
    accepted_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    revoked_at       TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);

CREATE INDEX operator_invitations_email_idx ON operator_invitations (lower(email));
CREATE INDEX operator_invitations_expiry_idx ON operator_invitations (expires_at);

ALTER TABLE operator_stepup_challenges
    DROP CONSTRAINT operator_stepup_challenges_purpose_check,
    ADD CONSTRAINT operator_stepup_challenges_purpose_check
        CHECK (purpose IN (
            'operator_role_change',
            'operator_remove',
            'operator_session_revoke',
            'operator_passkey_remove',
            'operator_invite',
            'secret_reveal',
            'secret_mutation'
        ));

ALTER TABLE operator_stepup_grants
    DROP CONSTRAINT operator_stepup_grants_purpose_check,
    ADD CONSTRAINT operator_stepup_grants_purpose_check
        CHECK (purpose IN (
            'operator_role_change',
            'operator_remove',
            'operator_session_revoke',
            'operator_passkey_remove',
            'operator_invite',
            'secret_reveal',
            'secret_mutation'
        ));
