-- The step-up handlers also use challenges for session/passkey operations
-- and the secrets vault. Keep the schema's accepted purpose set aligned
-- with validStepUpPurpose so those ceremonies reach WebAuthn verification.
ALTER TABLE operator_stepup_challenges
    DROP CONSTRAINT operator_stepup_challenges_purpose_check,
    ADD CONSTRAINT operator_stepup_challenges_purpose_check
        CHECK (purpose IN (
            'operator_role_change',
            'operator_remove',
            'operator_session_revoke',
            'operator_passkey_remove',
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
            'secret_reveal',
            'secret_mutation'
        ));
