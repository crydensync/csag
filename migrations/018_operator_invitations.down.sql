DELETE FROM operator_stepup_challenges WHERE purpose = 'operator_invite';
DELETE FROM operator_stepup_grants WHERE purpose = 'operator_invite';

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

DROP TABLE operator_invitations;
