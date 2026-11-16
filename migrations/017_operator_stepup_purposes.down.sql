-- Reverting the wider constraint is safe only after all challenges and
-- grants using the added purposes have expired or been consumed.
DELETE FROM operator_stepup_challenges
WHERE purpose NOT IN ('operator_role_change', 'operator_remove');
DELETE FROM operator_stepup_grants
WHERE purpose NOT IN ('operator_role_change', 'operator_remove');

ALTER TABLE operator_stepup_challenges
    DROP CONSTRAINT operator_stepup_challenges_purpose_check,
    ADD CONSTRAINT operator_stepup_challenges_purpose_check
        CHECK (purpose IN ('operator_role_change', 'operator_remove'));

ALTER TABLE operator_stepup_grants
    DROP CONSTRAINT operator_stepup_grants_purpose_check,
    ADD CONSTRAINT operator_stepup_grants_purpose_check
        CHECK (purpose IN ('operator_role_change', 'operator_remove'));
