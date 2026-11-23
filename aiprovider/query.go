package aiprovider

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/crydensync/api/internal/postgresdb"
	crydenai "github.com/crydensync/cryden/v2/ai"
)

// ErrNotReadOnly means the supplied role CAN write, so it must not back
// the AI query surface.
var ErrNotReadOnly = errors.New("aiprovider: the database role is not read-only")

// ErrCannotVerifyReadOnly means the check could not reach a conclusion.
// Separate from ErrNotReadOnly on purpose: "this role can write" and "we
// could not find out" call for different words, and the second one is
// almost always a connection problem the operator can fix.
var ErrCannotVerifyReadOnly = errors.New("aiprovider: could not verify the database role is read-only")

// readOnlyProbeTimeout bounds the whole check. It is short because this
// runs inside an HTTP request from a settings form — a check that hangs
// for a minute would look like a broken console, and an operator
// configuring a second database expects a few seconds at most.
const readOnlyProbeTimeout = 10 * time.Second

const readOnlyPrivilegeQuery = `
	SELECT to_regclass($1)::text,
	       has_table_privilege(current_user, to_regclass($1), 'SELECT'),
	       has_table_privilege(current_user, to_regclass($1), 'INSERT'),
	       has_table_privilege(current_user, to_regclass($1), 'UPDATE'),
	       has_table_privilege(current_user, to_regclass($1), 'DELETE'),
       has_table_privilege(current_user, to_regclass($1), 'TRUNCATE'),
       has_any_column_privilege(current_user, to_regclass($1), 'INSERT'),
       has_any_column_privilege(current_user, to_regclass($1), 'UPDATE')`

// CheckReadOnly verifies that the supplied role can SELECT the data entities
// the AI query templates use and has no table-level data modification rights
// on them. A temporary-table write is not a useful probe here: PostgreSQL
// commonly grants TEMP on a database to PUBLIC, even for a role that has only
// SELECT on the product tables.
func CheckReadOnly(ctx context.Context, dsn string) error {
	ctx, cancel := context.WithTimeout(ctx, readOnlyProbeTimeout)
	defer cancel()

	db, err := sql.Open("postgres", postgresdb.DSNWithSearchPath(dsn, postgresdb.AuthSchema))
	if err != nil {
		return fmt.Errorf("%w: opening the connection: %v", ErrCannotVerifyReadOnly, err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("%w: connecting: %v", ErrCannotVerifyReadOnly, err)
	}
	if _, err := db.ExecContext(ctx, `SELECT 1`); err != nil {
		return fmt.Errorf("%w: the connection cannot run a query: %v", ErrCannotVerifyReadOnly, err)
	}

	entities := make([]string, 0, len(crydenai.EntityColumns))
	for entity := range crydenai.EntityColumns {
		entities = append(entities, entity)
	}
	sort.Strings(entities)
	for _, entity := range entities {
		var relation sql.NullString
		var canSelect, canInsert, canUpdate, canDelete, canTruncate, canInsertColumn, canUpdateColumn sql.NullBool
		err := db.QueryRowContext(ctx, readOnlyPrivilegeQuery, entity).
			Scan(&relation, &canSelect, &canInsert, &canUpdate, &canDelete, &canTruncate, &canInsertColumn, &canUpdateColumn)
		if err != nil || !relation.Valid || !canSelect.Valid || !canSelect.Bool {
			return fmt.Errorf("%w: cannot verify SELECT access to %s: %v", ErrCannotVerifyReadOnly, entity, err)
		}
		if (canInsert.Valid && canInsert.Bool) || (canUpdate.Valid && canUpdate.Bool) ||
			(canDelete.Valid && canDelete.Bool) || (canTruncate.Valid && canTruncate.Bool) ||
			(canInsertColumn.Valid && canInsertColumn.Bool) || (canUpdateColumn.Valid && canUpdateColumn.Bool) {
			return fmt.Errorf("%w: role has a data-write grant on %s", ErrNotReadOnly, relation.String)
		}
	}
	return nil
}

// PostgresSnapshot implements cryden's ai.QueryableStore over a
// connection that CheckReadOnly has already accepted.
//
// It runs an already-validated QueryIntent. "Already-validated" is not a
// hope: cryden's ai.ExecuteIntent runs validateIntent before it calls
// RunSafeQuery at all, and widget.Ask runs it too — there is no path to
// this method that skips that. What this type adds is that the statement
// it builds is assembled from cryden's own EntityColumns list rather than
// from anything on the intent, so an entity that somehow got past
// validation still cannot put text of its own into the SQL.
type PostgresSnapshot struct {
	db      *sql.DB
	maxRows int
}

// NewPostgresSnapshot opens the read-only connection. It does NOT itself
// check that the role is read-only — that is CheckReadOnly's job and it
// belongs to the settings write, where the operator is present to be told
// about a failure. Opening here is deliberately cheap so that a
// deployment whose stored connection has since gone bad reports a query
// error rather than failing to start.
func NewPostgresSnapshot(dsn string, maxRows int) (*PostgresSnapshot, error) {
	db, err := sql.Open("postgres", postgresdb.DSNWithSearchPath(dsn, postgresdb.AuthSchema))
	if err != nil {
		return nil, fmt.Errorf("aiprovider: opening the read-only connection: %w", err)
	}
	if maxRows < 1 {
		maxRows = crydenai.DefaultLimit
	}
	if maxRows > crydenai.MaxLimit {
		maxRows = crydenai.MaxLimit
	}
	return &PostgresSnapshot{db: db, maxRows: maxRows}, nil
}

// Close releases the pool.
func (s *PostgresSnapshot) Close() error { return s.db.Close() }

var _ crydenai.QueryableStore = (*PostgresSnapshot)(nil)

// RunSafeQuery executes an intent.
//
// Every value that reaches the SQL text comes from cryden's own
// EntityColumns / AllowedFields maps. Filter *values* — the only part
// that originates with a user — are bind parameters, never interpolated.
// Column and operator names cannot be bound in SQL, which is exactly why
// they are taken from a fixed map on this side rather than trusted from
// the intent: a name that is not in the map is refused, not quoted.
func (s *PostgresSnapshot) RunSafeQuery(ctx context.Context, intent crydenai.QueryIntent) (crydenai.QueryResult, error) {
	columns, ok := crydenai.EntityColumns[intent.Entity]
	if !ok {
		return crydenai.QueryResult{}, fmt.Errorf("aiprovider: unknown entity %q", intent.Entity)
	}

	// The intent's own Limit was already defaulted and clamped by
	// ai.ExecuteIntent; this is the deployment's own ceiling on top of
	// the engine's, so an operator can make the AI surface cheaper than
	// cryden's maximum without changing the engine.
	limit := intent.Limit
	if limit <= 0 || limit > s.maxRows {
		limit = s.maxRows
	}

	var (
		where []string
		args  []any
	)
	for _, filter := range intent.Filters {
		if err := checkFilter(intent.Entity, filter); err != nil {
			return crydenai.QueryResult{}, err
		}
		args = append(args, filterArgument(filter.Operator, filter.Value))
		where = append(where, fmt.Sprintf("%s %s $%d", filter.Field, sqlOperator(filter.Operator), len(args)))
	}

	statement := buildStatement(intent, columns, where, limit)
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return crydenai.QueryResult{}, fmt.Errorf("aiprovider: running the query: %w", err)
	}
	defer rows.Close()

	return scanResult(rows)
}

// checkFilter refuses a filter whose field or operator is not in cryden's
// allowlist for that entity.
//
// Both names are checked here as well as in the engine. That is not
// redundancy for its own sake: SQL cannot bind a column or an operator
// name, so those two are the only parts of this query that are spliced
// into text rather than passed as parameters, and a second check at the
// point of assembly is what makes "the statement can only contain names
// from a fixed map" a property of this function rather than a claim about
// its callers.
func checkFilter(entity string, filter crydenai.QueryFilter) error {
	if !crydenai.AllowedFields[entity][filter.Field] {
		return fmt.Errorf("aiprovider: field %q is not allowed on %q", filter.Field, entity)
	}
	if !crydenai.AllowedOperators[filter.Operator] {
		return fmt.Errorf("aiprovider: operator %q is not allowed", filter.Operator)
	}
	return nil
}

// buildStatement assembles the SELECT. Every piece spliced into the text
// is a name drawn from cryden's maps — see RunSafeQuery — so the only
// thing a caller influences is the shape, never the vocabulary.
func buildStatement(intent crydenai.QueryIntent, columns, where []string, limit int) string {
	var b strings.Builder

	switch intent.Aggregate {
	case "count":
		b.WriteString("SELECT count(*) FROM ")
		b.WriteString(intent.Entity)
	case "group_by":
		b.WriteString("SELECT ")
		b.WriteString(intent.GroupBy)
		b.WriteString(", count(*) FROM ")
		b.WriteString(intent.Entity)
	default:
		b.WriteString("SELECT ")
		b.WriteString(strings.Join(columns, ", "))
		b.WriteString(" FROM ")
		b.WriteString(intent.Entity)
	}

	if len(where) > 0 {
		b.WriteString(" WHERE ")
		b.WriteString(strings.Join(where, " AND "))
	}
	if intent.Aggregate == "group_by" {
		b.WriteString(" GROUP BY ")
		b.WriteString(intent.GroupBy)
	}
	fmt.Fprintf(&b, " LIMIT %d", limit)
	return b.String()
}

// sqlOperator maps cryden's operator vocabulary onto SQL. "contains" is
// the one that is not a plain symbol: it becomes a LIKE.
func sqlOperator(operator string) string {
	if operator == "contains" {
		return "LIKE"
	}
	return operator
}

// filterArgument prepares a filter's value for its place in the query.
//
// "contains" is the only operator that needs anything done to its value:
// LIKE's wildcards are part of the pattern, so a caller writing
// "contains: a%" would otherwise get substring semantics they did not ask
// for and probably did not intend. The wildcards are added here, around
// the whole value, so the value is always a literal.
//
// This is not a safety measure — the value is a bind parameter either
// way, so neither form can reach the SQL text. It is about the operator
// meaning what it says.
func filterArgument(operator, value string) string {
	if operator == "contains" {
		// Escaped so a literal % or _ in the question stays literal:
		// the default LIKE escape character is a backslash.
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
		return "%" + escaped + "%"
	}
	return value
}

func scanResult(rows *sql.Rows) (crydenai.QueryResult, error) {
	// The header comes from the query rather than from the entity
	// definition, because an aggregate's columns are not the entity's
	// own — a count returns one column that no entity lists.
	names, err := rows.Columns()
	if err != nil {
		return crydenai.QueryResult{}, err
	}

	result := crydenai.QueryResult{Columns: names, Rows: [][]string{}}
	for rows.Next() {
		cells := make([]any, len(names))
		pointers := make([]any, len(names))
		for i := range cells {
			pointers[i] = &cells[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return crydenai.QueryResult{}, err
		}
		row := make([]string, len(names))
		for i, cell := range cells {
			row[i] = renderCell(cell)
		}
		result.Rows = append(result.Rows, row)
	}
	return result, rows.Err()
}

// renderCell turns a scanned value into the string form ai.QueryResult
// promises. Bytes become a string, a time keeps RFC 3339, and a NULL
// becomes empty rather than the word "NULL" — an empty cell is what a
// table shows and what a model reads as "nothing here".
func renderCell(cell any) string {
	switch value := cell.(type) {
	case nil:
		return ""
	case []byte:
		return string(value)
	case time.Time:
		return value.Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", value)
	}
}
