package admininvite

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/crydensync/api/internal/postgresdb"
	"github.com/crydensync/api/operator"
)

// Run creates a one-time invitation and prints its console link once.
func Run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("csag admin invite", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dbURL := flags.String("db", "", "PostgreSQL DATABASE_URL (required)")
	consoleURL := flags.String("console-url", "", "CSAX+ console origin or base path (required)")
	email := flags.String("email", "", "email address the invitation is bound to (required)")
	role := flags.String("role", "", "role to invite: admin or viewer (required)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *dbURL == "" || *consoleURL == "" || *email == "" || *role == "" {
		return errors.New("usage: csag admin invite --db <DATABASE_URL> --console-url <URL> --email <address> --role <admin|viewer>")
	}
	if err := validateConsoleURL(*consoleURL); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", postgresdb.DSNWithSearchPath(*dbURL, postgresdb.AuthSchema))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	invitation, err := operator.NewStore(db).CreateInvitation(ctx, *email, *role, "")
	if err != nil {
		return err
	}
	link, err := buildInviteURL(*consoleURL, invitation.Token)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Invitation created for %s as %s. It expires %s.\n%s\n", invitation.Email, invitation.Role, invitation.ExpiresAt.Format(time.RFC3339), link)
	return err
}

func validateConsoleURL(base string) error {
	parsed, err := url.Parse(strings.TrimSpace(base))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("console-url must be an http or https URL without credentials, query, or fragment")
	}
	return nil
}

func buildInviteURL(base, token string) (string, error) {
	if err := validateConsoleURL(base); err != nil {
		return "", err
	}
	parsed, _ := url.Parse(strings.TrimSpace(base))
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/invite"
	query := parsed.Query()
	query.Set("token", token)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
