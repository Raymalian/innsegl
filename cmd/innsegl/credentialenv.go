// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// ADR-0078: a credential reaches this binary from a file, never from a
// compose value or a command line, and is never printed.
//
// envSecret reads $NAME, or the first line of the file $NAME_FILE names. The
// stack sets only the _FILE form. Both set is refused rather than resolved:
// a configuration that quietly picks one of two disagreeing sources is how
// #124 shipped.
func envSecret(getenv func(string) string, name string) (string, error) {
	value, file := getenv(name), getenv(name+"_FILE")
	switch {
	case value != "" && file != "":
		return "", fmt.Errorf("both $%s and $%s_FILE are set; set one", name, name)
	case file == "":
		return value, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("reading $%s_FILE: %w", name, err)
	}
	line, _, _ := strings.Cut(string(b), "\n")
	line = strings.TrimSpace(line)
	if line == "" {
		return "", fmt.Errorf("$%s_FILE (%s) is empty", name, file)
	}
	return line, nil
}

// redacted is what -h shows in place of a credential.
const redacted = "xxxxx"

var dsnPasswordParam = regexp.MustCompile(`(password=)[^ &]+`)

// redactDSN hides the password in a connection string, in either of the two
// forms pgx takes, and leaves everything else readable.
func redactDSN(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" && u.User != nil {
		if _, has := u.User.Password(); has {
			u.User = url.UserPassword(u.User.Username(), redacted)
		}
		dsn = u.String()
	}
	return dsnPasswordParam.ReplaceAllString(dsn, "${1}"+redacted)
}

// redactCredentialDefaults rewrites the default -h shows for every flag
// whose default came from a credential variable. A flag's default is read
// from the environment, and in a container that environment is the
// deployment's: before this, `innsegl accounts -h` printed the auth-writer's
// password inside its DSN. Only the shown text changes; the value parsed is
// the same.
func redactCredentialDefaults(fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		switch {
		case f.DefValue == "":
		case strings.HasSuffix(f.Name, "dsn"):
			f.DefValue = redactDSN(f.DefValue)
		case strings.Contains(f.Name, "secret") || strings.Contains(f.Name, "password"):
			f.DefValue = redacted
		}
	})
}
