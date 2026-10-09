// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Rekor's search index lives in the log's own database (#451, ADR-0010's
// 2026-10-05 amendment).
//
// The index was a Redis sidecar on a volume of its own. That volume was not
// one of the irreplaceable four, so `down -v` removed it while every entry
// stayed in Trillian, and a verifier asking the log for a commit's entry got
// "no such entry" (OPS-036). Bring-up repaired it by walking the whole log on
// every start. Rekor v1 can keep the same index in MySQL, and trillian-db is
// already persisted on a trust volume, so the index now survives exactly what
// the log survives and nothing has to rebuild it at boot.
//
// These read the repository and need no Docker. The behaviour was measured
// against the pinned images and is recorded in the amendment.
// ---------------------------------------------------------------------------

// The shape: no Redis anywhere in the Sigstore stack, and rekor's index flags
// point at trillian-db.
func TestRekorIndexIsMySQLInTheLogDatabase(t *testing.T) {
	body := readFile(t, filepath.Join(repoRoot(t), "deploy", "compose", "sigstore.yml"))

	if slices.Contains(composeServices(t, filepath.Join(repoRoot(t), "deploy", "compose", "sigstore.yml")), "rekor-redis") {
		t.Error("sigstore.yml still declares rekor-redis; the index lives in trillian-db")
	}
	code := composeCode(body)
	for _, gone := range []string{"rekor-redis", "redis:", "sigstore-rekor-search", "--redis_server."} {
		if strings.Contains(code, gone) {
			t.Errorf("sigstore.yml still carries %q outside a comment", gone)
		}
	}

	rekor := serviceBlock(body, "rekor")
	if !strings.Contains(rekor, `"--search_index.storage_provider=mysql"`) {
		t.Error("rekor does not select the MySQL search index (--search_index.storage_provider=mysql)")
	}
	// The DSN carries this host's password, so it is in Rekor's own config
	// file, which the bootstrap renders (ADR-0078).
	if !strings.Contains(rekor, `"--config=/run/innsegl/credentials/rekor-index/rekor-server.yaml"`) {
		t.Error("rekor does not read its config file, where the index DSN is")
	}
	boot := readFile(t, filepath.Join(repoRoot(t), "deploy", "compose", "sigstore", "bootstrap.sh"))
	dsn := regexp.MustCompile(`dsn: ([^\s\\]+)`).FindStringSubmatch(boot)
	if dsn == nil {
		t.Fatal("the bootstrap renders no index DSN for rekor")
	}
	if !strings.Contains(dsn[1], "@tcp(trillian-db:3306)/") {
		t.Errorf("rekor's index DSN %q does not name trillian-db", dsn[1])
	}
	// Its own database, never Trillian's: rekor writing into the tables its
	// proofs are built from is the one thing this must not allow.
	if strings.HasSuffix(dsn[1], "/test") {
		t.Errorf("rekor's index DSN %q uses Trillian's database", dsn[1])
	}
}

// Least privilege moves from the network to the grant. rekor reaches MySQL
// over a network of two members, still has no route on innsegl-trillian-db,
// and its MySQL user may touch the index database and nothing else.
func TestRekorReachesTheIndexDatabaseAndNothingElse(t *testing.T) {
	root := repoRoot(t)
	body := readFile(t, filepath.Join(root, "deploy", "compose", "sigstore.yml"))

	members := map[string][]string{}
	for _, svc := range composeServices(t, filepath.Join(root, "deploy", "compose", "sigstore.yml")) {
		for _, n := range serviceNetworks(serviceBlock(body, svc)) {
			members[n] = append(members[n], svc)
		}
	}
	if got := members["innsegl-rekor-index"]; !slices.Equal(got, []string{"rekor", "trillian-db"}) {
		t.Errorf("innsegl-rekor-index members = %v, want exactly [rekor trillian-db]", got)
	}
	if slices.Contains(members["innsegl-trillian-db"], "rekor") {
		t.Error("rekor is on innsegl-trillian-db; the front end must have no route to the Trillian pair's network")
	}

	db := serviceBlock(body, "trillian-db")
	if !strings.Contains(db, "--init-file=/run/innsegl/credentials/logdb/init.sql") {
		t.Error("trillian-db does not run the index grant at start (--init-file); " +
			"an existing database volume would never get the user")
	}
	boot := readFile(t, filepath.Join(root, "deploy", "compose", "sigstore", "bootstrap.sh"))
	if !strings.Contains(boot, "/in/rekor-index.sql") || !strings.Contains(body, "./sigstore/rekor-index.sql:/in/rekor-index.sql:ro") {
		t.Error("the bootstrap does not render the init file from sigstore/rekor-index.sql")
	}

	sql := readFile(t, filepath.Join(root, "deploy", "compose", "sigstore", "rekor-index.sql"))
	// The DSN and the grant are written in two files; they must name one user.
	// The password is this host's, filled into the template's placeholder.
	dsn := regexp.MustCompile(`dsn: ([^:]+):(%s)@tcp\(trillian-db:3306\)/([a-z_]+)`).FindStringSubmatch(boot)
	if dsn == nil {
		t.Fatal("rekor's index DSN is not user:password@tcp(trillian-db:3306)/database")
	}
	if want := "CREATE USER '" + dsn[1] + "'@'%' IDENTIFIED BY '@REKOR_INDEX_PASSWORD@';"; !strings.Contains(sql, want) {
		t.Errorf("rekor-index.sql does not create the DSN's user: want %q", want)
	}
	if want := "CREATE DATABASE IF NOT EXISTS " + dsn[3] + ";"; !strings.Contains(sql, want) {
		t.Errorf("rekor-index.sql does not create the DSN's database: want %q", want)
	}
	grants := regexp.MustCompile(`(?im)^\s*GRANT\s.*\sON\s+(\S+)\s+TO\s`).FindAllStringSubmatch(sql, -1)
	if len(grants) == 0 {
		t.Fatal("rekor-index.sql grants nothing")
	}
	for _, g := range grants {
		if g[1] != "rekor_index.*" {
			t.Errorf("rekor-index.sql grants on %s; the index user may reach rekor_index.* only", g[1])
		}
	}
	// MySQL 5.7 reads an init file one statement per line.
	for _, line := range strings.Split(strings.TrimSpace(sql), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "--") && !strings.HasSuffix(line, ";") {
			t.Errorf("rekor-index.sql line %q is not one whole statement", line)
		}
	}
}

// Bring-up backfills the index ONCE, and only when it is behind the log.
//
// Not at every start: that was the cost #451 removed. But not never either: a
// log whose entries predate the move is answered `[]` for every one of them
// until they are backfilled, and between an update and a manual step the
// verifier and the reconciler would call good commits never logged. So the
// path every bring-up takes asks the index how many of this tree's entries it
// holds, and backfills only when that is fewer than the log's size. What the
// script does with each answer is scripts/rekor-reindex-selftest.sh.
func TestBringUpBackfillsOnlyWhenTheIndexIsBehind(t *testing.T) {
	mk := readFile(t, filepath.Join(repoRoot(t), "Makefile"))

	ready := makeRecipe(t, mk, "rekor-index-ready")
	if !strings.Contains(ready, "scripts/rekor-reindex.sh --if-behind") {
		t.Error("rekor-index-ready does not run the conditional backfill (rekor-reindex.sh --if-behind)")
	}
	if regexp.MustCompile(`rekor-reindex\.sh(\s*$|\s+[^-])`).MatchString(ready) || strings.Contains(ready, "$(MAKE) --no-print-directory rekor-reindex") {
		t.Error("rekor-index-ready reindexes unconditionally; that is the every-start walk #451 removed")
	}
	// After the log is pinned, which is what waits for it to answer.
	if p, b := strings.Index(ready, "rekor-tlog-id"), strings.Index(ready, "--if-behind"); p < 0 || b < p {
		t.Error("the backfill does not run after rekor-tlog-id, which waits for the log")
	}
	// The old Redis container is an orphan of the sigstore project now, and
	// is removed BY NAME. Not with --remove-orphans: innsegl-ca-store is a
	// service of this same project declared in sigstore.keycustody.yml, and
	// an `up` of sigstore.yml alone with --remove-orphans would remove it.
	// $(STACK_PREFIX) is innsegl on a live host and innsegl-dev on a dev
	// stack (ADR-0072); either way the name is the project's own.
	if !strings.Contains(ready, "rm -f $(STACK_PREFIX)-sigstore-rekor-redis") {
		t.Error("bring-up does not remove the old rekor-redis container; it would keep running after the upgrade")
	}
	for _, target := range []string{"sigstore-up", "rekor-log-up"} {
		r := makeRecipe(t, mk, target)
		if strings.Contains(r, "--remove-orphans") {
			t.Errorf("%s brings sigstore.yml up with --remove-orphans, which removes innsegl-ca-store "+
				"(sigstore.keycustody.yml, same project)", target)
		}
		if !strings.Contains(r, "$(MAKE) --no-print-directory rekor-index-ready") {
			t.Errorf("%s does not end in rekor-index-ready", target)
		}
	}

	// `make update` reaches it before it starts the core, and touches only the
	// log's services: an `up` of fulcio from sigstore.yml alone would undo the
	// key-custody overlay on a host that uses it.
	logUp := makeRecipe(t, mk, "rekor-log-up")
	// $(SIGSTORE_FILES) is sigstore.yml alone on a live host, and with the dev
	// names overlay on a dev stack (ADR-0072) — never the key-custody overlay.
	if !strings.Contains(logUp, "$(SIGSTORE_FILES) up -d trillian-db trillian-log-server trillian-log-signer rekor") {
		t.Error("rekor-log-up does not bring up exactly the log's services")
	}
	if strings.Contains(logUp, "fulcio") {
		t.Error("rekor-log-up touches fulcio")
	}
	upd := makeRecipe(t, mk, "update")
	l, c := strings.Index(upd, "--no-print-directory rekor-log-up"), strings.Index(upd, "--no-print-directory innsegl-here-services")
	if l < 0 || c < 0 || l > c {
		t.Error("make update does not run rekor-log-up before it starts the core; " +
			"an upgraded host would serve verification from an index that is behind")
	}
}

// The backfill runs Rekor's own backfill tool, of the same release as the
// server, so the keys it writes are the keys the server writes.
func TestTheBackfillToolIsTheServersRelease(t *testing.T) {
	root := repoRoot(t)
	compose := readFile(t, filepath.Join(root, "deploy", "compose", "sigstore.yml"))
	script := readFile(t, filepath.Join(root, "scripts", "rekor-reindex.sh"))

	server := regexp.MustCompile(`rekor-server:(v[0-9.]+)@sha256:`).FindStringSubmatch(compose)
	tool := regexp.MustCompile(`rekor/backfill-index:(v[0-9.]+)@sha256:[0-9a-f]{64}`).FindStringSubmatch(script)
	if server == nil || tool == nil {
		t.Fatalf("could not read both pins: server=%v backfill=%v (pin the tool by tag and digest)", server, tool)
	}
	if server[1] != tool[1] {
		t.Errorf("rekor-server is %s but backfill-index is %s; when one moves, both move", server[1], tool[1])
	}
}

// composeCode is a compose file with its comment lines removed.
func composeCode(body string) string {
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// serviceBlock returns one service's lines, comments removed.
func serviceBlock(body, name string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(composeCode(body), "\n") {
		if m := serviceLine.FindStringSubmatch(line); m != nil {
			in = m[1] == name
			continue
		}
		if line != "" && !strings.HasPrefix(line, " ") {
			in = false
		}
		if in {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// serviceNetworks reads the list under a service's `networks:` key.
func serviceNetworks(block string) []string {
	var out []string
	in := false
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "networks:" {
			in = true
			continue
		}
		if in && strings.HasPrefix(trimmed, "- ") {
			out = append(out, strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
			continue
		}
		in = false
	}
	return out
}

// The Go harnesses that stand up their own Rekor keep the index where the
// shipped stack does, so no test runs against a log shaped differently from
// production: MySQL in trillian-db, created by the same rekor-index.sql.
func TestEveryRekorHarnessKeepsTheIndexInTheLogDatabase(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{
		"internal/segment/rekorharness_test.go",
		"test/chaos/killharness_test.go",
		"test/load/harness_test.go",
	} {
		body := readFile(t, filepath.Join(root, rel))
		if strings.Contains(body, "--redis_server.") || strings.Contains(body, "redis:7") {
			t.Errorf("%s still runs Rekor with a Redis index", rel)
		}
		if !strings.Contains(body, `"--search_index.storage_provider=mysql"`) {
			t.Errorf("%s does not select Rekor's MySQL index", rel)
		}
		if !strings.Contains(body, "deploy/compose/sigstore/rekor-index.sql") ||
			!strings.Contains(body, "--init-file=/etc/mysql/rekor-index.sql") {
			t.Errorf("%s does not create the index user the way trillian-db does (rekor-index.sql via --init-file)", rel)
		}
	}
}
