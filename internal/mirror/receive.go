// SPDX-License-Identifier: Apache-2.0

package mirror

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/event"
)

// The receive endpoint: git's smart HTTP, push only (#464, ADR-0065
// decision 2).
//
//	GET  <GitPathPrefix><repo>.git/info/refs?service=git-receive-pack
//	POST <GitPathPrefix><repo>.git/git-receive-pack
//
// It sits behind the client-certificate guard, which puts the verified
// installation on the request. The handler checks it again (no installation
// is the guard's own refusal), then the repository's scope, then every
// command in the push before git sees any of it. git receive-pack itself runs
// with a clean environment, no hooks, and a bounded request.

// DefaultMaxPushBytes bounds one push request. A commit's objects are small;
// a first push of a large repository's history is the case this has to
// admit, and it is still bounded.
const DefaultMaxPushBytes int64 = 512 << 20

// maxCommands bounds the commands in one push. The client pushes one ref.
const maxCommands = 16

// maxPktLen is git's own largest pkt-line.
const maxPktLen = 65520

// ScopeChecker answers whether an installation may act on a repository
// (accounts.Store.InScope, through the gateway's reader).
type ScopeChecker interface {
	InScope(ctx context.Context, installationID, repo string) (bool, error)
}

// HandlerConfig is what the receive endpoint runs on. Every field but
// MaxBytes is required.
type HandlerConfig struct {
	Store *Store
	Scope ScopeChecker
	// Installation answers the installation the client guard verified
	// (gateway.InstallationFromContext).
	Installation func(context.Context) (string, bool)
	// Refuse writes the guard's one refusal (gateway.WriteClientRefusal),
	// so a refusal here is indistinguishable from the guard's.
	Refuse func(http.ResponseWriter)
	// MaxBytes bounds a push request; zero or less is DefaultMaxPushBytes.
	MaxBytes int64
}

type handler struct {
	cfg HandlerConfig
}

// NewHandler builds the receive endpoint, or refuses an incomplete
// configuration.
func NewHandler(cfg HandlerConfig) (http.Handler, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("mirror: receive endpoint: no store")
	case cfg.Scope == nil:
		return nil, errors.New("mirror: receive endpoint: no scope checker")
	case cfg.Installation == nil:
		return nil, errors.New("mirror: receive endpoint: no installation source")
	case cfg.Refuse == nil:
		return nil, errors.New("mirror: receive endpoint: no refusal writer")
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMaxPushBytes
	}
	return &handler{cfg: cfg}, nil
}

const (
	advertisePath = "/info/refs"
	receivePath   = "/git-receive-pack"
	receiveSvc    = "git-receive-pack"
)

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	installation, ok := h.cfg.Installation(r.Context())
	if !ok || !isInstallationID(installation) {
		h.cfg.Refuse(w)
		return
	}
	repo, action, ok := route(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	in, err := h.cfg.Scope.InScope(r.Context(), installation, repo)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "innsegl core: the client check is unavailable; retry", http.StatusServiceUnavailable)
		return
	}
	if !in {
		h.cfg.Refuse(w)
		return
	}
	switch action {
	case advertisePath:
		h.advertise(w, r, repo)
	case receivePath:
		h.receive(w, r, repo, installation)
	}
}

// route splits <prefix><host>/<org>/<name>.git<action> and answers only an
// identifier doc 02 §5 admits.
func route(urlPath string) (repo, action string, ok bool) {
	rest, ok := strings.CutPrefix(urlPath, commitpath.GitPathPrefix)
	if !ok {
		return "", "", false
	}
	for _, a := range []string{advertisePath, receivePath} {
		if base, found := strings.CutSuffix(rest, a); found {
			repo, isGit := strings.CutSuffix(base, ".git")
			if !isGit || event.ValidateRepo(repo) != nil {
				return "", "", false
			}
			return repo, a, true
		}
	}
	return "", "", false
}

func (h *handler) advertise(w http.ResponseWriter, r *http.Request, repo string) {
	if r.Method != http.MethodGet {
		http.Error(w, "innsegl core: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("service") != receiveSvc {
		http.Error(w, "innsegl core: this endpoint receives pushes only", http.StatusForbidden)
		return
	}
	dir, err := h.cfg.Store.Ensure(r.Context(), repo)
	if err != nil {
		http.Error(w, "innsegl core: the mirror is unavailable", http.StatusInternalServerError)
		return
	}
	out, err := h.cfg.Store.git(r.Context(), dir, nil, "receive-pack", "--stateless-rpc", "--advertise-refs", ".")
	if err != nil {
		http.Error(w, "innsegl core: the mirror is unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-"+receiveSvc+"-advertisement")
	w.Header().Set("Cache-Control", "no-cache")
	var b bytes.Buffer
	b.WriteString(pktLine("# service=" + receiveSvc + "\n"))
	b.WriteString("0000")
	b.Write(out)
	discardWrite(w.Write(b.Bytes()))
}

func (h *handler) receive(w http.ResponseWriter, r *http.Request, repo, installation string) {
	if r.Method != http.MethodPost {
		http.Error(w, "innsegl core: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Content-Type") != "application/x-"+receiveSvc+"-request" {
		http.Error(w, "innsegl core: not a receive-pack request", http.StatusBadRequest)
		return
	}
	var body io.Reader = http.MaxBytesReader(w, r.Body, h.cfg.MaxBytes)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "innsegl core: the request body is not gzip", http.StatusBadRequest)
			return
		}
		defer func() { _ = gz.Close() }()
		// The bound applies to what git reads, too: a small compressed
		// body must not expand without limit.
		body = io.LimitReader(gz, h.cfg.MaxBytes)
	}
	br := bufio.NewReaderSize(body, maxPktLen)
	head, commands, err := readCommands(br)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "innsegl core: the push is over the size this endpoint accepts", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "innsegl core: "+err.Error(), http.StatusBadRequest)
		return
	}
	for _, c := range commands {
		if cerr := checkCommand(c, installation); cerr != nil {
			http.Error(w, "innsegl core: "+cerr.Error(), http.StatusForbidden)
			return
		}
	}
	dir, err := h.cfg.Store.Ensure(r.Context(), repo)
	if err != nil {
		http.Error(w, "innsegl core: the mirror is unavailable", http.StatusInternalServerError)
		return
	}

	// G204: an argument list; dir is the validated repository's mirror.
	cmd := exec.CommandContext(r.Context(), "git", gitArgs(dir, "receive-pack", "--stateless-rpc", ".")...) //nolint:gosec // see above
	cmd.Env = h.cfg.Store.gitEnv()
	cmd.Stdin = io.MultiReader(bytes.NewReader(head), br)
	out := &resultWriter{w: w}
	cmd.Stdout = out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if rerr := cmd.Run(); rerr != nil && !out.started {
		var tooBig *http.MaxBytesError
		if errors.As(rerr, &tooBig) {
			http.Error(w, "innsegl core: the push is over the size this endpoint accepts", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "innsegl core: the mirror refused the push", http.StatusInternalServerError)
	}
}

// readCommands reads the command list at the head of a push, up to and
// including its flush packet, and answers the raw bytes read (to hand on to
// git unchanged) and each command line. Shallow lines are passed through to
// git, which refuses what it does not accept.
func readCommands(br *bufio.Reader) (head []byte, commands []string, err error) {
	var raw bytes.Buffer
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return nil, nil, fmt.Errorf("reading the push's commands: %w", err)
		}
		raw.Write(hdr[:])
		n, perr := strconv.ParseUint(string(hdr[:]), 16, 16)
		if perr != nil {
			return nil, nil, errors.New("the push's commands are not pkt-lines")
		}
		if n == 0 {
			return raw.Bytes(), commands, nil
		}
		if n <= 4 || n > maxPktLen {
			return nil, nil, fmt.Errorf("pkt-line length %d is not a command", n)
		}
		payload := make([]byte, n-4)
		if _, err := io.ReadFull(br, payload); err != nil {
			return nil, nil, fmt.Errorf("reading the push's commands: %w", err)
		}
		raw.Write(payload)
		line := string(payload)
		if strings.HasPrefix(line, "shallow ") {
			continue
		}
		commands = append(commands, line)
		if len(commands) > maxCommands {
			return nil, nil, fmt.Errorf("more than %d ref updates in one push", maxCommands)
		}
	}
}

// checkCommand admits exactly one shape: create or move this installation's
// staging ref for one tool call. No delete, no other ref.
func checkCommand(line, installation string) error {
	line = strings.TrimSuffix(line, "\n")
	if i := strings.IndexByte(line, 0); i >= 0 {
		line = line[:i]
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 || !isHexOID(parts[0]) || !isHexOID(parts[1]) {
		return errors.New("a push command is not `<old> <new> <ref>`")
	}
	ref := parts[2]
	if strings.Trim(parts[1], "0") == "" {
		return fmt.Errorf("deleting %s is refused; the mirror is evidence", ref)
	}
	prefix := commitpath.StagingRef(installation, "")
	if id, ok := strings.CutPrefix(ref, prefix); !ok || !commitpath.IsToolUseID(id) {
		return fmt.Errorf("%s is refused; this endpoint accepts only %s<tool call id>", ref, prefix)
	}
	return nil
}

func isHexOID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func pktLine(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

// resultWriter sets the result's headers on git's first byte and flushes
// each write, so a refusal before git answered can still be a status code.
type resultWriter struct {
	w       http.ResponseWriter
	started bool
}

func (rw *resultWriter) Write(p []byte) (int, error) {
	if !rw.started {
		rw.started = true
		rw.w.Header().Set("Content-Type", "application/x-"+receiveSvc+"-result")
		rw.w.Header().Set("Cache-Control", "no-cache")
		rw.w.WriteHeader(http.StatusOK)
	}
	n, err := rw.w.Write(p)
	if f, ok := rw.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

func discardWrite(int, error) {}
