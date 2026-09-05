// SPDX-License-Identifier: Apache-2.0

package failure

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
)

// sign_commit's own share of MCP-011 (RM-072, #95).
//
// # Why this file and not more of crashharness_test.go
//
// The other four tools run against test/failure's own SPIRE-only stack, with
// -fulcio-url and -rekor-url pointed at a closed port (127.0.0.1:1) because
// nothing before this issue ever needed them to answer. sign_commit needs
// them to answer for real: IP §7 forbids a mocked Fulcio, and RM-034 already
// built the pair of stacks that gives one — sigstoreharness_test.go's
// requireSigStack, its own SPIRE trio configured with an issuer Fulcio
// believes, joined to a real self-hosted Fulcio and Rekor. This file drives
// the SAME shipped `innsegl serve` binary crashharness_test.go builds (the
// campaign's own c.launch), pointed at that stack instead, and reuses
// RM-034's own devices — sigFailProxy, sigCommitObjects, stageSigFile,
// sigStaleLocks — rather than inventing new ones, per this issue's own
// instruction to use what #120 and RM-034 already built.
//
// # requireSigStack's lifetime, and why it is safe to call from here
//
// requireSigStack ties the stack's teardown to the CALLER's own t.Cleanup and
// resets its sync.Once so the next caller gets a fresh incarnation. Called
// once, at the top of signCommit, on signCommit's own *testing.T: the stack
// lives exactly as long as this subtest and is gone before entryCensus and
// reconcile run — which matters, because those two read test/failure's OWN
// SPIRE (c.stack, c.admin), never sig's, and sign_commit's runs are
// registered against sig's SPIRE precisely because Fulcio in this compose
// topology trusts only that one's issuer. A run left ACTIVE in the shared
// ledger with no matching entry in c.stack's SPIRE is exactly the
// spire_entry_missing drift reconcile exists to catch, so every run this file
// registers is retired before signCommit returns (signRetireAll).
//
// # The two named windows, and how each is driven rather than raced
//
// IP §6.5 names them and ADR-0031 fixes where the seam is:
//
//	A -> B  a commit_intent and no signature. Reached by holding the
//	        wrapper's OWN request to Fulcio's certificate endpoint
//	        (sigFulcioCertPath) — the ONLY thing on that path during a
//	        signing call, since the trust-material fetch (decision 2) hits
//	        /api/v1/rootCert, a different path. Once the request arrives at
//	        the proxy it is recorded before it is held (sigFailProxy's own
//	        ordering), so observing it is proof the server is parked there —
//	        the append into Phase A has already happened by construction
//	        (phases() calls Sign only after the intent is written), and
//	        nothing durable follows in this window because the certificate
//	        that would let `git commit` create an object has not arrived.
//
//	B -> C  a commit object and a Rekor entry exist, no commit_recorded.
//	        Reached by holding the wrapper's OWN search
//	        (sigRekorIndexPath, ADR-0031 decision 6's findRekorEntry) rather
//	        than gitsign's own upload, which is POST /api/v1/log/entries — a
//	        different, unheld path, so the object gitsign creates during
//	        `git commit` is unaffected and the online-mode entry it uploads
//	        as part of that call is already real and already in Rekor by the
//	        time our own search would run. Observing the search arrive is
//	        therefore proof the commit and its transparency entry both
//	        already exist and only the ledger append is outstanding.
//
// Both proxies are exact-path matches against endpoints sigFailProxy's own
// SIG-004 already names (sigFulcioCertPath, sigRekorIndexPath), so passing
// through everything else — the trust fetch, gitsign's own upload — needs no
// new logic.
//
// # gitsign is a grandchild, and it survives the SIGKILL
//
// sigFailProxy's own comment records the fact this file has to act on:
// gitsign outlives the SIGKILL that hits `innsegl serve`, because
// exec.CommandContext delivers the signal to the immediate child (`git`) and
// this process is killed before it can run that cleanup at all. While a
// held request is still open, the orphaned process is still holding
// .git/index.lock in the SAME repository every later shot reuses. So a
// held proxy is closed EXPLICITLY the instant this file has read what it
// needs from it (never left to the subtest's own t.Cleanup, which would
// leave it open for the rest of signCommit), and every shot then waits for
// every lock in the repository to clear AND for the killed daemon's own
// process tree to have fully exited (signAwaitLocksClear) before touching
// that repository again or reading its state to classify a shot.
//
// The lock alone is not enough (RM-072, #95): an orphan that has not yet
// reached the point of taking it — still doing its own Fulcio or Rekor round
// trip — leaves nothing for sigStaleLocks to see, and a kill landing anywhere
// before Phase B is exactly a kill that can leave one there. signAwaitLocksClear's
// own comment has the mechanism and the two CI seeds it explains.
type signHoldProxy struct {
	ln   net.Listener
	srv  *http.Server
	rp   *httputil.ReverseProxy
	path string

	closed chan struct{}
	once   sync.Once

	mu   sync.Mutex
	seen int
}

// newSignHoldProxy forwards every request to backend except requests whose
// path is EXACTLY path, which it records — proof the caller reached it — and
// then holds until close (or signHoldGrace, as a backstop against a shot that
// forgets to call it).
func newSignHoldProxy(t *testing.T, backend, path string) *signHoldProxy {
	t.Helper()
	target, err := url.Parse(backend)
	if err != nil {
		t.Fatalf("parsing the hold-proxy backend %q: %v", backend, err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the sign_commit hold proxy: %v", err)
	}
	p := &signHoldProxy{
		ln:     ln,
		rp:     httputil.NewSingleHostReverseProxy(target),
		path:   path,
		closed: make(chan struct{}),
	}
	p.rp.ErrorLog = nopLogger()
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 30 * time.Second, ErrorLog: nopLogger()}
	served := make(chan error, 1)
	go func() { served <- p.srv.Serve(ln) }()
	t.Cleanup(func() {
		p.close()
		if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("the sign_commit hold proxy for %s stopped serving: %v", path, err)
		}
	})
	return p
}

func (p *signHoldProxy) url() string { return "http://" + p.ln.Addr().String() }

func (p *signHoldProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == p.path {
		p.mu.Lock()
		p.seen++
		p.mu.Unlock()
		select {
		case <-r.Context().Done():
		case <-p.closed:
		case <-time.After(signHoldGrace):
		}
		return
	}
	p.rp.ServeHTTP(w, r)
}

// held reports how many requests to path have arrived (and are being, or
// were, withheld).
func (p *signHoldProxy) held() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen
}

// heldTrigger is a killWhen.trigger: it fires the instant a request to path
// is recorded, which sigFailProxy-style proxies do BEFORE blocking, so seeing
// it is proof the caller is now parked and not merely about to be.
func (p *signHoldProxy) heldTrigger() func(context.Context) (bool, error) {
	return func(context.Context) (bool, error) { return p.held() > 0, nil }
}

// close releases anything parked in this proxy. Idempotent: called explicitly
// by every shot the instant it has read `held`, and again (a no-op by then)
// from the t.Cleanup newSignHoldProxy registered as a backstop.
func (p *signHoldProxy) close() {
	p.once.Do(func() {
		close(p.closed)
		_ = p.srv.Close()
	})
}

// ---------------------------------------------------------------------------
// sig's SPIRE, reachable from the host.
// ---------------------------------------------------------------------------

// signParentID polls sig's SPIRE the way startSigStack's own
// registerSigOIDCProvider does, for the attested node every run this file
// registers hangs off. Not exposed on *sigStack itself: nothing in
// sigstoreharness_test.go needs it outside that one call.
func signParentID(t *testing.T, sig *sigStack) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for {
		out, err := sig.sigSpireServer(ctx, "agent", "list")
		if err == nil {
			for _, line := range strings.Split(out, "\n") {
				if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "SPIFFE ID"); ok {
					if id := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":")); id != "" {
						return id
					}
				}
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			t.Fatalf("no attested agent in sig's SPIRE within the deadline: %v", lastErr)
		}
		time.Sleep(2 * time.Second)
	}
}

// signAdminPEMs mints the admin SVID `innsegl serve` needs for sig's SPIRE and
// writes it where the subprocess can read it — the same shape
// crashharness_test.go's own writeAdminPEMs hands the OTHER four subtests,
// against sig's admin socket instead of c.stack's.
func signAdminPEMs(t *testing.T, sig *sigStack) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := sig.sigSpireServer(ctx, "x509", "mint", "-spiffeID", failureAdminID, "-ttl", "2h")
	if err != nil {
		t.Fatalf("mint the admin SVID for sign_commit's daemon: %v", err)
	}
	svidPEM, keyPEM, rootsPEM, err := parseMint(out)
	if err != nil {
		t.Fatalf("parse `x509 mint` output: %v", err)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"svid.pem": svidPEM, "key.pem": keyPEM, "bundle.pem": rootsPEM,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// signAdminProxy publishes sig's SPIRE admin API to a host port, the way
// startStack's own admin proxy does for c.stack — a standalone socat
// container joined to the admin network, because `innsegl serve` runs on the
// host and that network is not otherwise reachable from it.
//
// sig's own admin calls (sigSpireServer) never needed this: they run INSIDE
// the compose project over `docker compose exec`. innsegl serve is a host
// process and IP §6.5's own "the process a deployment runs" is the reason to
// keep it one, so this file gives it the same TCP path stack.startStack
// builds rather than dialling in over exec.
func signAdminProxy(t *testing.T, sig *sigStack) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	port, err := freeHostPort(ctx)
	if err != nil {
		t.Fatalf("reserve a host port for sig's admin proxy: %v", err)
	}
	name := sig.project + "-signadminproxy"
	if _, err := docker(ctx, "run", "--detach", "--name", name,
		"--publish", "127.0.0.1:"+port+":8081",
		envOr("INNSEGL_TEST_PROXY_IMAGE", defaultProxyImage),
		"TCP-LISTEN:8081,fork,reuseaddr", "TCP:spire-server:8081",
	); err != nil {
		t.Fatalf("start sig's admin proxy: %v", err)
	}
	t.Cleanup(func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rmCancel()
		if _, err := docker(rmCtx, "rm", "--force", name); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing %s: %v\n", name, err)
		}
	})
	network := sig.project + "-spire-admin"
	if _, err := docker(ctx, "network", "connect", network, name); err != nil {
		t.Fatalf("join %s to %s: %v", name, network, err)
	}
	return "127.0.0.1:" + port
}

// ---------------------------------------------------------------------------
// The workspace sign_commit signs in.
// ---------------------------------------------------------------------------

// signRepo is doc 02 §5's grammar: three lowercase-host segments, so
// sign_commit's Workspace resolves it under root without a filesystem path
// ever crossing the wire.
const signRepo = "signtest.invalid/mcp011/repo"

// signWorkspace makes the working tree sign_commit's -workspace root
// resolves signRepo to.
func signWorkspace(t *testing.T) (root, repoDir string) {
	t.Helper()
	root = t.TempDir()
	repoDir = filepath.Join(root, filepath.FromSlash(signRepo))
	if err := os.MkdirAll(repoDir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", repoDir, err)
	}
	cmd := exec.CommandContext(t.Context(), "git", "-C", repoDir, "init", "-q", "-b", "main")
	cmd.Env = sigGitEnv(repoDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init %s: %v: %s", repoDir, err, out)
	}
	return root, repoDir
}

// signStage stages a uniquely named file so every shot's tree differs from
// every other's — StagedTree refuses an empty commit, which is exactly the
// state a successful PRIOR shot in the SAME repository leaves the index in.
//
// The index is reset to HEAD first, and a unique filename is not enough
// without it. A shot that was refused or killed leaves its own file staged;
// the next shot that COMMITS sweeps that file in along with its own, because
// git commits the whole index. The first shot's replay then finds its file
// already committed, write-tree returns HEAD's own tree, and the server
// refuses an empty commit — a harness sequencing fault reported as though the
// tool had violated an invariant.
//
// Seen on CI at seed 1788593655011433377, where a blind stratum drew a delay
// past the uninterrupted call's own duration (744ms against 669ms), completed,
// and committed an earlier refused shot's file with its own.
func signStage(t *testing.T, repo, tag string) (tree string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", "-C", repo, "reset", "-q")
	cmd.Env = sigGitEnv(repo)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git reset in %s: %v: %s", repo, err, out)
	}
	stageSigFile(t, repo, "shot-"+tag+".txt", "innsegl RM-072 "+tag+"\n")
	return sigGitOut(t, repo, "write-tree")
}

// signAwaitLocksClear waits for every git lock in repo to be gone and for
// every pid in orphans to have exited, before the caller reads state to
// classify a shot or replays into it. orphans is nil for a caller with no
// killed daemon of its own (the replay daemons signSuccessfulTakeover and
// signRefusedTakeover launch, which complete their one call in-process and
// leave nothing orphaned) — the wait is then just the lock check it always
// was.
//
// # Why the lock check alone is not proof, and #95's real mechanism
//
// A gitsign process orphaned by SIGKILL (git's grandchild; it survives the
// parent's death, see this file's header comment) does not take `git`'s
// index lock until it has already gone through its own certificate request
// and signing round trip. Checking only for the lock proves the orphan has
// FINISHED once it has started touching the index — it proves nothing about
// an orphan that has not reached that point yet, and a kill landing anywhere
// before Phase B is exactly a kill that leaves one still in flight, doing a
// real Fulcio/Rekor round trip with no lock held at all.
//
// #95's two CI-only seeds are that gap made concrete: a blind kill classified
// as landing before Phase A or between A and B (sigStaleLocks saw nothing,
// so the wait returned at once) with the orphan from THAT SAME shot still
// running underneath it. The orphan went on to finish the commit for real —
// intent already on the chain, a real Rekor entry, no commit_recorded, since
// the only process that would append it is the one already dead — and it did
// so between the stale classification and signSuccessfulTakeover's own
// replay, which then found the tree it was asked to sign already sitting at
// HEAD and was refused for an empty commit. That refusal was correct; the
// classification that sent it down the replay-and-compare path instead of
// the refusal-is-the-assertion path was not. Neither of the two earlier
// attempts at this file's classification (the idempotency row's presence,
// then its COMPLETED status) could have caught this: the row a takeover
// consults is written only by the phases() call that finishes it, and an
// orphan that dies without ever reaching Phase C leaves that row exactly as
// `in_progress` as one that never started at all. What distinguishes the two
// is the process tree, not the row, so this is where the fix belongs.
//
// # Why orphans is a pid LIST captured DURING the call, not an ancestry walk done AFTER it
//
// A first version of this wait re-derived the tree after the kill, by
// walking `ps`'s ppid column outward from the daemon's own pid. That is
// unsound the instant the daemon is actually dead: the operating system
// reparents an orphan onto its subreaper (PID 1, ordinarily) as PART OF
// tearing the dead process down, which on both Linux and Darwin happens
// essentially as soon as SIGKILL lands — by the time this file's own code
// gets to run `ps` at all, a real orphan's ppid no longer names the daemon it
// came from, so an ancestry walk starting from that pid finds nothing and
// waits for nothing. signOrphanWatch exists because of that: it walks the
// SAME ppid chase, but continuously, WHILE the daemon is still alive and its
// children's ppid still says so — recording every pid it ever sees, so a
// child that exists for even one poll is remembered no matter what its ppid
// reads after its parent is gone. What this function is then given is not
// "whoever descends from pid right now" but "whoever was ever seen to,"
// checked the only way that still means something once the parent is dead:
// does the pid still exist at all.
func signAwaitLocksClear(t *testing.T, repo string, orphans []int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		stale := sigStaleLocks(t, repo)
		living := alivePids(orphans)
		if len(stale) == 0 && len(living) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("git lock(s) %v in %s and/or orphaned process(es) %v did not clear within 30s; "+
				"an orphaned gitsign process (git's grandchild, which survives the parent's SIGKILL) "+
				"may still be running against a real Fulcio/Rekor", stale, repo, living)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// alivePids filters pids down to the ones that still exist, in the sense
// that matters once their parent may be dead: not "is pid a descendant of
// anything," just "does a process by this number still exist" (a zombie the
// subreaper has not yet collected counts as existing — it is not gone until
// it is gone).
func alivePids(pids []int) []int {
	var living []int
	for _, pid := range pids {
		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		// Signal 0 sends nothing; it only asks the kernel whether pid could be
		// signalled, which is true iff it still exists.
		if proc.Signal(syscall.Signal(0)) == nil {
			living = append(living, pid)
		}
	}
	return living
}

// signOrphanWatch continuously records every pid that is, AT THE MOMENT
// observed, a descendant of one root pid — for as long as it runs, which
// must be the whole time that root pid is alive. See signAwaitLocksClear's
// own comment for why "continuously, while it is alive" is load-bearing:
// once the root is dead, its real children's ppid no longer says so, so a
// single walk taken afterward proves nothing.
type signOrphanWatch struct {
	root int
	stop chan struct{}
	done chan struct{}
	mu   sync.Mutex
	seen map[int]struct{}
}

// signOrphanPollInterval bounds how long a child could exist and still be
// missed. Short against the hundreds of milliseconds a real Fulcio + Rekor
// round trip takes, so `git`'s own gitsign child is polled for many times
// over across any call this file makes — never depended on for a single
// sample.
const signOrphanPollTimeout = 5 * time.Second

const signOrphanPollInterval = 5 * time.Millisecond

// startSignOrphanWatch begins watching root's descendants. The caller stops
// it with stopAndWait once root cannot fork anything new — in this file,
// once root has been SIGKILLed.
func startSignOrphanWatch(root int) *signOrphanWatch {
	w := &signOrphanWatch{root: root, stop: make(chan struct{}), done: make(chan struct{}), seen: map[int]struct{}{}}
	go func() {
		defer close(w.done)
		ticker := time.NewTicker(signOrphanPollInterval)
		defer ticker.Stop()
		// Bounded per poll, not per watch: one `ps` that hangs must not stall
		// the ticker, and the watch's own lifetime is the caller's to end.
		for {
			pollCtx, cancelPoll := context.WithTimeout(context.Background(), signOrphanPollTimeout)
			pids := psDescendants(pollCtx, w.root)
			cancelPoll()
			for _, pid := range pids {
				w.mu.Lock()
				w.seen[pid] = struct{}{}
				w.mu.Unlock()
			}
			select {
			case <-w.stop:
				return
			case <-ticker.C:
			}
		}
	}()
	return w
}

// stopAndWait halts the watcher's own goroutine and blocks until it has
// actually stopped, so pids cannot race a scan still in flight.
func (w *signOrphanWatch) stopAndWait() {
	close(w.stop)
	<-w.done
}

// pids returns every pid this watch ever saw descended from its root, in the
// snapshot it happened to be taken in — which is exactly what
// signAwaitLocksClear needs and an ancestry walk taken after the root is
// dead cannot give it.
func (w *signOrphanWatch) pids() []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]int, 0, len(w.seen))
	for pid := range w.seen {
		out = append(out, pid)
	}
	return out
}

// psDescendants returns the pids presently alive whose ppid chain traces
// back to root, direct or not. Valid only while root itself is alive — see
// signAwaitLocksClear's own comment on why this is a building block for
// signOrphanWatch and not a replacement for it.
//
// `ps -Ao pid=,ppid=` rather than /proc: this harness already runs on both
// Linux (CI) and Darwin (a contributor's machine, per this file's own
// header), and that flag set is the one BSD and GNU ps agree on.
func psDescendants(ctx context.Context, root int) []int {
	out, err := exec.CommandContext(ctx, "ps", "-Ao", "pid=,ppid=").Output()
	if err != nil {
		// Not fatal: this runs many times a second from a background
		// goroutine with no *testing.T of its own, and ps losing a race
		// against a process exiting mid-listing (common under load) must not
		// end the watch. A poll that finds nothing this time is retried next
		// tick, and startSignOrphanWatch's caller bounds the whole wait.
		return nil
	}
	children := map[int][]int{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		child, cerr := strconv.Atoi(fields[0])
		parent, perr := strconv.Atoi(fields[1])
		if cerr != nil || perr != nil {
			continue
		}
		children[parent] = append(children[parent], child)
	}
	var descendants []int
	queue := []int{root}
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		for _, child := range children[next] {
			descendants = append(descendants, child)
			queue = append(queue, child)
		}
	}
	return descendants
}

// ---------------------------------------------------------------------------
// The wire contract, read from the outside.
// ---------------------------------------------------------------------------

type signReply struct {
	CommitSHA  string `json:"commit_sha"`
	RekorEntry struct {
		UUID         string `json:"uuid"`
		LogIndex     int64  `json:"log_index"`
		LogID        string `json:"log_id"`
		IntegratedAt string `json:"integrated_at"`
	} `json:"rekor_entry"`
	Trailers []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"trailers"`
}

func signArgs(runID, tree, message, key string) map[string]any {
	return map[string]any{
		"run_id":          runID,
		"repo":            signRepo,
		"staged_ref":      tree,
		"message":         message,
		"task_ref":        crashTaskID,
		"idempotency_key": key,
	}
}

// signFlags is what one sign_commit daemon needs beyond what startVia already
// knows how to build for the other four tools: it runs against sig's SPIRE
// and a real (or, mid-shot, a held) Fulcio and Rekor.
type signFlags struct {
	spireAddr, pemDir, parentID, workspace, fulcioURL, rekorURL, gitsign string
}

// launchSign starts `innsegl serve` fully configured for sign_commit, through
// campaign.launch — the SAME process-management code startVia uses for the
// other four subtests, so the process this file kills is still the shipped
// binary and not a purpose-built stand-in.
func (c *campaign) launchSign(t *testing.T, f signFlags) *daemon {
	t.Helper()
	return c.launch(t,
		"-dsn", c.dsn,
		"-spire-address", f.spireAddr,
		"-trust-domain", failureTrustDomain,
		"-spire-server-id", failureServerID,
		"-parent-id", f.parentID,
		"-svid", filepath.Join(f.pemDir, "svid.pem"),
		"-key", filepath.Join(f.pemDir, "key.pem"),
		"-bundle", filepath.Join(f.pemDir, "bundle.pem"),
		"-listen", "127.0.0.1:0",
		"-health-listen", "127.0.0.1:0",
		"-idempotency-lease", crashLease.String(),
		"-register-rate-calls", "0",
		"-identity-mode", "literal",
		"-workspace", f.workspace,
		"-oidc-issuer", sigIssuer,
		"-sign-author-name", sigAuthorFullName,
		"-sign-author-email", sigAuthorEmailAddr,
		"-sign-author-allow-unlinked",
		"-gitsign", f.gitsign,
		"-fulcio-url", f.fulcioURL,
		"-rekor-url", f.rekorURL,
	)
}

// signRegister registers one run on a fresh, uninterrupted sign daemon.
func (c *campaign) signRegister(t *testing.T, f signFlags, prefix string) registerReply {
	t.Helper()
	d := c.launchSign(t, f)
	session := c.connect(t, d, d.addr)
	out := c.callOnce(t, session, mcp.ToolRegisterAgent, map[string]any{
		"agent_type": crashAgentType, "task_id": crashTaskID,
		"idempotency_key": c.name(prefix),
	})
	d.reap()
	var reply registerReply
	decodeInto(t, out, &reply)
	if reply.RunID == "" || reply.SPIFFEID == "" {
		t.Fatalf("register_agent returned %+v; IP §4 requires all three members", reply)
	}
	return reply
}

// signRetire retires one run on a fresh daemon, so the shared ledger shows it
// inactive before c.reconcile compares "active runs" against c.stack's SPIRE
// — a run this file registered against sig's DIFFERENT SPIRE would otherwise
// read as spire_entry_missing drift there, for a reason that has nothing to
// do with either reconciler or SPIRE.
func (c *campaign) signRetire(t *testing.T, f signFlags, runID string) {
	t.Helper()
	d := c.launchSign(t, f)
	session := c.connect(t, d, d.addr)
	c.callOnce(t, session, mcp.ToolRetireAgent, map[string]any{"run_id": runID})
	d.reap()
}

// ---------------------------------------------------------------------------
// Reading back what a shot left behind.
// ---------------------------------------------------------------------------

// signEventByTree finds the event of one type carrying one tree hash. Used
// instead of idempotency_key because Phase A and Phase C carry a DERIVED key
// (internal/mcp keeps the derivation unexported, deliberately — two callers
// deriving the same namespacing is a coincidence this project does not want
// to depend on) and the tree hash this file staged is unique per shot by
// construction (signStage), so it identifies the same event unambiguously.
func signEventByTree(records []event.Fields, eventType, tree string) (event.Fields, bool) {
	for _, rec := range records {
		if kind, ok := rec[event.FieldEventType].(string); !ok || kind != eventType {
			continue
		}
		if th, ok := rec[event.FieldTreeHash].(string); !ok || th != tree {
			continue
		}
		return rec, true
	}
	return nil, false
}

func countEventsWithTree(records []event.Fields, eventType, tree string) int {
	n := 0
	for _, rec := range records {
		if kind, ok := rec[event.FieldEventType].(string); !ok || kind != eventType {
			continue
		}
		if th, ok := rec[event.FieldTreeHash].(string); !ok || th != tree {
			continue
		}
		n++
	}
	return n
}

// ---------------------------------------------------------------------------
// Firing one shot: dispatch sign_commit, kill under it, report what the
// caller got. Mirrors campaign.fire's shape; separate because sign_commit's
// daemon is launched with signFlags, not startVia's fixed closed-port ones.
// ---------------------------------------------------------------------------

// fireSign returns the shot AND every pid seen descended from the daemon it
// killed, for as long as that daemon was alive to have descendants at all
// (signOrphanWatch) — so the caller can wait out whatever the SIGKILL
// orphaned (signAwaitLocksClear) before it reads any state to classify the
// shot.
func (c *campaign) fireSign(t *testing.T, f signFlags, args map[string]any, when killWhen) (shot, []int) {
	t.Helper()
	d := c.launchSign(t, f)
	session := c.connect(t, d, d.addr)

	// Started now, not just before the kill: `git commit` is spawned partway
	// through the call this file is about to dispatch, and the watch has to
	// already be running by then to ever see it — see signOrphanWatch's own
	// comment on why "continuously, while the root is alive" is the whole
	// mechanism.
	watch := startSignOrphanWatch(d.cmd.Process.Pid)

	type outcome struct {
		res *sdk.CallToolResult
		err error
	}
	done := make(chan outcome, 1)
	// A real Fulcio/Rekor round trip, not a Postgres one: a bound wide enough
	// that an uninterrupted call never trips it, even under contention.
	callCtx, cancelCall := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancelCall()

	dispatched := time.Now()
	go func() {
		res, err := session.CallTool(callCtx, &sdk.CallToolParams{
			Name: string(mcp.ToolSignCommit), Arguments: args,
		})
		done <- outcome{res, err}
	}()

	s := shot{}
	if when.trigger != nil {
		s.triggerFired = c.waitForState(t, when.trigger)
	} else {
		remaining := when.after - time.Since(dispatched)
		if remaining > 0 {
			time.Sleep(remaining)
		}
		s.triggerFired = true
	}
	s.killedAfter = time.Since(dispatched)
	d.kill(t)
	c.countKill()
	// Stopped only now: the daemon is confirmed dead (d.kill already reaped
	// its wait status), so it can fork nothing further, and the watch's own
	// pid list is final.
	watch.stopAndWait()
	orphans := watch.pids()

	out := <-done
	s.callErr = out.err
	if out.err == nil && out.res != nil {
		if out.res.IsError {
			t.Fatalf("sign_commit(%v) failed on the wire: %v\n(kill was %s after dispatch, intent %q)",
				args, out.res.StructuredContent, s.killedAfter, when.label)
		}
		s.delivered = out.res.StructuredContent
	}
	return s, orphans
}

// ---------------------------------------------------------------------------
// One shot, classified, and its takeover.
// ---------------------------------------------------------------------------

// signShot runs one crash-and-replay of sign_commit and returns the window
// the kill actually landed in, read back from the object database and the
// chain — never inferred from the delay or from what was aimed at.
func (c *campaign) signShot(
	t *testing.T, f signFlags, repoDir string, runID, why, target string, delay time.Duration,
) string {
	t.Helper()
	key := c.name("sign-key")
	tree := signStage(t, repoDir, strings.NewReplacer("/", "-", "_", "-").Replace(key))
	args := signArgs(runID, tree, "commit for "+key, key)

	shotFlags := f
	var hold *signHoldProxy
	when := killWhen{label: why, after: delay}
	switch target {
	case "":
	case winSignIntentNoObject:
		// The wrapper's own request to Fulcio's certificate endpoint — see
		// this file's header comment. Held from dispatch: nothing else on
		// this path exists before Phase A has already been appended.
		hold = newSignHoldProxy(t, f.fulcioURL, sigFulcioCertPath)
		shotFlags.fulcioURL = hold.url()
		when.trigger = hold.heldTrigger()
	case winSignObjectNoRecord:
		// The wrapper's own Rekor SEARCH (ADR-0031 decision 6), not gitsign's
		// own upload (a different path) — see this file's header comment.
		hold = newSignHoldProxy(t, f.rekorURL, sigRekorIndexPath)
		shotFlags.rekorURL = hold.url()
		when.trigger = hold.heldTrigger()
	default:
		t.Fatalf("sign_commit has no trigger for %q", target)
	}

	before := len(sigCommitObjects(t, repoDir))
	s, orphans := c.fireSign(t, shotFlags, args, when)
	if when.trigger != nil && !s.triggerFired {
		t.Fatalf("%s: the state to interrupt never appeared within %s (seed %d)",
			why, crashTriggerBudget, c.seed)
	}
	if hold != nil {
		// Released HERE, not at the subtest's own cleanup: an orphaned
		// gitsign holds .git/index.lock in the SAME repository every later
		// shot reuses, and the replay below needs that lock free.
		hold.close()
	}
	// orphans, not nil: this daemon was just SIGKILLed, and whatever it may
	// have orphaned (#95) has to be confirmed gone before the reads just
	// below classify this shot — see signAwaitLocksClear's own comment.
	signAwaitLocksClear(t, repoDir, orphans)

	// --- classify, from durable state ---------------------------------
	_, hasIntent := signEventByTree(c.chain(t), event.EventTypeCommitIntent, tree)
	objectCreated := len(sigCommitObjects(t, repoDir)) > before
	_, hasRecorded := signEventByTree(c.chain(t), event.EventTypeCommitRecorded, tree)
	// The chain is not the whole of "recorded". sign_commit runs its phases
	// INSIDE c.idem.Do, so a replay returns the stored reply without reaching
	// StagedTree at all — but only if the idempotency row was written. A kill
	// between the `commit_recorded` append and that row leaves the chain
	// saying recorded and the store saying nothing, and a replay then re-runs
	// the phases against an index the first attempt's own commit already
	// emptied. That is the B -> C shape, not a lost reply: the takeover is
	// refused, and asking the chain alone would send it down the successful
	// path and report the refusal as a fault.
	// COMPLETED and not merely present: a claimed row whose call never
	// finished is exactly the row Do takes over and re-runs, so it buys the
	// replay nothing — the phases run again against the emptied index just as
	// if no row existed at all.
	//
	// This check alone does not make #95 hold — its two CI seeds were a
	// DIFFERENT gap, in what "before" these reads means rather than in what
	// they mean once taken; signAwaitLocksClear (called above, before any of
	// this runs) is what closes that one.
	idemRec, idemFound := c.idemRecord(t, key)
	replayable := idemFound && idemRec.Status == crashCompleted

	var window string
	switch {
	case !hasIntent && !objectCreated:
		window = winSignBeforeIntent
	case !objectCreated:
		window = winSignIntentNoObject
	case !hasRecorded || !replayable:
		window = winSignObjectNoRecord
	case s.delivered == nil:
		window = winSignRecordedNoReply
	default:
		window = winSignSeen
	}
	c.landed(target, window)

	if window == winSignObjectNoRecord {
		c.signRefusedTakeover(t, why, f, repoDir, tree, key, runID, before)
	} else {
		c.signSuccessfulTakeover(t, why, f, repoDir, tree, key, runID, s, before)
	}
	return window
}

// signSuccessfulTakeover is every landing except the B -> C window: a replay
// must complete the commit exactly once in total (across the crashed
// attempt and the replay together) and record it exactly once, whether the
// crashed attempt did nothing at all, left a dangling intent, or already
// finished and only the reply was lost.
func (c *campaign) signSuccessfulTakeover(
	t *testing.T, why string, f signFlags, repoDir, tree, key, runID string, s shot, before int,
) {
	t.Helper()
	args := signArgs(runID, tree, "commit for "+key, key)

	rec, claimed := c.idemRecord(t, key)

	d := c.launchSign(t, f)
	session := c.connect(t, d, d.addr)
	first := c.callOnce(t, session, mcp.ToolSignCommit, args)
	second := c.callOnce(t, session, mcp.ToolSignCommit, args)
	d.reap()
	// nil, not a watch of this daemon: it was never SIGKILLed mid-call — both
	// calls above already returned, so its own git commit (if any) has
	// already finished by construction — and a caller that DID time out
	// above already failed the test via callOnce's own t.Fatalf before
	// reaching here.
	signAwaitLocksClear(t, repoDir, nil)

	c.sameReply(t, why, "two replays of one sign_commit request", first, second)
	if claimed && rec.Status == crashCompleted {
		c.requireOriginalReply(t, why, first, rec.Response)
	}
	if s.delivered != nil {
		c.sameReply(t, why, "the reply the caller had before the crash and the replay", s.delivered, first)
	}

	var reply signReply
	decodeInto(t, first, &reply)
	if reply.CommitSHA == "" || reply.RekorEntry.UUID == "" {
		t.Fatalf("%s: sign_commit replied %+v; IP §4 requires commit_sha and rekor_entry.uuid (seed %d)",
			why, reply, c.seed)
	}

	after := len(sigCommitObjects(t, repoDir))
	if after != before+1 {
		t.Fatalf("%s: the repository holds %d new commit object(s) across this shot and its "+
			"replay together, want exactly 1. IP §6.6: never a second commit. (seed %d)",
			why, after-before, c.seed)
	}
	records := c.chain(t)
	if n := countEventsWithTree(records, event.EventTypeCommitRecorded, tree); n != 1 {
		t.Fatalf("%s: the chain holds %d commit_recorded event(s) for this shot's tree, want "+
			"exactly 1 (seed %d)", why, n, c.seed)
	}
	if n := countEventsWithTree(records, event.EventTypeCommitIntent, tree); n != 1 {
		t.Fatalf("%s: the chain holds %d commit_intent event(s) for this shot's tree, want "+
			"exactly 1 (seed %d)", why, n, c.seed)
	}
	c.verifyChainNow(t, records)
}

// signRefusedTakeover is RM-033's one place sign_commit is not self-healing,
// asserted rather than fixed: a lease takeover landing in the B -> C window
// must be REFUSED, not repaired, and must not sign a second commit.
//
// ADR-0031 decision 6 keeps internal/signing's Rekor SEARCH (findRekorEntry)
// unexported on purpose. Recovering the entry for a commit that already
// exists is exactly what a repair would need, and that repair belongs to
// RM-035's reconciler — not run here, and not this issue's to build. What
// this file owns is proving the refusal actually happens: GitRepos.StagedTree
// refuses when the index is already the tree at HEAD, which is precisely the
// state this window leaves the repository in (the crashed attempt's `git
// commit` already moved HEAD to this shot's tree before the ledger append
// that would have closed Phase C).
func (c *campaign) signRefusedTakeover(
	t *testing.T, why string, f signFlags, repoDir, tree, key, runID string, before int,
) {
	t.Helper()
	args := signArgs(runID, tree, "commit for "+key, key)

	// The lease is short (crashLease) and the other four subtests take it
	// over with no explicit wait, because starting and connecting a fresh
	// daemon ordinarily outlasts it already. Waited out explicitly here
	// anyway: this is the one call in the file whose whole point is the
	// refusal, not a race against the lease clock.
	time.Sleep(crashLease + 250*time.Millisecond)

	d := c.launchSign(t, f)
	session := c.connect(t, d, d.addr)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	res, err := session.CallTool(ctx, &sdk.CallToolParams{
		Name: string(mcp.ToolSignCommit), Arguments: args,
	})
	cancel()
	d.reap()
	// nil: this call is refused before Phase B (StagedTree's own check, IP
	// §6.5's ordering), so this daemon orphans nothing — see
	// signSuccessfulTakeover's identical call for the fuller reasoning.
	signAwaitLocksClear(t, repoDir, nil)

	if err != nil {
		t.Fatalf("%s: replaying into the B -> C window: transport failure %v (seed %d)", why, err, c.seed)
	}
	if !res.IsError {
		var reply signReply
		decodeInto(t, res.StructuredContent, &reply)
		t.Fatalf("%s: a lease takeover landing in the B -> C window was ADMITTED, returning "+
			"commit %s. ADR-0031 decision 6 keeps findRekorEntry unexported for exactly this "+
			"reason: recovering a Rekor entry for an existing commit is the reconciler's job "+
			"(RM-035), not this tool's, and a takeover that repairs the window silently is the "+
			"design ADR-0031 already refused. (seed %d)", why, reply.CommitSHA, c.seed)
	}
	class, retryable, message := errorOnTheWire(t, res)
	if class != string(mcp.ClassInvariantViolation) {
		t.Fatalf("%s: the B -> C takeover was refused as %s, want %s: %s (seed %d)",
			why, class, mcp.ClassInvariantViolation, message, c.seed)
	}
	if retryable {
		t.Errorf("%s: the B -> C refusal is marked retryable; a caller told to retry would "+
			"re-run Phase B, and this window must not invite a second signature. (seed %d)",
			why, c.seed)
	}
	t.Logf("%s: the B -> C takeover was refused as %s: %s", why, class, message)

	after := len(sigCommitObjects(t, repoDir))
	if after != before+1 {
		t.Fatalf("%s: the repository holds %d commit object(s) more than before this shot, want "+
			"exactly 1 (the crashed attempt's own commit, and no second one from the refused "+
			"takeover). IP §6.6: never a second commit. (seed %d)", why, after-before, c.seed)
	}
	records := c.chain(t)
	if n := countEventsWithTree(records, event.EventTypeCommitRecorded, tree); n != 0 {
		t.Fatalf("%s: %d commit_recorded event(s) exist for this shot's tree; a refused takeover "+
			"must not have appended one — only the reconciler (not run here) may repair this "+
			"window. (seed %d)", why, n, c.seed)
	}
	if n := countEventsWithTree(records, event.EventTypeCommitIntent, tree); n != 1 {
		t.Fatalf("%s: %d commit_intent event(s) exist for this shot's tree, want exactly 1 "+
			"(seed %d)", why, n, c.seed)
	}
	c.verifyChainNow(t, records)
}

// ---------------------------------------------------------------------------
// The subtest.
// ---------------------------------------------------------------------------

func (c *campaign) signCommit(t *testing.T) {
	sig := requireSigStack(t)

	root, repoDir := signWorkspace(t)
	f := signFlags{
		spireAddr: signAdminProxy(t, sig),
		pemDir:    signAdminPEMs(t, sig),
		parentID:  signParentID(t, sig),
		workspace: root,
		fulcioURL: sig.fulcioURL,
		rekorURL:  sig.rekorURL,
		gitsign:   sig.gitsignPath,
	}

	run := c.signRegister(t, f, "sign-run")
	t.Cleanup(func() { c.signRetire(t, f, run.RunID) })

	// Calibration. The blind campaign's window is THIS deployment's measured
	// call duration — a real Fulcio round trip plus a Rekor upload, far
	// slower than the other four tools' Postgres round trips — not a number
	// typed in.
	before := len(sigCommitObjects(t, repoDir))
	tree := signStage(t, repoDir, "warm")
	args := signArgs(run.RunID, tree, "warm commit", c.name("sign-warm-key"))

	d := c.launchSign(t, f)
	session := c.connect(t, d, d.addr)
	started := time.Now()
	out := c.callOnce(t, session, mcp.ToolSignCommit, args)
	took := time.Since(started)
	d.reap()

	var warm signReply
	decodeInto(t, out, &warm)
	if warm.CommitSHA == "" || warm.RekorEntry.UUID == "" {
		t.Fatalf("the uninterrupted control replied %+v; IP §4 requires commit_sha and "+
			"rekor_entry.uuid", warm)
	}
	if after := len(sigCommitObjects(t, repoDir)); after != before+1 {
		t.Fatalf("the uninterrupted control left %d new commit object(s), want exactly 1", after-before)
	}

	blind := envInt("INNSEGL_CRASH_SIGN_BLIND", crashSignBlindDefault)
	// Four fifths of the measured call, where the other four tools use five
	// quarters. sign_commit is the one tool whose success CONSUMES the thing
	// its own replay needs: the commit empties the index, so a kill that lands
	// after the call has actually finished must be classified and replayed
	// against a tree that may already be at HEAD.
	//
	// Narrowing the draw keeps most blind kills inside the call rather than
	// past it, which is what a blind stratum is for — but it was never what
	// #95 needed to hold, and does not by itself make it hold: a kill drawn
	// well inside the call can still leave an orphaned gitsign (git's
	// grandchild; it survives the parent's SIGKILL, see this file's header
	// comment) running underneath it, which finishes on its own time and not
	// on the harness's. signAwaitLocksClear is what actually closes that race
	// — see its own comment for the mechanism and #95's two CI seeds — by
	// waiting for the killed daemon's whole process tree to be gone, not only
	// for the .git lock a straggler has not necessarily taken yet, before
	// anything here reads state to classify or replay a shot. This narrowing
	// stays regardless: the landing after completion is not lost coverage
	// (winSignSeen is reached by the uninterrupted control above, and the two
	// windows that matter — IP §6.5's A -> B and B -> C — have aimed shots
	// that drive them rather than hoping a stratum lands there), and keeping
	// most blind kills inside the call is still the more informative use of a
	// blind stratum's draw.
	window := took * 4 / 5
	t.Logf("sign_commit completes uninterrupted in %s (a real Fulcio + Rekor round trip); "+
		"blind kills are drawn from [0, %s) across %d strata, seed %d", took, window, blind, c.seed)

	// THE AIMED SHOTS GO FIRST (RM-082, #120): both of IP §6.5's named
	// windows are covered by these shots and by these shots alone. An aimed
	// shot draws no number from the campaign's generator, so
	// INNSEGL_CRASH_SEED still replays the identical blind schedule.
	for _, target := range []string{winSignIntentNoObject, winSignObjectNoRecord} {
		c.aim(t, target, func(t *testing.T) string {
			return c.signShot(t, f, repoDir, run.RunID, "observed trigger for "+target, target, 0)
		})
	}

	for i, delay := range c.strata(window, blind) {
		t.Logf("blind stratum %d/%d: kill %s after dispatch -> %s", i+1, blind, delay,
			c.signShot(t, f, repoDir, run.RunID,
				fmt.Sprintf("blind stratum %d, +%s", i+1, delay), "", delay))
	}
}
