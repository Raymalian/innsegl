// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/version"
)

// `innsegl retire <run_id>` — RM-154 (#257).
//
// # Why an operator needs this
//
// Nothing in this system can observe that an agent died. A harness can say a
// run ended, and its stop hook does; the reaper can say nothing has been heard
// from a run since a deadline, and that is a withdrawal of standing
// authorisation, not an ending. Neither is a human who KNOWS the run is over —
// the machine is gone, the work was abandoned, the session will not come back.
// Until this command there was no way to put that knowledge into the record
// without an MCP client, so the one party holding the fact had no way to say
// it and the run read live until a horizon expired it.
//
// Positive knowledge should be able to enter the ledger. That is all this is.
//
// # It is a client and nothing more
//
// The retirement itself is `retire_agent`, unchanged: it appends `run_retired`
// and then deletes the run's SPIRE entry, in that order, with the ordering
// argument ADR-0018 settled. This command adds no event type, no field, no
// error class and no tool — it opens one MCP session, makes one call, and
// turns the answer into an exit status.
//
// It talks to the IDENTITY-LIFECYCLE listener, not the agent one. #170 split
// the surface so that the tools which create and destroy identities are not
// reachable by the caller doing the work; `retire_agent` destroys one, so it
// lives on the admin listener ($INNSEGL_MCP_ADMIN_URL), beside
// `register_agent`. Pointing this at the agent listener finds no such tool,
// which is the split working rather than a misconfiguration to route around.
//
// # How "already ended" is known, which is the one subtle part
//
// IP §4 makes `retire_agent` idempotent: "retiring a retired run returns
// success with the original timestamp". It NEVER refuses an already-retired
// run, and there is no RUN_ALREADY_RETIRED on this path — so a refusal is not
// the signal, and the surface offers no flag saying which call did the work.
// The only thing that differs between the two cases is the instant itself:
//
//   - a retirement THIS invocation caused is stamped by the ledger's clock
//     while the call is in flight, so it is at or after the instant the call
//     was made;
//   - a retirement that was already on the chain was stamped before this
//     invocation began.
//
// So the command notes the instant it asks, and compares. Nothing is inferred
// about the ledger beyond what IP §4 already promises, and no second surface
// is consulted to find out — asking a read API would make the command depend
// on a service that has nothing to do with retiring anything, and would give
// a different answer when that service was down.
//
// THE LIMIT, stated rather than discovered. The comparison is only as good as
// the two clocks. Two invocations inside the same millisecond — doc 02 §1's
// resolution — are indistinguishable, and a ledger whose clock trails this
// host's by more than the call takes makes a first retirement look like a
// second. Both misreport the exit status and NEITHER changes what is recorded:
// `retire_agent` appends exactly one `run_retired` per run whatever this
// command believes, because migrations/0004's partial unique index, not this
// comparison, is what enforces that. The failure mode is an operator told
// "already ended" about a run they just ended, which the reported instant lets
// them see for themselves. A human running the same command twice is many
// milliseconds apart; the window is not one a shell can hit.
//
// # THE CREDENTIAL THE LISTENER REQUIRES (#268)
//
// #264 put a repository-scoped credential in front of the six identity-
// lifecycle tools, and `serve` refuses to start a split listener without a key
// set — so wherever that listener exists the credential is MANDATORY and this
// command was refused at the transport before any tool ran. #266 surveyed the
// callers that existed on its branch, the signer and the harness hook, and
// fixed both; this command was written on the other epic and was invisible to
// that survey. Measured on the merged tree, `innsegl retire` reported a
// listener that had answered 401 as UNREACHABLE — which sends an operator to
// restart a deployment that is up.
//
// WHICH REPOSITORY, when this command names a RUN. The credential authorises a
// repository. This command takes a run id. The repository it must be scoped to
// is the RUN'S OWN — and the only party that knows which repository holds a run
// is the listener, which will not answer without the credential. That circle
// cannot be cut inside the protocol, so the repository comes from the caller,
// from three places, first one wins:
//
//	-repo host/org/name    the operator names it outright
//	$INNSEGL_REPO_ID       the variable the signer and the harness hook read
//	the working tree       origin's URL, by doc 02 §5's rule
//
// The working tree is last and NOT the only way, because the run this command
// exists for is a STRANDED one: a machine that is gone, a checkout that may
// well not be this one. Deriving is the convenience; `-repo` is the capability.
//
// WHAT DERIVING COSTS, stated rather than discovered. #264 answers a run in a
// repository the credential does not authorise exactly as it answers a run
// that does not exist — deliberately, because a run id is public in every
// `Agent-Run` trailer and must not become an oracle over which repository holds
// it. So an operator standing in repository A who retires a run belonging to
// repository B is told NO SUCH RUN about an id that is correct. No client can
// make the server distinguish those; the only thing this command can do is say
// so, which is why NO SUCH RUN names `-repo` whenever a credential was in play.
//
// WHEN IT MINTS. Never, until the listener says otherwise. The first call
// carries nothing; a 401 — and only a 401 — mints one and repeats the SAME call
// exactly once. A deployment that enforces nothing produces no 401, so it mints
// nothing, runs no git, and behaves byte-for-byte as this command did before.
// A second 401 is reported with the remedy rather than retried: a loop against
// a server that has already said no is still a loop.
//
// HOW IT MINTS, and where the key is. By running the shipped `innsegl
// admin-credential mint` inside a throwaway container that mounts the
// deployment's private signing key READ-ONLY, with no network. The key is never
// copied onto this machine, never read by this process and never printed; the
// only value that crosses the boundary is the credential, on the child's stdout
// pipe. It is the same mint, with the same variables, that
// scripts/innsegl-commit.sh and scripts/hooks/subagent-identity.sh run, so an
// operator who has either of those working has this working.
//
// WHERE IT IS KEPT. In one struct field, for the life of one process. Never
// exported, never written to a file, never logged, and never placed in an
// argument vector — `ps` shows every argument of every process on this machine,
// and a bearer token there is replayable for the rest of its life. It reaches
// the listener through a RoundTripper that sets the header and does nothing
// else with it.
//
// # Five statuses because an operator does five different things
//
// Ended, and the record now says so — nothing to do. Already ended — the
// record already said so; whatever prompted the second attempt is answered,
// and nothing was appended. No such run — the id is wrong, or this is the
// wrong deployment; look again before assuming an identity is loose. Could not
// be reached — nothing was decided, the run is exactly as it was, and the
// command is safe to run again when the surface is back. Refused — the
// listener ANSWERED and would not admit this caller; the deployment is healthy
// and what is missing is a credential, which is a different thing to go and do.

const (
	// envMCPAdminURL names the identity-lifecycle listener. It is the variable
	// scripts/innsegl-commit.sh and the harness hooks already read, with the
	// same default, so an operator who has one of those working has this
	// working.
	envMCPAdminURL = "INNSEGL_MCP_ADMIN_URL"
	// defaultMCPAdminURL is the loopback address the reference deployment
	// publishes the admin listener on.
	defaultMCPAdminURL = "http://127.0.0.1:28090/"
	// defaultRetireTimeout bounds the whole exchange — connect, initialize,
	// call. A surface that is black-holing packets must become an exit status
	// rather than a hang, because the operator reaching for this command is
	// usually already dealing with something that stopped answering.
	defaultRetireTimeout = 30 * time.Second
	// retireClientName is what this command calls itself on the initialize
	// handshake. It names the tool, never the person running it.
	retireClientName = "innsegl-retire"
	// fieldRetiredAt is retire_agent's result member (IP §4: `{retired_at}`).
	// A PROTECTED string (doc 08 §3): it is read here, never defined here.
	fieldRetiredAt = "retired_at"
	// The members of IP §4's structured error, read off a refusal.
	fieldErrorClass = "error_class"
	fieldMessage    = "message"
	fieldRunID      = "run_id"
)

// Exit statuses, continuing cli.go's contract. The canary owns 3 and 4, the
// reaper 5 and 6, the reconciler 7 and 8, the sealer 9 and 10, `api` 11-13,
// `init` 14 and 15, `resolve-alert` 16 and 17; these are retire's. A
// successful retirement is exitOK, which is the fourth of the four.
const (
	// exitRetireAlreadyEnded: the run was already retired when this ran. The
	// record is unchanged and no second `run_retired` exists — the instant
	// reported is the original one.
	exitRetireAlreadyEnded = 18
	// exitRetireNoSuchRun: this deployment's ledger holds no such run. Nothing
	// was written and nothing was deleted.
	exitRetireNoSuchRun = 19
	// exitRetireUnreachable: the surface could not be reached, or reached and
	// could not finish — an unreachable ledger, a SPIRE that would not delete
	// the entry, an answer this command cannot read. The run may or may not be
	// retired; running the command again converges, because `retire_agent` is
	// idempotent and a retry appends nothing it already appended.
	exitRetireUnreachable = 20
	// exitRetireUnauthorized: the listener ANSWERED, and refused the caller.
	// exitRetireUnauthorized: the listener ANSWERED and refused this caller
	// (#268). It is deliberately NOT exitRetireUnreachable. That status says
	// "nothing was decided; run it again once the surface answers", and the
	// surface has answered — an operator who reads it goes and restarts a
	// healthy deployment, which is the misdirection #266 removed from the
	// signer. The move here is to mint a credential, or to name the run's
	// repository, and a different move earns a different status. Nothing is
	// renumbered: 0, 18, 19 and 20 mean exactly what they meant, and a script
	// switching on them keeps working.
	exitRetireUnauthorized = 21
)

// The credential's environment, every name shared with the signer and the
// harness hook so that one deployment is configured once (#266, #268).
const (
	// envRepoID names the repository when the working tree is not the run's
	// own. `-repo` outranks it; it outranks the working tree.
	envRepoID = "INNSEGL_REPO_ID"
	// envAdminCredentialMint is the escape hatch for an operator whose signing
	// key is not on this machine's container volume: any command that prints
	// one credential for the repository it is given.
	//
	// #nosec G101 -- this is the NAME of an environment variable holding a
	// command line, not a credential. Nothing in this file holds one for longer
	// than a process.
	envAdminCredentialMint = "INNSEGL_ADMIN_CREDENTIAL_MINT"
	// The deployment the signing key lives in. All three are the shipped
	// defaults from deploy/compose, and all three are overridable for a
	// deployment that renamed its project or its image.
	envAdminKeyVolume = "INNSEGL_ADMIN_KEY_VOLUME"
	envAdminKeyPath   = "INNSEGL_ADMIN_KEY_PATH"
	envAdminImage     = "INNSEGL_IMAGE"
	envComposeProject = "COMPOSE_PROJECT_NAME"

	defaultComposeProject = "innsegl-core"
	adminKeyVolumeSuffix  = "_innsegl-admin-key"
	defaultAdminKeyPath   = "/k/signing.key"
	defaultAdminImage     = "innsegl:local"

	// The header the credential travels in, and its scheme. Read by #264's
	// middleware, which strips it once it has verified.
	authorizationHeader = "Authorization"
	bearerScheme        = "Bearer"
)

func retireCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("innsegl retire", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		endpoint = fs.String("url", envOr(envMCPAdminURL, defaultMCPAdminURL),
			"identity-lifecycle (admin) MCP endpoint — prefer the environment variable ($"+
				envMCPAdminURL+")")
		timeout = fs.Duration("timeout", envDuration("INNSEGL_RETIRE_TIMEOUT", defaultRetireTimeout),
			"how long to wait for the surface before reporting it unreachable")
		repo = fs.String("repo", "",
			"the RUN'S OWN repository, doc 02 §5's host/org/name. Needed only where the "+
				"lifecycle listener authenticates (#264), and only when the run does not "+
				"belong to this working tree — defaults to $"+envRepoID+
				", then to this tree's origin remote")
	)

	fs.Usage = func() {
		fprintf(stderr, "innsegl retire - end a run an operator knows is over (RM-154, #257)\n\n")
		fprintf(stderr, "Usage:\n  innsegl retire [flags] <run_id>\n\n")
		fprintf(stderr, "Appends one run_retired to the ledger and deletes the run's SPIRE entry, by\n")
		fprintf(stderr, "calling the retire_agent tool on the identity-lifecycle listener. Retirement\n")
		fprintf(stderr, "is effective immediately and permanent (IP §6.2): the run can no longer take a\n")
		fprintf(stderr, "credential or sign, and no event is ever removed to undo it. Running it twice\n")
		fprintf(stderr, "is safe — the second run appends nothing and reports the original instant.\n\n")
		fprintf(stderr, "Use it when you KNOW the run is over. A run that has merely gone quiet is not\n")
		fprintf(stderr, "over; leave that to the reaper, which records a withdrawal a later call undoes.\n\n")
		fprintf(stderr, "Exit status:\n")
		fprintf(stderr, "  %2d  the run is retired, and this command is what retired it\n", exitOK)
		fprintf(stderr, "  %2d  the command line was not understood\n", exitUsage)
		fprintf(stderr, "  %2d  ALREADY ENDED - it was retired before this ran; nothing was appended\n",
			exitRetireAlreadyEnded)
		fprintf(stderr, "  %2d  NO SUCH RUN - check the id, and that this is the right deployment\n",
			exitRetireNoSuchRun)
		fprintf(stderr, "  %2d  UNREACHABLE - nothing was decided; run it again once the surface answers\n",
			exitRetireUnreachable)
		fprintf(stderr, "  %2d  REFUSED - the listener ANSWERED and would not admit this caller. The\n",
			exitRetireUnauthorized)
		fprintf(stderr, "      deployment is up; what is missing is a credential (#264)\n")
		fprintf(stderr, "\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	runID, code := retireTarget(fs, *endpoint, *repo, stderr)
	if code != exitOK {
		return code
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// One credential, for the life of this process, held nowhere else.
	cred := &retireCredential{}
	transport := cred.httpClient()

	// Noted BEFORE the call, so that an instant the ledger stamps while the
	// call is in flight compares as "at or after this". See the header.
	asked := event.NewTimestamp(time.Now())

	cred.attempting()
	retiredAt, err := callRetireAgent(ctx, *endpoint, runID, transport)

	// THE REFUSAL IS THE ONLY TRIGGER. Nothing is probed and nothing is
	// configured: a deployment that does not enforce never reaches this block,
	// so it mints nothing and runs no git.
	var scope retireScope
	if err != nil && cred.refusedThisAttempt() {
		var scopeErr error
		if scope, scopeErr = resolveRetireScope(ctx, *repo); scopeErr != nil {
			return reportRetireUnauthorized(stderr, *endpoint, runID, retireScope{}, scopeErr)
		}
		token, mintErr := mintAdminCredential(ctx, scope.repo)
		if mintErr != nil {
			return reportRetireUnauthorized(stderr, *endpoint, runID, scope, mintErr)
		}
		cred.hold(token)

		// Re-stamped, because the refused attempt reached no handler at all:
		// the call whose answer is compared against the ledger's clock is the
		// one below, and it begins now.
		asked = event.NewTimestamp(time.Now())
		cred.attempting()
		retiredAt, err = callRetireAgent(ctx, *endpoint, runID, transport)
		if err != nil && cred.refusedThisAttempt() {
			return reportRetireUnauthorized(stderr, *endpoint, runID, scope,
				errors.New("the credential this process minted was refused as well"))
		}
	}

	if err != nil {
		return reportRetireFailure(stderr, *endpoint, runID, err, cred.enforcing(), scope)
	}

	if retiredAt.Time().Before(asked.Time()) {
		fprintf(stderr, "innsegl retire: ALREADY ENDED - run %s was retired at %s, before this ran.\n",
			runID, retiredAt)
		fprintf(stderr, "innsegl retire: nothing was appended; retirement is permanent and there is\n")
		fprintf(stderr, "innsegl retire: nothing left to do for this run.\n")
		return exitRetireAlreadyEnded
	}

	fprintf(stdout, "retired %s at %s\n", runID, retiredAt)
	return exitOK
}

// retireTarget reads the one positional argument and the endpoint, and says
// what is wrong in terms of what to type instead.
func retireTarget(fs *flag.FlagSet, endpoint, repo string, stderr io.Writer) (string, int) {
	switch fs.NArg() {
	case 1:
	case 0:
		fprintf(stderr, "innsegl retire: a run id is required - innsegl retire <run_id>\n")
		fprintf(stderr, "innsegl retire: the id is the run_id register_agent returned, and the one the\n")
		fprintf(stderr, "innsegl retire: dashboard shows on the run.\n")
		return "", exitUsage
	default:
		fprintf(stderr, "innsegl retire: one run at a time; %q is a second run id. Retirement is\n", fs.Arg(1))
		fprintf(stderr, "innsegl retire: permanent, so this command does not take a list.\n")
		return "", exitUsage
	}
	if endpoint == "" {
		fprintf(stderr, "innsegl retire: -url (or $%s) is required: it is the\n", envMCPAdminURL)
		fprintf(stderr, "innsegl retire: identity-lifecycle listener, not the one agents call. The\n")
		fprintf(stderr, "innsegl retire: reference deployment publishes it on %s\n", defaultMCPAdminURL)
		return "", exitUsage
	}
	// Checked HERE and not where a credential is minted. A repository this
	// binary would refuse is a command line to correct, and correcting it
	// before a call is made costs the operator nothing; discovering it inside
	// a refusal would report a listener problem for a typing mistake.
	if repo != "" {
		if err := event.ValidateRepo(repo); err != nil {
			fprintf(stderr, "innsegl retire: -repo %q is not a repository: %v\n", repo, err)
			return "", exitUsage
		}
	}
	return fs.Arg(0), exitOK
}

// reportRetireFailure turns a failed call into the status an operator acts on.
//
// RUN_NOT_FOUND is the one refusal with its own status: it is a statement
// about the id, and the operator's next move is to look at the id rather than
// at the deployment. Every other refusal — and every transport failure — is
// the same move: find out what is wrong with the surface, then run this again.
func reportRetireFailure(
	stderr io.Writer, endpoint, runID string, err error, enforcing bool, scope retireScope,
) int {
	var refused *mcp.Error
	if errors.As(err, &refused) && refused.Class == mcp.ClassRunNotFound {
		fprintf(stderr, "innsegl retire: NO SUCH RUN - %s holds no run %s: %s\n",
			endpoint, runID, refused.Message)
		fprintf(stderr, "innsegl retire: nothing was written and nothing was deleted. Check the id,\n")
		fprintf(stderr, "innsegl retire: and that this is the deployment the run was registered on.\n")
		if enforcing {
			// The one place the cost of scoping a credential to a repository
			// can be named. #264 answers a run in a repository this credential
			// does not authorise EXACTLY as it answers a run that does not
			// exist, so the answer above is ambiguous and the server will
			// never disambiguate it.
			fprintf(stderr, "innsegl retire:\n")
			fprintf(stderr, "innsegl retire: This listener authenticates (#264), and a run in a repository the\n")
			fprintf(stderr, "innsegl retire: credential does not authorise is answered exactly like a run that\n")
			fprintf(stderr, "innsegl retire: does not exist - a run id is public, so which repository holds it\n")
			fprintf(stderr, "innsegl retire: is deliberately not answerable. This call was authorised for %s,\n",
				scope.repo)
			fprintf(stderr, "innsegl retire: taken from %s. If the id is right, name the run's own repository:\n",
				scope.source)
			fprintf(stderr, "innsegl retire:   innsegl retire -repo host/org/name %s\n", runID)
		}
		return exitRetireNoSuchRun
	}

	fprintf(stderr, "innsegl retire: UNREACHABLE - %s could not be reached, or could not finish: %v\n",
		endpoint, err)
	fprintf(stderr, "innsegl retire: run %s is left exactly as it was found. Running this again is\n", runID)
	fprintf(stderr, "innsegl retire: safe: retire_agent is idempotent, so a retry converges and never\n")
	fprintf(stderr, "innsegl retire: appends a second ending.\n")
	return exitRetireUnreachable
}

// callRetireAgent opens one MCP session, makes the one call, and returns the
// instant the ledger holds for the run's retirement.
//
// A refusal comes back as a *mcp.Error carrying the class the tool raised, so
// the caller switches on IP §4's vocabulary rather than on message text. A
// class this binary does not know is deliberately NOT passed through under an
// invented name: it becomes an ordinary error, which is the unreachable path.
func callRetireAgent(
	ctx context.Context, endpoint, runID string, transport *http.Client,
) (event.Timestamp, error) {
	client := sdk.NewClient(
		&sdk.Implementation{Name: retireClientName, Version: version.Version()}, nil)

	session, err := client.Connect(ctx,
		&sdk.StreamableClientTransport{Endpoint: endpoint, HTTPClient: transport}, nil)
	if err != nil {
		return event.Timestamp{}, fmt.Errorf("opening an MCP session: %w", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &sdk.CallToolParams{
		Name:      string(mcp.ToolRetireAgent),
		Arguments: map[string]any{fieldRunID: runID},
	})
	if err != nil {
		return event.Timestamp{}, fmt.Errorf("calling %s: %w", mcp.ToolRetireAgent, err)
	}

	body, ok := res.StructuredContent.(map[string]any)
	if !ok {
		return event.Timestamp{}, fmt.Errorf(
			"%s answered with %T where IP §4 requires an object", mcp.ToolRetireAgent, res.StructuredContent)
	}
	if res.IsError {
		return event.Timestamp{}, retireRefusal(runID, body)
	}

	raw, ok := body[fieldRetiredAt].(string)
	if !ok {
		return event.Timestamp{}, fmt.Errorf(
			"%s answered without a %s; there is no instant to report", mcp.ToolRetireAgent, fieldRetiredAt)
	}
	ts, err := event.ParseTimestamp(raw)
	if err != nil {
		return event.Timestamp{}, fmt.Errorf("%s answered with %w", mcp.ToolRetireAgent, err)
	}
	return ts, nil
}

// retireRefusal rebuilds IP §4's structured error from the wire.
//
// The class is checked against the closed vocabulary before it is carried:
// a name outside it cannot be switched on, and treating it as one would let a
// deployment answering something else entirely be read as a refusal this
// command understands.
func retireRefusal(runID string, body map[string]any) error {
	class, ok := body[fieldErrorClass].(string)
	if !ok {
		return fmt.Errorf("%s refused without an %s; there is nothing to switch on",
			mcp.ToolRetireAgent, fieldErrorClass)
	}
	message, ok := body[fieldMessage].(string)
	if !ok {
		message = string(mcp.Class(class))
	}
	scoped, ok := body[fieldRunID].(string)
	if !ok || scoped == "" {
		scoped = runID
	}
	if !mcp.Class(class).Valid() {
		return fmt.Errorf("%s refused with %q, which is not an IP §4 error class: %s",
			mcp.ToolRetireAgent, class, message)
	}
	return &mcp.Error{
		Class:     mcp.Class(class),
		Message:   message,
		Retryable: mcp.Class(class).Retryable(),
		RunID:     scoped,
	}
}

// ---------------------------------------------------------------------------
// The credential (#268). See the header for the four decisions in it.
// ---------------------------------------------------------------------------

// retireCredential is the one credential this invocation holds, together with
// the record of whether the listener refused one during the attempt in flight.
//
// It is a value and not a package variable: one invocation holds one
// credential, nothing outside this file can read it, and nothing outlives the
// process. The mutex is there because the SDK's transport makes requests from
// more than one goroutine — the standalone SSE stream runs beside the call.
type retireCredential struct {
	mu sync.Mutex
	// token is the credential itself. It is written once, by a mint, and read
	// only by the RoundTripper below.
	token string
	// refused records a 401 during the attempt in flight. Cleared by
	// attempting, so it never answers for the previous call.
	refused bool
	// everRefused records that this listener refused something at least once,
	// which is how a deployment that authenticates is told from one that does
	// not. It survives a successful retry, because what it says is a property
	// of the LISTENER and not of an attempt.
	everRefused bool
}

// bearer returns the credential to present, or "" while none is held.
func (c *retireCredential) bearer() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

// hold takes the credential a mint produced.
func (c *retireCredential) hold(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
}

// attempting marks the start of one attempt, so that refusedThisAttempt is
// about the call that is about to be made and not the one before it.
func (c *retireCredential) attempting() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refused = false
}

// noteRefusal records a 401 from the listener.
func (c *retireCredential) noteRefusal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refused = true
	c.everRefused = true
}

// refusedThisAttempt reports whether the listener refused the credential
// during the attempt that has just finished. It is consulted ONLY when that
// attempt failed: a 401 on the standalone SSE stream beside a call that
// succeeded decided nothing and must not cause a mint.
func (c *retireCredential) refusedThisAttempt() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refused
}

// enforcing reports whether this listener has refused anything at all.
func (c *retireCredential) enforcing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.everRefused
}

// httpClient is the transport the MCP session runs over.
func (c *retireCredential) httpClient() *http.Client {
	return &http.Client{Transport: &retireCredentialTransport{base: http.DefaultTransport, cred: c}}
}

// retireCredentialTransport presents whatever credential is held on every
// request, and reads the status off every answer.
//
// EVERY request, not the handshake alone. #264 wraps the whole listener, so
// `initialize` is refused on the same terms as a tool call — and a credential
// that expires between the handshake and the call is refused there instead.
// Reading only the first would turn that into a generic "could not be reached".
//
// The header is set on a CLONE. A RoundTripper may not modify the request it is
// given, and the SDK reuses one across a reconnect.
type retireCredentialTransport struct {
	base http.RoundTripper
	cred *retireCredential
}

func (t *retireCredentialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if token := t.cred.bearer(); token != "" {
		req = req.Clone(req.Context())
		req.Header.Set(authorizationHeader, bearerScheme+" "+token)
	}
	resp, err := t.base.RoundTrip(req)
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		t.cred.noteRefusal()
	}
	return resp, err
}

// ---------------------------------------------------------------------------
// Which repository the credential is scoped to.
// ---------------------------------------------------------------------------

// retireScope is the repository a credential is minted for, and where that
// repository came from. The source is carried because a remedy has to say what
// was ASSUMED: an operator who did not type `-repo` has no other way to find
// out which repository their credential authorised.
type retireScope struct {
	repo   string
	source string
}

const (
	scopeFromFlag     = "-repo"
	scopeFromEnv      = "$" + envRepoID
	scopeFromWorktree = "this working tree's origin remote"
)

// resolveRetireScope answers the ordering problem in the header: three places,
// first one wins.
//
// It is called LAZILY, only after the listener has refused something. A
// deployment that enforces nothing therefore reads no environment and runs no
// git, which is what makes single-listener mode unchanged rather than merely
// unaffected.
func resolveRetireScope(ctx context.Context, explicit string) (retireScope, error) {
	if explicit != "" {
		// Already validated at the flag parse, so an operator who mistypes it
		// is told before a call is made rather than inside a refusal.
		return retireScope{repo: explicit, source: scopeFromFlag}, nil
	}
	if fromEnv := strings.TrimSpace(os.Getenv(envRepoID)); fromEnv != "" {
		if err := event.ValidateRepo(fromEnv); err != nil {
			return retireScope{}, fmt.Errorf("$%s is not a repository: %w", envRepoID, err)
		}
		return retireScope{repo: fromEnv, source: scopeFromEnv}, nil
	}
	repo, err := repoFromWorkingTree(ctx)
	if err != nil {
		return retireScope{}, err
	}
	return retireScope{repo: repo, source: scopeFromWorktree}, nil
}

// repoFromWorkingTree reads doc 02 §5's `host/org/name` out of origin's URL.
//
// It is the rule internal/mcp applies to a worktree and the rule
// scripts/innsegl-commit.sh applies in awk, expressed a third time because the
// first is unexported and the second is a shell pipeline. A DIFFERENCE between
// the three would appear as a refusal from the listener with no obvious cause,
// so the one thing that is not restated is what counts as valid: that is
// event.ValidateRepo, the single definition, called below.
//
// THE CASE RULE, which nobody guesses. doc 02 §5 lowercases the HOST and says
// nothing about the other two, so `github.com/Example-Org/Example-Repo` is
// correct and lowercasing all three names a repository that does not exist on
// a case-sensitive forge.
func repoFromWorkingTree(ctx context.Context) (string, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", "remote", "get-url", "origin")
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", errors.New("this working tree has no origin remote to take a repository from")
	}
	remote := strings.TrimSpace(out.String())
	if remote == "" {
		return "", errors.New("this working tree's origin remote has no URL")
	}

	id := remote
	for _, prefix := range []string{"https://", "http://", "ssh://", "git://"} {
		id = strings.TrimPrefix(id, prefix)
	}
	id = strings.TrimPrefix(id, "git@")
	// `git@github.com:org/name` — the colon is the host separator, and only the
	// first one is: a path may not contain another.
	if host, rest, found := strings.Cut(id, ":"); found && !strings.Contains(host, "/") {
		id = host + "/" + rest
	}
	id = strings.TrimSuffix(id, ".git")
	id = strings.TrimSuffix(id, "/")

	host, rest, found := strings.Cut(id, "/")
	if !found {
		return "", fmt.Errorf("origin %q is not host/org/name", remote)
	}
	id = strings.ToLower(host) + "/" + rest
	if err := event.ValidateRepo(id); err != nil {
		return "", fmt.Errorf("origin %q: %w", remote, err)
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// The mint.
// ---------------------------------------------------------------------------

// adminKeyVolume, adminKeyPath and adminImage are the deployment the signing
// key lives in, with the shipped defaults. Every name is one the signer and the
// harness hook already read, so a deployment that renamed its project or its
// image configures that once.
func adminKeyVolume() string {
	return envOr(envAdminKeyVolume,
		envOr(envComposeProject, defaultComposeProject)+adminKeyVolumeSuffix)
}

func adminKeyPath() string { return envOr(envAdminKeyPath, defaultAdminKeyPath) }

func adminImage() string { return envOr(envAdminImage, defaultAdminImage) }

// mintAdminCredential returns one credential for repo, or says what could not
// be run.
//
// THE CREDENTIAL ARRIVES ON A PIPE and leaves in a return value. It is never an
// argument (`ps` shows every argument of every process on this machine), never
// a file, and never a stream this process writes.
//
// THE CHILD'S STDERR IS DISCARDED, as the signer's and the hook's is. A mint
// that failed has nothing to say that the remedy below does not say better, and
// an operator-supplied $INNSEGL_ADMIN_CREDENTIAL_MINT that wrote a credential to
// its stderr must not be able to put one into this command's output.
func mintAdminCredential(ctx context.Context, repo string) (string, error) {
	name, args := mintCommand(repo)

	var out bytes.Buffer
	// #nosec G204 -- the command and its arguments are this deployment's own
	// configuration, read from the environment the operator is already running
	// this binary in. There is no lower-privileged source for them to come
	// from: an operator who can set $INNSEGL_ADMIN_CREDENTIAL_MINT can already
	// run anything as themselves.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s could not mint a credential: %w", name, err)
	}

	token := strings.TrimSpace(out.String())
	if token == "" {
		return "", fmt.Errorf("%s printed no credential", name)
	}
	return token, nil
}

// mintCommand is the command line that prints one credential for repo.
//
// The container exists for a fraction of a second, mounts the key READ-ONLY,
// has no network, no writable root filesystem and no privilege escalation.
// `--user 0:0` because the deployment's one-shot leaves the key 0400 and
// root-owned, which is the point: the image's own unprivileged user cannot read
// it, so neither could a compromised innsegl-mcp — which does not mount this
// volume at all.
func mintCommand(repo string) (string, []string) {
	if override := strings.Fields(os.Getenv(envAdminCredentialMint)); len(override) > 0 {
		// Deliberately word-split: a command with its own arguments is the
		// normal case, and this is the contract the signer already publishes.
		// The repository is the last argument, as it is there.
		return override[0], append(override[1:], repo)
	}
	key := adminKeyPath()
	return "docker", []string{
		"run", "--rm", "--network", "none", "--read-only", "--user", "0:0",
		"--security-opt", "no-new-privileges",
		"-v", adminKeyVolume() + ":" + path.Dir(key) + ":ro",
		adminImage(),
		"admin-credential", "mint", "-key", key, "-repo", repo,
	}
}

// reportRetireUnauthorized is the refusal that says what to run.
//
// It exists because the listener's own answer cannot. #264 returns ONE
// byte-identical 401 for every credential failure by design — a distinguishable
// reason is an oracle — so the only place an operator can be told what to do is
// here, on their own machine, where the deployment's configuration is readable.
//
// It says three things the UNREACHABLE message must never say: the listener
// answered, the run is untouched, and the next move is a credential.
func reportRetireUnauthorized(
	stderr io.Writer, endpoint, runID string, scope retireScope, reason error,
) int {
	fprintf(stderr, "innsegl retire: REFUSED - %s answered, and would not admit this caller. The\n", endpoint)
	fprintf(stderr, "innsegl retire: identity-lifecycle listener requires the repository-scoped credential\n")
	fprintf(stderr, "innsegl retire: #264 put in front of it. The listener is UP: this is not a deployment\n")
	fprintf(stderr, "innsegl retire: to restart, and run %s is exactly as it was found - nothing was\n", runID)
	fprintf(stderr, "innsegl retire: written and nothing was deleted.\n")
	fprintf(stderr, "innsegl retire:\n")
	fprintf(stderr, "innsegl retire: %v\n", reason)
	fprintf(stderr, "innsegl retire:\n")

	if scope.repo == "" {
		fprintf(stderr, "innsegl retire: The credential authorises a REPOSITORY and this command names a RUN,\n")
		fprintf(stderr, "innsegl retire: so the run's own repository has to be named. Name it:\n")
		fprintf(stderr, "innsegl retire:   innsegl retire -repo host/org/name %s\n", runID)
		fprintf(stderr, "innsegl retire: or set $%s, which the signer and the harness hook read too.\n",
			envRepoID)
		return exitRetireUnauthorized
	}

	key := adminKeyPath()
	fprintf(stderr, "innsegl retire: Mint one against this deployment's signing key:\n")
	fprintf(stderr, "innsegl retire:   docker run --rm --network none --user 0:0 \\\n")
	fprintf(stderr, "innsegl retire:     -v %s:%s:ro %s \\\n", adminKeyVolume(), path.Dir(key), adminImage())
	fprintf(stderr, "innsegl retire:     admin-credential mint -key %s -repo %s\n", key, scope.repo)
	fprintf(stderr, "innsegl retire:\n")
	fprintf(stderr, "innsegl retire: That key is written by the deployment's own one-shot, so an empty volume\n")
	fprintf(stderr, "innsegl retire: means the stack has never been up with the identity lifecycle split out:\n")
	fprintf(stderr, "innsegl retire:   make innsegl-up-here\n")
	fprintf(stderr, "innsegl retire:\n")
	fprintf(stderr, "innsegl retire: Minting elsewhere: set $%s to a command that\n", envAdminCredentialMint)
	fprintf(stderr, "innsegl retire: prints one credential for the repository it is given.\n")
	fprintf(stderr, "innsegl retire:\n")
	fprintf(stderr, "innsegl retire: The repository was taken from %s: %s. A run that belongs to ANOTHER\n",
		scope.source, scope.repo)
	fprintf(stderr, "innsegl retire: repository - the stranded run in a checkout that is not this one - needs\n")
	fprintf(stderr, "innsegl retire: its own named:\n")
	fprintf(stderr, "innsegl retire:   innsegl retire -repo host/org/name %s\n", runID)
	fprintf(stderr, "innsegl retire:\n")
	fprintf(stderr, "innsegl retire: The listener will never say WHY a credential is inadmissible - one\n")
	fprintf(stderr, "innsegl retire: byte-identical refusal is deliberate. Ask on your own machine instead:\n")
	fprintf(stderr, "innsegl retire:   innsegl admin-credential verify -jwks <set>\n")
	return exitRetireUnauthorized
}
