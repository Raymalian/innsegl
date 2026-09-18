// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
// # Four statuses because an operator does four different things
//
// Ended, and the record now says so — nothing to do. Already ended — the
// record already said so; whatever prompted the second attempt is answered,
// and nothing was appended. No such run — the id is wrong, or this is the
// wrong deployment; look again before assuming an identity is loose. Could not
// be reached — nothing was decided, the run is exactly as it was, and the
// command is safe to run again when the surface is back.

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
		fprintf(stderr, "\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	runID, code := retireTarget(fs, *endpoint, stderr)
	if code != exitOK {
		return code
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Noted BEFORE the call, so that an instant the ledger stamps while the
	// call is in flight compares as "at or after this". See the header.
	asked := event.NewTimestamp(time.Now())

	retiredAt, err := callRetireAgent(ctx, *endpoint, runID)
	if err != nil {
		return reportRetireFailure(stderr, *endpoint, runID, err)
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
func retireTarget(fs *flag.FlagSet, endpoint string, stderr io.Writer) (string, int) {
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
	return fs.Arg(0), exitOK
}

// reportRetireFailure turns a failed call into the status an operator acts on.
//
// RUN_NOT_FOUND is the one refusal with its own status: it is a statement
// about the id, and the operator's next move is to look at the id rather than
// at the deployment. Every other refusal — and every transport failure — is
// the same move: find out what is wrong with the surface, then run this again.
func reportRetireFailure(stderr io.Writer, endpoint, runID string, err error) int {
	var refused *mcp.Error
	if errors.As(err, &refused) && refused.Class == mcp.ClassRunNotFound {
		fprintf(stderr, "innsegl retire: NO SUCH RUN - %s holds no run %s: %s\n",
			endpoint, runID, refused.Message)
		fprintf(stderr, "innsegl retire: nothing was written and nothing was deleted. Check the id,\n")
		fprintf(stderr, "innsegl retire: and that this is the deployment the run was registered on.\n")
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
func callRetireAgent(ctx context.Context, endpoint, runID string) (event.Timestamp, error) {
	client := sdk.NewClient(
		&sdk.Implementation{Name: retireClientName, Version: version.Version()}, nil)

	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: endpoint}, nil)
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
