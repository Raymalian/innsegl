// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"innsegl.dev/innsegl/internal/identity"
)

// `innsegl init` — set up signing end to end (#117, RM-080).
//
// Today, adopting Innsegl's own signing means: install gitsign, find its
// path, write three `git config` keys, decide a trust root, decide whether
// identities are pseudonymous, and complete an OIDC flow — assembled from
// documentation, by hand, once per repository. This command is that
// sequence, run once: it locates or installs a pinned, SHA-256-verified
// gitsign; asks the two questions below (or takes them as flags); writes the
// git configuration and the deployment config; signs one real commit and
// proves it with `innsegl verify`; and can undo all of it exactly.
//
// # A known conflict between this issue and ADR-0010, reported rather than
// papered over
//
// #117 frames "who must be able to verify" as two working, symmetric
// choices. ADR-0010, measured 2026-08-28 against the live public Fulcio
// configuration endpoint, forecloses one of them for THIS project's
// SPIFFE-ID signing pipeline: public Fulcio's allowlist accepts no issuer of
// type `spiffe`, so no OIDC token this deployment can present will ever
// produce a certificate `internal/verify` accepts as attributed (it requires
// a URI SAN carrying a SPIFFE ID; see internal/verify/commit.go's
// commitCertificate). Under `-trust-root public`, this command therefore
// writes the deployment configuration a public-Sigstore future could use
// (e.g. for release-artifact signing in the shape release.yml already
// practises) but REFUSES to attempt, let alone claim to have proven, a
// SPIFFE-attributed test signature under it — see initsign.go's
// errPublicSigningUnsupported for the full citation. This is flagged as a
// question for the human maintaining ADR-0010 and this issue, not resolved
// unilaterally here.
//
// # --local, and only --local
//
// Every git config write goes through initgit.go's gitLocal, which always
// passes `--local` explicitly. Nothing here ever reads or writes
// $HOME/.gitconfig, and nothing here ever touches a repository other than
// -repo.

// Exit statuses, continuing cli.go's contract. The api command owns 11-13;
// these are init's.
const (
	// exitInitUnverified: configuration may have been written, but the test
	// signature could not be proven to verify (including a public trust
	// root, which is refused outright — see the package comment above).
	// Setup is NOT complete: "measure, do not assert" (IP §2) means a
	// command that wrote files is not success until the chain held.
	exitInitUnverified = 14
	// exitInitInconclusive: init could not even get to the point of
	// attempting a signature — bad configuration, a gitsign that failed its
	// checksum, or (for --undo) nothing recorded to reverse.
	exitInitInconclusive = 15
)

// initDeps are the seams this command's tests replace. Production wiring is
// defaultInitDeps.
type initDeps struct {
	installGitsign func(context.Context, gitsignInstallOptions) (string, error)
	signVerifier   signAndVerifier
}

func (d initDeps) install() func(context.Context, gitsignInstallOptions) (string, error) {
	if d.installGitsign != nil {
		return d.installGitsign
	}
	return locateOrInstallGitsign
}

func (d initDeps) verifier() signAndVerifier {
	if d.signVerifier != nil {
		return d.signVerifier
	}
	return spireSignVerifier{}
}

// initCommand is the subcommand body wired into cli.go's dispatch table.
func initCommand(args []string, stdout, stderr io.Writer) int {
	return runInitCommand(context.Background(), args, stdout, stderr, initDeps{})
}

// initOptions is the resolved command line.
type initOptions struct {
	repo string
	undo bool

	trustRootFlag      string
	identityModeFlag   string
	identitySecret     string
	identitySecretFile string
	nonInteractive     bool

	fulcioURL  string
	rekorURL   string
	oidcIssuer string

	spireAddress string
	trustDomain  string
	serverID     string
	workloadAPI  string
	svidFile     string
	keyFile      string
	bundleFile   string

	gitsignPath    string
	gitsignVersion string

	authorName  string
	authorEmail string

	installHook bool

	asJSON bool
}

func runInitCommand(ctx context.Context, args []string, stdout, stderr io.Writer, deps initDeps) int {
	fs := flag.NewFlagSet("innsegl init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o initOptions

	fs.StringVar(&o.repo, "repo", ".", "path to the git repository to set up signing in")
	fs.BoolVar(&o.undo, "undo", false, "reverse a prior `innsegl init` run exactly, and exit")

	fs.StringVar(&o.trustRootFlag, "trust-root", os.Getenv(envInitTrustRoot),
		"who must be able to verify: \"self-hosted\" (only us, ADR-0010's default) or "+
			"\"public\" (anyone, public Sigstore) ($"+envInitTrustRoot+"); empty prompts interactively")
	fs.StringVar(&o.identityModeFlag, "identity-mode", os.Getenv(envIdentityMode),
		"what identity appears in the record: \"pseudonymous\" or \"literal\" ($"+envIdentityMode+"); "+
			"only asked interactively under -trust-root public")
	fs.StringVar(&o.identitySecret, "identity-secret", os.Getenv(envIdentitySecret),
		"the pseudonymisation key; generated if empty and mode is pseudonymous ($"+envIdentitySecret+")")
	fs.StringVar(&o.identitySecretFile, "identity-secret-file", os.Getenv(envIdentitySecretFile),
		"file holding the pseudonymisation key, instead of -identity-secret ($"+envIdentitySecretFile+")")
	fs.BoolVar(&o.nonInteractive, "non-interactive", envBool(envInitNonInteractive, false),
		"never prompt; both questions must then be answered by flag ($"+envInitNonInteractive+")")

	fs.StringVar(&o.fulcioURL, "fulcio-url", os.Getenv(envFulcioURL),
		"this deployment's Fulcio base URL ($"+envFulcioURL+"); defaults to public Sigstore's under -trust-root public")
	fs.StringVar(&o.rekorURL, "rekor-url", os.Getenv(envRekorURL),
		"this deployment's Rekor base URL ($"+envRekorURL+"); defaults to public Sigstore's under -trust-root public")
	fs.StringVar(&o.oidcIssuer, "oidc-issuer", os.Getenv(envOIDCIssuer),
		"the OIDC issuer Fulcio believes ($"+envOIDCIssuer+")")

	fs.StringVar(&o.spireAddress, "spire-address", os.Getenv(envSPIREAddress),
		"SPIRE server admin API, host:port; required under -trust-root self-hosted to sign the "+
			"test commit ($"+envSPIREAddress+")")
	fs.StringVar(&o.trustDomain, "trust-domain", os.Getenv(envTrustDomain),
		"SPIFFE trust domain name, e.g. innsegl.dev ($"+envTrustDomain+")")
	fs.StringVar(&o.serverID, "spire-server-id", os.Getenv(envSPIREServerID),
		"SPIFFE ID the SPIRE server must present ($"+envSPIREServerID+")")
	fs.StringVar(&o.workloadAPI, "workload-api", envOr(envWorkloadAPI, "unix:///run/spire/agent-sockets/api.sock"),
		"Workload API socket this process fetches its own admin SVID from ($"+envWorkloadAPI+")")
	fs.StringVar(&o.svidFile, "admin-svid", os.Getenv(envInitSVIDFile),
		"PEM admin X509-SVID, instead of the Workload API — for bootstrapping a trust domain "+
			"before init itself is an attested workload ($"+envInitSVIDFile+")")
	fs.StringVar(&o.keyFile, "admin-key", os.Getenv(envInitKeyFile),
		"PEM private key for -admin-svid ($"+envInitKeyFile+")")
	fs.StringVar(&o.bundleFile, "admin-bundle", os.Getenv(envInitBundleFile),
		"PEM trust bundle for -admin-svid ($"+envInitBundleFile+")")

	fs.StringVar(&o.gitsignPath, "gitsign-path", "",
		"trust this exact gitsign binary instead of locating or installing the pinned release")
	fs.StringVar(&o.gitsignVersion, "gitsign-version", defaultGitsignVersion,
		"gitsign release to pin, downloaded and SHA-256-verified before use")

	fs.StringVar(&o.authorName, "author-name", "", "author name for the test commit; defaults to user.name")
	fs.StringVar(&o.authorEmail, "author-email", "", "author email for the test commit; defaults to user.email")

	fs.BoolVar(&o.installHook, "hook", false, "also install a pre-push hook refusing unsigned commits")
	fs.BoolVar(&o.asJSON, "json", false, "write the report as JSON")

	fs.Usage = func() {
		fprintf(stderr, "innsegl init - set up signed commits in one repository end to end (#117)\n\n")
		fprintf(stderr, "Usage:\n  innsegl init [flags]\n  innsegl init -undo [-repo path]\n\n")
		fprintf(stderr, "--local only: nothing is written outside the repository named by -repo,\n"+
			"and the operator's global git config is never touched.\n\n")
		fprintf(stderr, "Exit status:\n")
		fprintf(stderr, "  %d  a real test commit was signed and `innsegl verify` accepted it\n", exitOK)
		fprintf(stderr, "  %d  the command line was not understood\n", exitUsage)
		fprintf(stderr, "  %d  UNVERIFIED - setup did not prove itself; see the message for why\n", exitInitUnverified)
		fprintf(stderr, "  %d  INCONCLUSIVE - nothing could be attempted, or (with -undo) nothing was recorded to reverse\n",
			exitInitInconclusive)
		fprintf(stderr, "\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fprintf(stderr, "innsegl init: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return exitUsage
	}

	if o.undo {
		return runInitUndo(ctx, o, stdout, stderr)
	}
	return runInitApply(ctx, o, stdout, stderr, deps)
}

// runInitUndo is #117 point 6: "`innsegl init --undo` reverses everything,
// and the command prints exactly what it changed."
func runInitUndo(ctx context.Context, o initOptions, stdout, stderr io.Writer) int {
	g := newGitLocal("", o.repo)
	rec, err := loadGitSigningRecorder(ctx, g)
	if err != nil {
		fprintf(stderr, "innsegl init: %v\n", err)
		return exitInitInconclusive
	}

	files, ferr := rec.recordedFiles(ctx)
	if ferr != nil {
		fprintf(stderr, "innsegl init: %v\n", ferr)
		return exitInitInconclusive
	}
	ref, rerr := rec.recordedRef(ctx)
	if rerr != nil {
		fprintf(stderr, "innsegl init: %v\n", rerr)
		return exitInitInconclusive
	}

	var changed []string
	if ref != "" {
		if err := runGit(ctx, "", o.repo, "update-ref", "-d", ref); err != nil {
			fprintf(stderr, "innsegl init: removing %s: %v\n", ref, err)
			return exitInitInconclusive
		}
		changed = append(changed, "removed "+ref)
	}
	if len(files) > 0 {
		if err := removeDeployConfig(o.repo, files); err != nil {
			fprintf(stderr, "innsegl init: %v\n", err)
			return exitInitInconclusive
		}
		for _, f := range files {
			changed = append(changed, "removed "+f)
		}
	}
	if err := rec.undo(ctx); err != nil {
		fprintf(stderr, "innsegl init: %v\n", err)
		return exitInitInconclusive
	}
	for _, key := range signingKeys {
		changed = append(changed, "restored "+key)
	}

	fprintf(stdout, "innsegl init --undo: reversed %d change(s):\n", len(changed))
	for _, c := range changed {
		fprintf(stdout, "  %s\n", c)
	}
	return exitOK
}

// runInitApply is everything up to and including the smoke test.
func runInitApply(ctx context.Context, o initOptions, stdout, stderr io.Writer, deps initDeps) int {
	if o.repo == "" {
		fprintf(stderr, "innsegl init: -repo is required\n")
		return exitUsage
	}

	root, err := resolveTrustRoot(trustRootPrompt{
		Flag: o.trustRootFlag, In: os.Stdin, Out: stdout,
		NonInteractive: o.nonInteractive, TerminalPresent: stdinIsTerminal(),
	})
	if err != nil {
		fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	mode, err := resolveIdentityMode(identityModePrompt{
		TrustRoot: root, Flag: o.identityModeFlag, In: os.Stdin, Out: stdout,
		NonInteractive: o.nonInteractive, TerminalPresent: stdinIsTerminal(),
	})
	if err != nil {
		fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	fulcioURL, rekorURL, oidcIssuer := o.fulcioURL, o.rekorURL, o.oidcIssuer
	if root == trustRootPublic {
		if fulcioURL == "" {
			fulcioURL = defaultPublicFulcioURL
		}
		if rekorURL == "" {
			rekorURL = defaultPublicRekorURL
		}
	}
	missing := ""
	switch {
	case fulcioURL == "":
		missing = "-fulcio-url (or $" + envFulcioURL + ")"
	case rekorURL == "":
		missing = "-rekor-url (or $" + envRekorURL + ")"
	case root == trustRootSelfHosted && oidcIssuer == "":
		missing = "-oidc-issuer (or $" + envOIDCIssuer + ")"
	case root == trustRootSelfHosted && o.spireAddress == "":
		missing = "-spire-address (or $" + envSPIREAddress + ")"
	case root == trustRootSelfHosted && o.trustDomain == "":
		missing = "-trust-domain (or $" + envTrustDomain + ")"
	}
	if missing != "" {
		fprintf(stderr, "innsegl init: %s is required\n", missing)
		return exitUsage
	}

	secret, serr := resolveInitIdentitySecret(o, mode)
	if serr != "" {
		fprintf(stderr, "innsegl init: %s\n", serr)
		return exitUsage
	}

	g := newGitLocal("", o.repo)

	gitsignPath := o.gitsignPath
	if gitsignPath == "" {
		installed, ierr := deps.install()(ctx, gitsignInstallOptionsFor(o))
		if ierr != nil {
			fprintf(stderr, "innsegl init: %v\n", ierr)
			return exitInitInconclusive
		}
		gitsignPath = installed
	}

	rec := newGitSigningRecorder(g)
	if aerr := rec.apply(ctx, gitsignSetup{GitsignPath: gitsignPath}); aerr != nil {
		fprintf(stderr, "innsegl init: %v\n", aerr)
		return exitInitInconclusive
	}
	fprintf(stdout, "git config --local: gpg.format=x509, gpg.x509.program=%s, commit.gpgsign=true\n", gitsignPath)

	depCfg := deployConfig{
		FulcioURL: fulcioURL, RekorURL: rekorURL, OIDCIssuer: oidcIssuer, IdentityMode: string(mode),
	}
	paths, derr := writeDeployConfig(o.repo, depCfg, secret)
	if derr != nil {
		fprintf(stderr, "innsegl init: %v\n", derr)
		return exitInitInconclusive
	}
	if err := rec.recordFiles(ctx, paths); err != nil {
		fprintf(stderr, "innsegl init: %v\n", err)
		return exitInitInconclusive
	}
	fprintf(stdout, "deployment config written: %s\n", strings.Join(paths, ", "))

	if o.installHook {
		hookPaths, herr := installPrePushHook(ctx, o.repo)
		if herr != nil {
			fprintf(stderr, "innsegl init: %v\n", herr)
			return exitInitInconclusive
		}
		if err := rec.recordFiles(ctx, hookPaths); err != nil {
			fprintf(stderr, "innsegl init: %v\n", err)
			return exitInitInconclusive
		}
		if len(hookPaths) > 0 {
			fprintf(stdout, "pre-push hook installed: %s\n", strings.Join(hookPaths, ", "))
		}
	}

	pseudonyms, perr := identity.New(mode, secret)
	if perr != nil {
		fprintf(stderr, "innsegl init: %v\n", perr)
		return exitInitInconclusive
	}

	authorName, authorEmail, aerr := resolveAuthor(ctx, g, o)
	if aerr != "" {
		fprintf(stderr, "innsegl init: %s\n", aerr)
		return exitInitInconclusive
	}

	result, terr := runSmokeTest(ctx, smokeTestRequest{
		TrustRoot: root, Repo: o.repo,
		FulcioURL: fulcioURL, RekorURL: rekorURL, OIDCIssuer: oidcIssuer,
		Pseudonyms:   pseudonyms,
		AuthorName:   authorName,
		AuthorEmail:  authorEmail,
		GitPath:      "",
		GitsignPath:  gitsignPath,
		SpireAddress: o.spireAddress, TrustDomain: o.trustDomain, ServerID: o.serverID,
		WorkloadAPI: o.workloadAPI, SVIDFile: o.svidFile, KeyFile: o.keyFile, BundleFile: o.bundleFile,
	}, deps.verifier())
	if terr != nil {
		fprintf(stderr, "innsegl init: %v\n", terr)
		fprintf(stderr, "innsegl init: setup is NOT complete — the chain did not hold\n")
		return exitInitUnverified
	}

	if err := rec.recordRef(ctx, result.Ref); err != nil {
		fprintf(stderr, "innsegl init: %v\n", err)
		return exitInitInconclusive
	}

	fprintf(stdout, "VERIFIED: %s signed a real commit (%s) and `innsegl verify` accepted it\n",
		result.Ref, result.CommitSHA)
	return exitOK
}

// Public Sigstore's own well-known endpoints — the same defaults
// release.yml's own INNSEGL_FULCIO_URL / INNSEGL_REKOR_URL name.
const (
	defaultPublicFulcioURL = "https://fulcio.sigstore.dev"
	defaultPublicRekorURL  = "https://rekor.sigstore.dev"
)

// init's own admin-file env names, distinct from the MCP's
// (envMCPSVIDFile...): a different process, a different set of flags, and
// serve.go's own comment is explicit that this second path is for
// "bootstrapping a trust domain" — precisely `init`'s first run.
const (
	envInitSVIDFile   = "INNSEGL_INIT_SVID_FILE"
	envInitKeyFile    = "INNSEGL_INIT_KEY_FILE"
	envInitBundleFile = "INNSEGL_INIT_BUNDLE_FILE"
)

func gitsignInstallOptionsFor(o initOptions) gitsignInstallOptions {
	opts := defaultGitsignInstallOptions(o.repo)
	if o.gitsignVersion != "" {
		opts.Version = o.gitsignVersion
	}
	return opts
}

// resolveInitIdentitySecret mirrors serve.go's resolveIdentitySecret exactly
// (RM-084, #124): -identity-secret and -identity-secret-file are refused
// together, a file is trimmed, and — the one addition init makes — a
// pseudonymous mode with neither generates a fresh one, because an operator
// running init for the first time has no secret yet to supply.
func resolveInitIdentitySecret(o initOptions, mode identity.Mode) (string, string) {
	if o.identitySecretFile != "" {
		if o.identitySecret != "" {
			return "", "-identity-secret and -identity-secret-file are both set: two sources " +
				"for one secret"
		}
		body, err := os.ReadFile(o.identitySecretFile)
		if err != nil {
			return "", "-identity-secret-file: " + err.Error()
		}
		return strings.TrimSpace(string(body)), ""
	}
	if o.identitySecret != "" {
		return o.identitySecret, ""
	}
	if mode != identity.ModePseudonymous {
		return "", ""
	}
	return generateIdentitySecret(), ""
}

// generateIdentitySecret mints a fresh deployment secret: 32 random bytes,
// hex-encoded to 64 characters — comfortably over identity.MinSecretBytes
// (16) even before hex expansion, mirroring the pattern this project's own
// compose stack already uses to generate a per-deployment secret (#124).
func generateIdentitySecret() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// resolveAuthor defaults the test commit's author to the repository's own
// user.name / user.email — the same identity any OTHER commit the operator
// makes here would carry — and refuses clearly if neither is configured,
// rather than handing gitsign an empty author line.
func resolveAuthor(ctx context.Context, g gitLocal, o initOptions) (name, email, problem string) {
	name, email = o.authorName, o.authorEmail
	if name == "" {
		v, ok, err := g.configGet(ctx, "user.name")
		if err != nil {
			return "", "", err.Error()
		}
		if ok {
			name = v
		}
	}
	if email == "" {
		v, ok, err := g.configGet(ctx, "user.email")
		if err != nil {
			return "", "", err.Error()
		}
		if ok {
			email = v
		}
	}
	if name == "" || email == "" {
		return "", "", "no author identity: set user.name and user.email (or -author-name / " +
			"-author-email) before running init"
	}
	return name, email, ""
}

// installPrePushHook is #117 point 5: "Optionally installs a pre-push hook
// refusing unsigned commits." Opt-in (-hook), because a hook silently
// installed into someone else's workflow is a surprise this command should
// not create for them.
func installPrePushHook(ctx context.Context, repo string) ([]string, error) {
	hookPath, err := runGitOutput(ctx, "", repo, "rev-parse", "--git-path", "hooks/pre-push")
	if err != nil {
		return nil, fmt.Errorf("innsegl init: locating the hooks directory: %w", err)
	}
	hookPath = strings.TrimSpace(hookPath)
	if !isAbsPath(hookPath) {
		hookPath = repo + "/" + hookPath
	}

	if existing, err := os.ReadFile(hookPath); err == nil {
		if !strings.Contains(string(existing), prePushHookMarker) {
			return nil, fmt.Errorf("innsegl init: %s already exists and was not written by "+
				"`innsegl init` — refusing to overwrite a hook it does not own", hookPath)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("innsegl init: reading the existing pre-push hook: %w", err)
	}

	if err := os.WriteFile(hookPath, []byte(prePushHookScript), 0o755); err != nil { //nolint:gosec // a hook must be executable
		return nil, fmt.Errorf("innsegl init: writing the pre-push hook: %w", err)
	}
	return []string{hookPath}, nil
}

const prePushHookMarker = "innsegl init managed pre-push hook"

const prePushHookScript = `#!/bin/sh
# ` + prePushHookMarker + ` — do not edit by hand; see 'innsegl init --undo'.
# Refuses to push a commit in range that carries no gpgsig header.
set -eu
zero="0000000000000000000000000000000000000000"
while read -r local_ref local_sha remote_ref remote_sha; do
	[ "$local_sha" = "$zero" ] && continue
	range="$local_sha"
	if [ "$remote_sha" != "$zero" ]; then
		range="$remote_sha..$local_sha"
	fi
	for commit in $(git rev-list "$range" --); do
		if ! git cat-file commit "$commit" | grep -q '^gpgsig '; then
			echo "innsegl: $commit is not signed; refusing to push (see 'innsegl init --undo' to remove this hook)" >&2
			exit 1
		fi
	done
done
`

func isAbsPath(p string) bool { return strings.HasPrefix(p, "/") }
