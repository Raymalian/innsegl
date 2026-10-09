// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/signing"
)

// OperatorAuthorPath is where a machine reports its operator author to the
// core, over its own certificate (#545). The core pins the first report for
// this installation (GH-010).
const OperatorAuthorPath = "/_core/operator-author"

// OperatorAuthorReport is the body: who this machine pushes as, read from git.
type OperatorAuthorReport struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// ErrOperatorAuthorPinned is the core holding a different pair for this
// machine; it changes only on the core host.
var ErrOperatorAuthorPinned = errors.New("the core has a different operator author pinned for this machine")

// ErrNoNoreplyAddress is a repository whose git user.email is not a GitHub
// noreply address, so it has no operator author to use.
var ErrNoNoreplyAddress = errors.New("this repository's git user.email is not a GitHub noreply " +
	"address (<id>+<login>@users.noreply.github.com)")

// NoreplyIdentity answers the operator author a repository pushes as:
// `<login> <email>`, from git's user.email in dir (#545, ENF-013). Only
// user.email is read, and only a GitHub noreply address is used; the name is
// that address's login. user.name is never read: it is a person's name, and
// an author line is published.
func NoreplyIdentity(ctx context.Context, dir string) (name, email string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// #nosec G702 -- argv, no shell: dir is one argument to -C, and what is not
	// a directory git can enter is refused by git itself.
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "config", "--get", "user.email").Output()
	if err != nil {
		return "", "", ErrNoNoreplyAddress
	}
	email = strings.TrimSpace(string(out))
	login, ok := signing.NoreplyLogin(email)
	if !ok {
		return "", "", ErrNoNoreplyAddress
	}
	return login, email, nil
}

// PinOutcome is what a report did on the core (GH-011).
type PinOutcome string

// The two outcomes of a report the core accepted.
const (
	// PinNew is a report that pinned the pair now.
	PinNew PinOutcome = "pinned"
	// PinHeld is the same pair, already pinned: nothing changed.
	PinHeld PinOutcome = "already-pinned"
)

// OperatorAuthorPinResult is the core's answer to an accepted report.
type OperatorAuthorPinResult struct {
	Pinned bool       `json:"pinned"`
	Result PinOutcome `json:"result,omitempty"`
}

// OperatorAuthorPin is the core's answer to GET: the pair pinned for the
// calling installation, if any (GH-011).
type OperatorAuthorPin struct {
	Pinned bool   `json:"pinned"`
	Name   string `json:"name,omitempty"`
	Email  string `json:"email,omitempty"`
}

// ErrNotPinnable is an identity the core would not pin: it pins only a
// GitHub noreply address, named by that address's own login.
var ErrNotPinnable = errors.New("the core pins only a GitHub noreply address " +
	"(<id>+<login>@users.noreply.github.com) named by its own <login>")

// CheckPinnable applies the core's pin rule (accounts.PinOperatorAuthor) on
// the machine, before asking.
func CheckPinnable(name, email string) error {
	login, ok := signing.NoreplyLogin(email)
	if !ok || name != login {
		return ErrNotPinnable
	}
	return nil
}

// ReportOperatorAuthor reports name and email to the core this machine is
// enrolled with, and answers whether the core pinned them now or already
// held them.
func ReportOperatorAuthor(ctx context.Context, paths Paths, name, email string) (PinOutcome, error) {
	c, err := cliConn(paths)
	if err != nil {
		return "", err
	}
	return reportOperatorAuthor(ctx, c.rt, c.base, name, email)
}

// PinnedOperatorAuthor answers the pair the core holds for this machine, ok
// false when it holds none.
func PinnedOperatorAuthor(ctx context.Context, paths Paths) (name, email string, ok bool, err error) {
	c, err := cliConn(paths)
	if err != nil {
		return "", "", false, err
	}
	return readOperatorAuthor(ctx, c.rt, c.base)
}

func reportOperatorAuthor(ctx context.Context, rt http.RoundTripper, coreURL, name, email string) (PinOutcome, error) {
	body, err := json.Marshal(OperatorAuthorReport{Name: name, Email: email})
	if err != nil {
		return "", err
	}
	raw, err := operatorAuthorCall(ctx, rt, http.MethodPost, coreURL, body)
	if err != nil {
		return "", err
	}
	var answer OperatorAuthorPinResult
	if json.Unmarshal(raw, &answer) == nil && answer.Result == PinHeld {
		return PinHeld, nil
	}
	// A core older than GH-011 answers no result; it pinned or held the pair.
	return PinNew, nil
}

func readOperatorAuthor(ctx context.Context, rt http.RoundTripper, coreURL string) (name, email string, ok bool, err error) {
	raw, err := operatorAuthorCall(ctx, rt, http.MethodGet, coreURL, nil)
	if err != nil {
		return "", "", false, err
	}
	var pin OperatorAuthorPin
	if err := json.Unmarshal(raw, &pin); err != nil {
		return "", "", false, fmt.Errorf("the core's answer is not a pin: %w", err)
	}
	if !pin.Pinned {
		return "", "", false, nil
	}
	return pin.Name, pin.Email, true, nil
}

// operatorAuthorCall makes one request to the route and answers a 200's
// body, or the core's refusal as an error.
func operatorAuthorCall(ctx context.Context, rt http.RoundTripper, method, coreURL string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var reader io.Reader = http.NoBody
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(coreURL, "/")+OperatorAuthorPath, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return nil, fmt.Errorf("the core answered %d, and its body could not be read: %w", resp.StatusCode, err)
	}
	if resp.StatusCode == http.StatusOK {
		return raw, nil
	}
	if resp.StatusCode == http.StatusConflict {
		var answer struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &answer) != nil || answer.Error == "" {
			answer.Error = strings.TrimSpace(string(raw))
		}
		return nil, fmt.Errorf("%w: %s", ErrOperatorAuthorPinned, answer.Error)
	}
	// A core older than the GET answers 405 (ENF-016): ErrCoreOlder.
	return nil, coreAnswerError(resp.StatusCode, raw)
}
