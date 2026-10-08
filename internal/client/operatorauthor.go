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

// ReportOperatorAuthor reports name and email to the core this machine is
// enrolled with.
func ReportOperatorAuthor(ctx context.Context, paths Paths, name, email string) error {
	s, err := NewServer(paths, io.Discard)
	if err != nil {
		return err
	}
	return reportOperatorAuthor(ctx, s.transport, s.core.CoreURL, name, email)
}

func reportOperatorAuthor(ctx context.Context, rt http.RoundTripper, coreURL, name, email string) error {
	body, err := json.Marshal(OperatorAuthorReport{Name: name, Email: email})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(coreURL, "/")+OperatorAuthorPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return fmt.Errorf("the core answered %d, and its body could not be read: %w", resp.StatusCode, err)
	}
	var answer struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &answer) != nil {
		// Not the core's JSON (a proxy's page, say): its text is the message.
		answer.Error = ""
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusConflict:
		return fmt.Errorf("%w: %s", ErrOperatorAuthorPinned, answer.Error)
	default:
		if answer.Error == "" {
			answer.Error = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("the core answered %d: %s", resp.StatusCode, answer.Error)
	}
}
