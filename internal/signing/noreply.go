// SPDX-License-Identifier: Apache-2.0

package signing

import "regexp"

// noreplyAddress is GitHub's account-linked noreply address,
// `<digits>+<login>@users.noreply.github.com`: the address GitHub attaches to
// the account, and the one a deploy host matches against its team. The older
// form without the digits is not linked to an account by id, so it is not
// accepted. Migration 0015 holds the same rule for the pinned pair.
var noreplyAddress = regexp.MustCompile(`^[0-9]+\+([A-Za-z0-9-]+)@users\.noreply\.github\.com$`)

// NoreplyLogin answers the GitHub login a noreply address names, and whether
// email is one (#545). An operator author is `<login> <email>`: the address
// is what a host matches, and the login is a label the account already
// publishes — never a person's name read from git's user.name.
func NoreplyLogin(email string) (string, bool) {
	m := noreplyAddress.FindStringSubmatch(email)
	if m == nil {
		return "", false
	}
	return m[1], true
}
