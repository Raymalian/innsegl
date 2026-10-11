// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Revoking this machine needs the person at it (#600, CLI-045). Any process
// of this user could otherwise disconnect the machine, and with it the
// recording of every agent on it. innsegl has no Touch ID prompt of its own
// (its only Touch ID path is the Secure Enclave age identity, which opens
// encrypted material and is not set up on every machine), so the person
// types a word on the controlling terminal. The terminal is opened
// directly: an agent's shell and a pipe have none, so they cannot answer.

// disconnectWord is what the person types to confirm a disconnect.
const disconnectWord = "disconnect"

// errNotConfirmed is a person who did not type the word.
var errNotConfirmed = errors.New("the disconnect was not confirmed")

// confirmTyped asks question on w and reads one line from r: nil only when
// the line is the word itself.
func confirmTyped(r io.Reader, w io.Writer, question string) error {
	if _, err := fmt.Fprintf(w, "%s\nType %q to go on: ", question, disconnectWord); err != nil {
		return err
	}
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.TrimSpace(line) != disconnectWord {
		return errNotConfirmed
	}
	return nil
}

// openTTY opens the controlling terminal for reading and writing.
func openTTY() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// confirmOnTerminal is a presence check that asks on the terminal open
// returns.
func confirmOnTerminal(open func() (*os.File, error)) func(string) error {
	return func(question string) error {
		tty, err := open()
		if err != nil {
			return fmt.Errorf("there is no terminal to confirm on (%w); run `innsegl connect --disconnect` "+
				"yourself, in a terminal", err)
		}
		defer func() { _ = tty.Close() }()
		return confirmTyped(tty, tty, question)
	}
}

// askPresence is deps.presence, or the terminal.
func (d connectDeps) askPresence(question string) error {
	if d.presence != nil {
		return d.presence(question)
	}
	return confirmOnTerminal(openTTY)(question)
}
