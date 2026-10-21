// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/client"
)

func codexCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("codex", flag.ContinueOnError)
	fs.SetOutput(stderr)
	api := fs.Bool("api", false, "use the API-key route instead of the ChatGPT-login route")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: innsegl codex [--api] -- [codex arguments]\n\nStart a Codex 0.163.0 root CLI session through the enrolled gateway.\nUses per-invocation routing and lifecycle hooks; does not edit user configuration.\nCapture only: subagents and signed-commit attribution are not supported yet.")
	}
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return exitOK
	} else if err != nil {
		return exitUsage
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	config, err := client.ReadCoreConfig(client.ClientPaths(home))
	if err != nil {
		fmt.Fprintln(stderr, "innsegl codex:", err)
		return exitConnectFailed
	}
	listen := config.Listen
	if listen == "" {
		listen = client.DefaultListen
	}
	base := "http://" + listen
	// Validate local endpoint before making any request or passing credentials.
	if _, err = client.CodexLaunchArgs(base, client.ReleaseBinary(), *api); err != nil {
		fmt.Fprintln(stderr, "innsegl codex:", err)
		return exitUsage
	}
	httpClient := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/_client/capabilities", nil)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintln(stderr, "innsegl codex: the local client is unavailable; check innsegl status")
		return exitConnectFailed
	}
	defer resp.Body.Close()
	var caps struct {
		Formats []string `json:"formats"`
	}
	supported := false
	if resp.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&caps) == nil {
		for _, f := range caps.Formats {
			supported = supported || f == "responses-http"
		}
	}
	if !supported {
		fmt.Fprintln(stderr, "innsegl codex: upgrade the client and core for Responses capture and restore enrollment; check innsegl status")
		return exitConnectFailed
	}
	if _, err = os.Stat(client.ReleaseBinary()); err != nil {
		fmt.Fprintln(stderr, "innsegl codex: install the release binary before running lifecycle hooks")
		return exitConnectFailed
	}
	fmt.Fprintln(stderr, "innsegl: root-session capture; lifecycle hooks set for this invocation; subagents and signed commits are not supported. Review lifecycle hooks with /hooks before the first task.")
	return runCodexProcess("codex", base, client.ReleaseBinary(), *api, fs.Args(), os.Stdin, stdout, stderr)
}

func runCodexProcess(program, base, hookBinary string, api bool, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// A profile, alternate daemon or later config override could select a
	// different provider or replace the lifecycle hooks installed here.
	for _, arg := range args {
		if strings.HasPrefix(arg, "-c") || arg == "--oss" || strings.HasPrefix(arg, "--local-provider") || arg == "--config" || strings.HasPrefix(arg, "-p") || arg == "--profile" || strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "--profile=") || strings.HasPrefix(arg, "--remote") || strings.HasPrefix(arg, "-c=") {
			fmt.Fprintln(stderr, "innsegl codex: configuration/profile/remote overrides are not supported by this capture launcher")
			return exitUsage
		}
	}
	version, err := exec.CommandContext(context.Background(), program, "--version").Output()
	if err != nil || strings.TrimSpace(string(version)) != "codex-cli 0.163.0" {
		fmt.Fprintln(stderr, "innsegl codex: this build supports Codex CLI 0.163.0 only")
		return exitUsage
	}
	fixed, err := client.CodexLaunchArgs(base, hookBinary, api)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	// The executable is selected by the operator; arguments are passed directly without a shell.
	cmd := exec.CommandContext(context.Background(), program, append(fixed, args...)...) //nolint:gosec // Intentional CLI launcher after routing override validation.
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err = cmd.Run(); err != nil {
		var status *exec.ExitError
		if errors.As(err, &status) {
			return status.ExitCode()
		}
		fmt.Fprintln(stderr, "innsegl codex:", err)
		return exitConnectFailed
	}
	return exitOK
}
