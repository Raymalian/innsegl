// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/version"
)

// `innsegl status` (#472): from an enrolled machine, what is up, what is
// down, the versions, and this machine's scope. Exit 1 names what is down.

type statusDeps struct {
	home string
	// localURL overrides where the client service is asked; empty means the
	// address the enrolment recorded.
	localURL string
}

func statusCommand(args []string, stdout, stderr io.Writer) int {
	home, err := os.UserHomeDir()
	if err != nil {
		fprintf(stderr, "innsegl status: %v\n", err)
		return exitUsage
	}
	return runStatus(context.Background(), args, stdout, stderr, statusDeps{home: home})
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer, deps statusDeps) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fprintf(stderr, "usage: innsegl status\n")
		return exitUsage
	}
	paths := client.ClientPaths(deps.home)
	if _, err := client.ReadCoreConfig(paths); err != nil {
		fprintf(stderr, "innsegl status: this machine is not connected to a core (%v)\n", err)
		return exitConnectFailed
	}

	var down []string
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	line := func(name string, up bool, detail string) {
		state := "up"
		if !up {
			state = "DOWN"
			down = append(down, name)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", name, state, detail)
	}
	fmt.Fprintf(tw, "this binary\t\t%s\n", version.String())

	local := deps.localURL
	if local == "" {
		local = "http://" + enrolledListen(paths)
	}
	if svc, err := localClientStatus(ctx, local); err != nil {
		line("client service", false, "not answering at "+local+": run `innsegl connect --update` or restart it")
	} else {
		detail := "certificate until " + svc.CertificateExpiresAt
		if svc.Revoked {
			detail = "the core refused this machine's renewal; enrol again"
		}
		line("client service", !svc.Revoked, detail)
	}

	body, err := client.FetchCoreStatus(ctx, paths)
	if err != nil {
		line("core", false, err.Error())
	} else {
		var st coreStatus
		if jerr := json.Unmarshal(body, &st); jerr != nil {
			line("core", false, "unreadable status: "+jerr.Error())
		} else {
			line("core", true, st.Version)
			for _, c := range st.Components {
				line(c.Name, c.Up, c.Detail)
			}
			in := st.Installation
			repos := strings.Join(in.Repos, ", ")
			if len(in.Repos) == 0 || (len(in.Repos) == 1 && in.Repos[0] == "*") {
				repos = "all repositories"
			}
			fmt.Fprintf(tw, "this machine\t%s\t%s, %s, %s, %s\n", in.Status, in.Name, in.Kind, in.Organisation, repos)
		}
	}
	if err := tw.Flush(); err != nil {
		return exitConnectFailed
	}
	if len(down) > 0 {
		fprintf(stderr, "innsegl status: down: %s\n", strings.Join(down, ", "))
		return exitConnectFailed
	}
	return exitOK
}

type localStatus struct {
	Revoked              bool   `json:"revoked"`
	CertificateExpiresAt string `json:"certificate_expires_at"`
}

func localClientStatus(ctx context.Context, base string) (localStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+client.StatusPath, http.NoBody)
	if err != nil {
		return localStatus{}, err
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return localStatus{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var st localStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil {
		return localStatus{}, err
	}
	return st, nil
}
