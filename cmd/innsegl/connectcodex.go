// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"innsegl.dev/innsegl/internal/client"
)

type codexCapabilities struct {
	Formats     []string `json:"formats"`
	Signing     bool     `json:"signing"`
	SigningMode string   `json:"signing_mode"`
	Agents      string   `json:"agents"`
}

var errCodexClientUnavailable = errors.New("the local client is unavailable; check innsegl status")

// Reuse the enrolled client's existing capability negotiation. It proves
// the configured client/core path accepts Responses before setup reports ready.
func readCodexCapabilities(ctx context.Context, base string) (codexCapabilities, error) {
	var caps codexCapabilities
	if _, err := client.CodexLaunchArgs(base, client.ReleaseBinary(), false); err != nil {
		return caps, err
	}
	httpClient := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/_client/capabilities", nil)
	if err != nil {
		return caps, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return caps, errCodexClientUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&caps) == nil {
		for _, format := range caps.Formats {
			if format == "responses-http" {
				return caps, nil
			}
		}
	}
	return caps, errors.New("upgrade the client and core for Responses capture and restore enrollment; check innsegl status")
}

func (d connectDeps) verifyCodexRuntime(ctx context.Context, cfg client.CodexManagedConfig, out io.Writer) error {
	load := d.codexCapabilities
	if load == nil {
		load = readCodexCapabilities
	}
	ready, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var caps codexCapabilities
	for {
		var err error
		caps, err = load(ready, cfg.LocalURL)
		if err == nil {
			break
		}
		if !errors.Is(err, errCodexClientUnavailable) {
			return err
		}
		select {
		case <-ready.Done():
			return err
		case <-time.After(100 * time.Millisecond):
		}
	}
	if caps.Agents != "linked-threads" {
		return errors.New("upgrade the client and core for managed Codex child-session capture")
	}
	if cfg.Signing && (!caps.Signing || caps.SigningMode != "structured") {
		return errors.New("upgrade the client and core for managed Codex commit signing")
	}
	fmt.Fprintln(out, "innsegl connect: the local client and enrolled core support Codex root/child capture")
	return nil
}

func (d connectDeps) codexConfig(f connectFlags, settings client.SettingsConfig) (client.CodexManagedConfig, error) {
	api, signing, err := client.CodexManagedMode(d.codexSettings)
	if err != nil {
		return client.CodexManagedConfig{}, err
	}
	if f.codexAPI != nil {
		api = *f.codexAPI
	}
	if f.codexSigning != nil {
		signing = *f.codexSigning
	}
	return client.CodexManagedConfig{LocalURL: settings.LocalURL, HookBin: settings.HookBin, API: api, Signing: signing}, nil
}

func (d connectDeps) checkCodexSettings(f connectFlags, settings client.SettingsConfig, install bool) error {
	if d.codexSettings == "" || (install && d.codexUnavailable) {
		return nil
	}
	cfg, err := d.codexConfig(f, settings)
	if err != nil {
		return err
	}
	if install {
		return client.ValidateCodexSettings(d.codexSettings, cfg)
	}
	return client.CheckCodexSettingsWritable(d.codexSettings, cfg, false)
}

func (d connectDeps) installCodexSettings(ctx context.Context, f connectFlags, settings client.SettingsConfig, out io.Writer) error {
	if d.codexSettings == "" {
		return nil
	}
	if d.codexUnavailable {
		fmt.Fprintln(out, "innsegl connect: Codex is not installed; its existing managed settings were retained")
		return nil
	}
	cfg, err := d.codexConfig(f, settings)
	if err != nil {
		return err
	}
	if err := d.verifyCodexRuntime(ctx, cfg, out); err != nil {
		return err
	}
	if err := client.InstallCodexSettings(d.codexSettings, cfg, d.now, out); err != nil {
		return err
	}
	load := d.loadCodex
	if load == nil {
		load = loadCodexSettings
	}
	if err := load(ctx, cfg); err != nil {
		return err
	}
	fprintf(out, "innsegl connect: Codex loaded its managed route, root/child lifecycle hooks and telemetry settings\n")
	fprintf(out, "innsegl connect: ordinary `codex` and `codex resume` use the gateway; restart Codex to load managed settings\n")
	if cfg.Signing {
		fprintf(out, "innsegl connect: Codex experimental signing uses direct shell calls; rewritten commits carry allow decisions for the whole shell invocation\n")
	}
	return nil
}

func reportCodexSetupError(err error, stderr io.Writer) int {
	return reportCodexSettingsError(err, stderr, "`innsegl connect --update`")
}

func reportCodexSettingsError(err error, stderr io.Writer, retry string) int {
	if code, done := reportNotWritable(err, stderr, ", then run "+retry); done {
		return code
	}
	fprintf(stderr, "innsegl connect: Codex managed setup is incomplete: %v\nResolve this and run %s.\n", err, retry)
	return exitConnectFailed
}
