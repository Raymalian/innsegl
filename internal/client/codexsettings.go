// SPDX-License-Identifier: Apache-2.0

package client

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// CodexLaunchArgs returns per-invocation settings, leaving the user's
// config and authentication files untouched. This initial route supports
// root CLI sessions only; nested execution is observed as wire evidence.
func CodexLaunchArgs(base, binary string, api bool) ([]string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("codex needs the local client service's plain loopback URL")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() || u.Port() == "" {
		return nil, fmt.Errorf("codex needs a loopback address with a port")
	}
	if !filepath.IsAbs(binary) || strings.ContainsAny(binary, "\r\n\x00") {
		return nil, fmt.Errorf("the hook binary must have an absolute path")
	}
	base = strings.TrimSuffix(base, "/")
	path := "/backend-api/codex"
	if api {
		path = "/v1"
	}
	values := []string{
		`model_provider="innsegl"`,
		`model_providers.innsegl.name="Innsegl"`,
		`model_providers.innsegl.base_url=` + strconv.Quote(base+path),
		`model_providers.innsegl.wire_api="responses"`,
		`model_providers.innsegl.requires_openai_auth=true`,
		`model_providers.innsegl.supports_websockets=false`,
		`agents.enabled=false`,
		`features.hooks=true`,
	}
	hook := "env INNSEGL_CORE_URL=" + shellQuote(base) + " " + shellQuote(binary) + " hook session --capture-only"
	for _, event := range []string{"SessionStart", "UserPromptSubmit", "SessionEnd"} {
		timeout := "5"
		if event == "SessionEnd" {
			timeout = "3"
		}
		values = append(values, "hooks."+event+"=[{hooks=[{type=\"command\",command="+strconv.Quote(hook)+",timeout="+timeout+"}]}]")
	}
	args := []string{"--no-daemon"}
	for _, v := range values {
		args = append(args, "-c", v)
	}
	return args, nil
}
