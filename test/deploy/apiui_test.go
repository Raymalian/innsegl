// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// #475: `innsegl api` serves the dashboard. The innsegl-dashboard (nginx)
// container is gone; innsegl-api runs an image of its own — the runtime
// image plus the built UI — publishes the dashboard's two ports, and
// terminates its TLS with the certificate the core writes.

// dashboardTLSVolume holds the dashboard's certificate and key; the core
// writes it (RM-311). The ports are bindaddress_test.go's.
const dashboardTLSVolume = "innsegl-dashboard-tls"

func allProfilesConfig(ctx context.Context, t *testing.T) composeConfig {
	t.Helper()
	return interpolateComposeProfiles(ctx, t, "innsegl-segments",
		[]string{"init", "separate", "demo", "canary"}, "deploy/compose/innsegl.yml")
}

func TestTheDashboardContainerIsGone(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{"deploy/docker/dashboard.Dockerfile", "deploy/docker/dashboard-nginx.conf"} {
		if _, err := os.Stat(filepath.Join(root, rel)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still exists (err %v); innsegl-api serves the dashboard", rel, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping the compose half: %v", err)
	}
	if _, ok := allProfilesConfig(ctx, t).Services["innsegl-dashboard"]; ok {
		t.Error("innsegl.yml still declares innsegl-dashboard")
	}
}

// uiDirInImage is where the Dockerfile's api target puts the built UI.
func uiDirInImage(t *testing.T) string {
	t.Helper()
	df := readFile(t, filepath.Join(repoRoot(t), "Dockerfile"))
	stage := dockerfileStage(t, df, "api")
	m := regexp.MustCompile(`(?m)^COPY --from=ui-build \S+ (\S+)$`).FindStringSubmatch(stage)
	if m == nil {
		t.Fatalf("the Dockerfile's api target copies no UI from ui-build:\n%s", stage)
	}
	return m[1]
}

// dockerfileStage is the text of one named stage: from its FROM line to
// the next FROM.
func dockerfileStage(t *testing.T, df, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?ms)^FROM [^\n]* AS ` + regexp.QuoteMeta(name) + `\n(.*?)(?:^FROM |\z)`).FindStringSubmatch(df)
	if m == nil {
		t.Fatalf("the Dockerfile has no stage named %s", name)
	}
	return m[1]
}

func TestTheAPIServesTheDashboard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping: %v", err)
	}
	cfg := allProfilesConfig(ctx, t)
	apiSvc := cfg.service(t, "innsegl-api")
	mcp := cfg.service(t, "innsegl-mcp")

	// Its own image, from the api target; the core keeps the runtime one,
	// so a UI change restarts innsegl-api alone.
	if apiSvc.Build == nil || apiSvc.Build.Target != "api" {
		t.Errorf("innsegl-api builds %+v, want the Dockerfile's api target", apiSvc.Build)
	}
	if mcp.Build == nil || mcp.Build.Target != "runtime" {
		t.Errorf("innsegl-mcp builds %+v, want the runtime target", mcp.Build)
	}
	if apiSvc.Image == mcp.Image {
		t.Errorf("innsegl-api and innsegl-mcp share the image %s; a UI change would restart the core", apiSvc.Image)
	}

	env := func(k string) string {
		v, _ := cfg.env("innsegl-api", k)
		return v
	}
	if got, want := env("INNSEGL_API_UI_DIR"), uiDirInImage(t); got != want {
		t.Errorf("INNSEGL_API_UI_DIR=%q, but the api target puts the UI at %q", got, want)
	}

	// The certificate: the core's volume, read-only, at the file the core
	// names (gateway.DashboardTLSFileName).
	certFile := env("INNSEGL_API_TLS_CERT")
	if path.Base(certFile) != "dashboard-tls.pem" {
		t.Errorf("INNSEGL_API_TLS_CERT=%q, want the core's dashboard-tls.pem", certFile)
	}
	mounted := false
	for _, v := range apiSvc.Volumes {
		if v.Source != dashboardTLSVolume {
			continue
		}
		mounted = true
		if !v.ReadOnly {
			t.Errorf("innsegl-api mounts %s read-write; the core is its one writer", dashboardTLSVolume)
		}
		if v.Target != path.Dir(certFile) {
			t.Errorf("%s is mounted at %s, but INNSEGL_API_TLS_CERT is %s", dashboardTLSVolume, v.Target, certFile)
		}
	}
	if !mounted {
		t.Errorf("innsegl-api does not mount %s", dashboardTLSVolume)
	}

	// The listeners and what is published to them.
	for k, port := range map[string]int{"INNSEGL_API_LISTEN": dashboardContainerPort, "INNSEGL_API_TLS_LISTEN": dashboardTLSContainerPort} {
		_, p, err := net.SplitHostPort(env(k))
		if err != nil || p != strconv.Itoa(port) {
			t.Errorf("%s=%q, want port %d", k, env(k), port)
		}
	}
	published := map[int]string{}
	for _, p := range apiSvc.Ports {
		published[p.Target] = p.Published
	}
	if published[dashboardTLSContainerPort] != "8443" {
		t.Errorf("innsegl-api publishes %d on host port %q, want 8443 (the address passkeys bind to)",
			dashboardTLSContainerPort, published[dashboardTLSContainerPort])
	}
	if published[dashboardContainerPort] != "8082" {
		t.Errorf("innsegl-api publishes %d on host port %q, want 8082 (localhost's plain HTTP)",
			dashboardContainerPort, published[dashboardContainerPort])
	}

	// A container on internal networks alone cannot publish a port.
	if _, ok := apiSvc.Networks["innsegl-dashboard-frontend"]; !ok {
		t.Errorf("innsegl-api is not on innsegl-dashboard-frontend, so its ports cannot be published: %v", apiSvc.Networks)
	}
	// And never on the MCP's client network: the dashboard has no route to
	// the write surface (doc 05 §1).
	if _, ok := apiSvc.Networks["innsegl-mcp-clients"]; ok {
		t.Error("innsegl-api joined innsegl-mcp-clients")
	}
	for name, svc := range cfg.Services {
		for _, v := range svc.Volumes {
			if v.Source == dashboardTLSVolume && !v.ReadOnly && name != "innsegl-mcp" {
				t.Errorf("%s mounts %s read-write; only the core writes it", name, dashboardTLSVolume)
			}
		}
	}
}

// The compose settings of innsegl-api pass `innsegl api`'s own option
// checks. A setting the command refuses crash-loops the service on every
// host, and nothing at build time says so (measured twice for the core in
// the week before #475). This runs the shipped binary with exactly the
// environment and command compose gives the service, the DSNs pointed at a
// closed port: past its checks it exits 11 (UNAVAILABLE, no ledger); a
// refused setting exits 2.
func TestTheAPIAcceptsItsOwnComposeSettings(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping: %v", err)
	}
	cfg := allProfilesConfig(ctx, t)
	svc := cfg.service(t, "innsegl-api")
	bin := buildInnsegl(ctx, t)

	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	for k, v := range svc.Environment {
		if v == nil {
			continue
		}
		val := *v
		if strings.HasSuffix(k, "_DSN") && val != "" {
			val = "postgres://nobody:x@127.0.0.1:1/innsegl?sslmode=disable&connect_timeout=2"
		}
		env = append(env, k+"="+val)
	}
	run := exec.CommandContext(ctx, bin, svc.Command...)
	run.Env = env
	out, err := run.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("innsegl %v did not exit with a status: %v\n%s", svc.Command, err, out)
	}
	if code := exit.ExitCode(); code != 11 {
		t.Fatalf("innsegl %v with innsegl-api's compose settings exited %d, want 11 "+
			"(past every option check, stopped only by the unreachable ledger):\n%s", svc.Command, code, out)
	}
}

// An existing deployment still has the innsegl-dashboard container, which
// holds the dashboard's ports. Compose leaves a container whose service is
// gone from the file running, so `make update` must remove it, or
// innsegl-api cannot bind 8443 and 8082.
func TestTheUpdateRemovesTheContainersOfRemovedServices(t *testing.T) {
	mk := readFile(t, filepath.Join(repoRoot(t), "Makefile"))
	m := regexp.MustCompile(`(?ms)^innsegl-here-services:[^\n]*\n(.*?)\n\n`).FindStringSubmatch(mk)
	if m == nil {
		t.Fatal("the Makefile has no innsegl-here-services target")
	}
	up := regexp.MustCompile(`\$\(INNSEGL_COMPOSE\) up -d[^\n]*`).FindString(m[1])
	if up == "" {
		t.Fatal("innsegl-here-services runs no `$(INNSEGL_COMPOSE) up -d`")
	}
	if !strings.Contains(up, "--remove-orphans") {
		t.Errorf("innsegl-here-services runs %q without --remove-orphans; an old innsegl-dashboard "+
			"would keep the dashboard's ports", up)
	}
	if !regexp.MustCompile(`(?ms)^update:\n.*\$\(MAKE\) --no-print-directory innsegl-here-services`).MatchString(mk) {
		t.Error("make update no longer goes through innsegl-here-services")
	}
}
