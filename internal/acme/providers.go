// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/acmedns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/desec"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/dnsimple"
	"github.com/go-acme/lego/v4/providers/dns/exec"
	"github.com/go-acme/lego/v4/providers/dns/gandiv5"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/hetzner"
	"github.com/go-acme/lego/v4/providers/dns/httpreq"
	"github.com/go-acme/lego/v4/providers/dns/linode"
	"github.com/go-acme/lego/v4/providers/dns/namecheap"
	"github.com/go-acme/lego/v4/providers/dns/ns1"
	"github.com/go-acme/lego/v4/providers/dns/ovh"
	"github.com/go-acme/lego/v4/providers/dns/porkbun"
	"github.com/go-acme/lego/v4/providers/dns/rfc2136"
	"github.com/go-acme/lego/v4/providers/dns/vultr"
)

// The DNS providers compiled in. The library supports far more, but its
// all-providers factory brings every cloud SDK and more than doubles the
// binary, past the size the SPIRE agent hashes a workload's binary up to
// (deploy/compose/spire/agent.conf, workload_size_limit): the core would get
// no identity. These are the providers with a plain API token, plus the
// three generic ones (RFC 2136 dynamic updates, an HTTP endpoint, and a
// command) that reach any DNS a deployment runs. Adding one is one line
// here; test/deploy's binary-size test says whether it still fits.
var providers = map[string]func() (challenge.Provider, error){
	"acme-dns":     func() (challenge.Provider, error) { return acmedns.NewDNSProvider() },
	"cloudflare":   func() (challenge.Provider, error) { return cloudflare.NewDNSProvider() },
	"desec":        func() (challenge.Provider, error) { return desec.NewDNSProvider() },
	"digitalocean": func() (challenge.Provider, error) { return digitalocean.NewDNSProvider() },
	"dnsimple":     func() (challenge.Provider, error) { return dnsimple.NewDNSProvider() },
	"exec":         func() (challenge.Provider, error) { return exec.NewDNSProvider() },
	"gandiv5":      func() (challenge.Provider, error) { return gandiv5.NewDNSProvider() },
	"godaddy":      func() (challenge.Provider, error) { return godaddy.NewDNSProvider() },
	"hetzner":      func() (challenge.Provider, error) { return hetzner.NewDNSProvider() },
	"httpreq":      func() (challenge.Provider, error) { return httpreq.NewDNSProvider() },
	"linode":       func() (challenge.Provider, error) { return linode.NewDNSProvider() },
	"namecheap":    func() (challenge.Provider, error) { return namecheap.NewDNSProvider() },
	"ns1":          func() (challenge.Provider, error) { return ns1.NewDNSProvider() },
	"ovh":          func() (challenge.Provider, error) { return ovh.NewDNSProvider() },
	"porkbun":      func() (challenge.Provider, error) { return porkbun.NewDNSProvider() },
	"rfc2136":      func() (challenge.Provider, error) { return rfc2136.NewDNSProvider() },
	"vultr":        func() (challenge.Provider, error) { return vultr.NewDNSProvider() },
}

// Providers names the DNS providers this build can use, sorted.
func Providers() []string {
	out := make([]string, 0, len(providers))
	for name := range providers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// providerByName builds the named provider from its own settings.
func providerByName(name string) (challenge.Provider, error) {
	build, ok := providers[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("not one this build supports (%s)", strings.Join(Providers(), ", "))
	}
	return build()
}
