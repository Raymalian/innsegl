// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"time"

	"innsegl.dev/innsegl/migrations"
)

// The API waits for the schema its own code needs (ACC-016).
//
// The core (innsegl serve) applies migrations at its start; the API never
// does. `make update` recreates both, and compose starts the API without
// waiting for the core, which may still be migrating: a new API answering
// from tables that lack its columns fails requests until the core catches
// up. So the API reads the applied version first and does not listen until
// it is at least the newest migration this binary carries. Its container is
// not healthy meanwhile, and the log says what it waits for.
//
// It waits on the schema, not on the core's readiness: the core's /readyz
// also needs SPIRE and Sigstore, and the dashboard must come up during their
// outages, which is when it is read.

// schemaPoll is how often a waiting API asks again.
const schemaPoll = 2 * time.Second

// neededSchema is the newest migration embedded in this binary.
func neededSchema() (string, error) {
	all, err := migrations.All()
	if err != nil {
		return "", err
	}
	return all[len(all)-1].Version, nil
}

// waitForSchema returns once read answers a version at or past want, or when
// ctx ends. A failed read is logged and asked again: the database may still
// be starting.
func waitForSchema(ctx context.Context, read func(context.Context) (string, error), want string,
	log *serveLog, every time.Duration,
) error {
	logged := false
	for {
		got, err := read(ctx)
		if err == nil && got >= want {
			if logged {
				log.info("the core has applied the schema; serving", "schema", got)
			}
			return nil
		}
		if !logged {
			log.warn(fmt.Sprintf("waiting for the core to apply migration %s before serving", want),
				"applied", got, "err", err)
			logged = true
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("stopped while waiting for migration %s: %w", want, ctx.Err())
		case <-time.After(every):
		}
	}
}
