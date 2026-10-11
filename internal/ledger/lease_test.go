// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// openLeases opens the writer lease of a migrated store's database.
func openLeases(t *testing.T, dsn string) *Leases {
	t.Helper()
	l, err := OpenLeases(testCtx(t, 30*time.Second), dsn)
	if err != nil {
		t.Fatalf("OpenLeases: %v", err)
	}
	t.Cleanup(l.Close)
	return l
}

// openWriter opens a store whose connections say they write as holder: the
// shape a core that holds the lease runs in.
func openWriter(t *testing.T, dsn, holder string) *Store {
	t.Helper()
	s, err := OpenAs(testCtx(t, 30*time.Second), dsn, holder)
	if err != nil {
		t.Fatalf("OpenAs: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// LED-047 — one core writes a ledger at a time (RM-326, #580).
func TestLED047OneCoreHoldsTheWriterLease(t *testing.T) {
	_, dsn := newStore(t)
	leases := openLeases(t, dsn)
	ctx := testCtx(t, 60*time.Second)

	if _, held, err := leases.Status(ctx); err != nil || held {
		t.Fatalf("Status on a fresh ledger = held %v, err %v; want no lease", held, err)
	}

	a, err := leases.Acquire(ctx, "core-a", time.Minute)
	if err != nil {
		t.Fatalf("core-a Acquire: %v", err)
	}
	if a.Holder != "core-a" || a.Epoch < 1 || !a.ExpiresAt.After(time.Now()) {
		t.Fatalf("core-a's lease = %+v; want holder core-a, an epoch, a future expiry", a)
	}

	t.Run("a second core is refused while the lease is live", func(t *testing.T) {
		_, err := leases.Acquire(ctx, "core-b", time.Minute)
		var held *LeaseHeldError
		if !errors.As(err, &held) || held.Lease.Holder != "core-a" {
			t.Fatalf("core-b Acquire = %v; want a LeaseHeldError naming core-a", err)
		}
	})

	t.Run("the holder renews, and the epoch stays", func(t *testing.T) {
		r, err := leases.Renew(ctx, a, time.Minute)
		if err != nil {
			t.Fatalf("Renew: %v", err)
		}
		if r.Epoch != a.Epoch || r.ExpiresAt.Before(a.ExpiresAt) {
			t.Fatalf("renewed %+v from %+v; want the same epoch and a later expiry", r, a)
		}
	})

	t.Run("the holder appends; another core's append is refused by the database", func(t *testing.T) {
		if _, err := openWriter(t, dsn, "core-a").Append(ctx, storeBody(1)); err != nil {
			t.Fatalf("the holder's append: %v", err)
		}
		_, err := openWriter(t, dsn, "core-b").Append(ctx, storeBody(2))
		if se := storeError(t, err); se.Class != ClassLedgerUnavailable || !se.Retryable {
			t.Fatalf("a non-holder's append = %+v; want LEDGER_UNAVAILABLE, retryable", se)
		}
	})

	t.Run("a released lease is taken by the next core, and the old one is fenced", func(t *testing.T) {
		if err := leases.Release(ctx, a); err != nil {
			t.Fatalf("Release: %v", err)
		}
		b, err := leases.Acquire(ctx, "core-b", time.Minute)
		if err != nil {
			t.Fatalf("core-b Acquire after the release: %v", err)
		}
		if b.Epoch <= a.Epoch {
			t.Fatalf("core-b's epoch %d is not after core-a's %d", b.Epoch, a.Epoch)
		}
		if _, err := leases.Renew(ctx, a, time.Minute); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("core-a's Renew after the handover = %v; want ErrLeaseLost", err)
		}
		if _, err := openWriter(t, dsn, "core-a").Append(ctx, storeBody(3)); err == nil {
			t.Fatal("core-a appended after it lost the lease")
		}
		if _, err := openWriter(t, dsn, "core-b").Append(ctx, storeBody(4)); err != nil {
			t.Fatalf("core-b's append: %v", err)
		}
		if err := leases.Release(ctx, b); err != nil {
			t.Fatalf("Release core-b: %v", err)
		}
	})

	t.Run("an expired lease is taken over", func(t *testing.T) {
		c, err := leases.Acquire(ctx, "core-c", 50*time.Millisecond)
		if err != nil {
			t.Fatalf("core-c Acquire: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
		if _, aerr := openWriter(t, dsn, "core-c").Append(ctx, storeBody(5)); aerr == nil {
			t.Fatal("core-c appended on an expired lease")
		}
		d, err := leases.Acquire(ctx, "core-d", time.Minute)
		if err != nil {
			t.Fatalf("core-d could not take over an expired lease: %v", err)
		}
		if d.Epoch <= c.Epoch {
			t.Fatalf("core-d's epoch %d is not after core-c's %d", d.Epoch, c.Epoch)
		}
		if _, err := leases.Renew(ctx, c, time.Minute); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("core-c's Renew after the takeover = %v; want ErrLeaseLost", err)
		}
	})

	t.Run("a store that names no writer is not fenced by the lease", func(t *testing.T) {
		// One-shot commands (retire, migrate-schema) run beside the core
		// and append through the same serialized path.
		s, err := Open(ctx, dsn)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer s.Close()
		if _, err := s.Append(ctx, storeBody(6)); err != nil {
			t.Fatalf("an unnamed append while core-d holds the lease: %v", err)
		}
	})

	t.Run("the refusal names the holder and its expiry", func(t *testing.T) {
		_, err := leases.Acquire(ctx, "core-e", time.Minute)
		var held *LeaseHeldError
		if !errors.As(err, &held) || !strings.Contains(err.Error(), "core-d") {
			t.Fatalf("Acquire while core-d holds = %v; want a refusal naming core-d", err)
		}
	})

	t.Run("an unreachable ledger is LEDGER_UNAVAILABLE on every call", func(t *testing.T) {
		if _, err := OpenLeases(ctx, "not a dsn ::"); err == nil {
			t.Fatal("OpenLeases on an unparseable dsn succeeded")
		}
		if _, err := OpenLeases(ctx, "postgres://nobody@127.0.0.1:1/x?sslmode=disable&connect_timeout=1"); err == nil {
			t.Fatal("OpenLeases on an unreachable ledger succeeded")
		}
		gone := openLeases(t, dsn)
		gone.Close()
		if _, _, err := gone.Status(ctx); storeError(t, err).Class != ClassLedgerUnavailable {
			t.Fatalf("Status on a closed pool = %v", err)
		}
		if _, err := gone.Acquire(ctx, "core-f", time.Minute); storeError(t, err).Class != ClassLedgerUnavailable {
			t.Fatalf("Acquire on a closed pool = %v", err)
		}
		if err := gone.Release(ctx, WriterLease{Holder: "core-f"}); storeError(t, err).Class != ClassLedgerUnavailable {
			t.Fatalf("Release on a closed pool = %v", err)
		}
	})

	t.Run("an empty holder is refused", func(t *testing.T) {
		if _, err := leases.Acquire(ctx, "", time.Minute); err == nil {
			t.Fatal("Acquire with no holder succeeded")
		}
		if _, err := OpenAs(ctx, dsn, ""); err == nil {
			t.Fatal("OpenAs with no holder succeeded")
		}
	})
}

// LED-048 — a frozen ledger never writes (RM-326, #580).
func TestLED048AFrozenLedgerRefusesEveryAppend(t *testing.T) {
	_, dsn := newStore(t)
	leases := openLeases(t, dsn)
	ctx := testCtx(t, 60*time.Second)

	a, err := leases.Acquire(ctx, "core-a", time.Minute)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	frozen, err := leases.Freeze(ctx, "moving to a new host")
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	if frozen.FrozenAt == nil || frozen.FrozenReason != "moving to a new host" || frozen.Holder != "" {
		t.Fatalf("after Freeze the lease reads %+v; want a freeze time, the reason, and no holder", frozen)
	}
	again, err := leases.Freeze(ctx, "a second reason")
	if err != nil {
		t.Fatalf("a second Freeze: %v", err)
	}
	if !again.FrozenAt.Equal(*frozen.FrozenAt) || again.FrozenReason != frozen.FrozenReason {
		t.Fatalf("a second Freeze changed the freeze to %+v from %+v; freezing twice is one freeze", again, frozen)
	}

	for name, s := range map[string]*Store{
		"the holder":       openWriter(t, dsn, "core-a"),
		"an unnamed store": newStoreOn(t, dsn),
	} {
		_, err := s.Append(ctx, storeBody(1))
		if se := storeError(t, err); se.Class != ClassLedgerUnavailable {
			t.Errorf("%s appended to a frozen ledger: %+v", name, se)
		}
	}
	if _, err := rawConn(t, dsn).Exec(ctx, `SELECT 1`); err != nil {
		t.Fatalf("a frozen ledger must still be readable: %v", err)
	}

	if _, err := leases.Acquire(ctx, "core-b", time.Minute); !errors.Is(err, ErrFrozen) {
		t.Fatalf("Acquire on a frozen ledger = %v; want ErrFrozen", err)
	}
	if _, err := leases.Renew(ctx, a, time.Minute); !errors.Is(err, ErrFrozen) {
		t.Fatalf("Renew on a frozen ledger = %v; want ErrFrozen", err)
	}

	if err := leases.Thaw(ctx); err != nil {
		t.Fatalf("Thaw: %v", err)
	}
	if st, _, err := leases.Status(ctx); err != nil || st.FrozenAt != nil {
		t.Fatalf("after Thaw the lease reads %+v, %v; want no freeze", st, err)
	}
	if _, err := leases.Acquire(ctx, "core-b", time.Minute); err != nil {
		t.Fatalf("Acquire after Thaw: %v", err)
	}
	if _, err := openWriter(t, dsn, "core-b").Append(ctx, storeBody(2)); err != nil {
		t.Fatalf("an append after Thaw: %v", err)
	}
	if err := leases.Thaw(ctx); err != nil {
		t.Fatalf("thawing a ledger that is not frozen: %v", err)
	}

	t.Run("a freeze with no lease ever taken still refuses", func(t *testing.T) {
		_, dsn := newStore(t)
		fresh := openLeases(t, dsn)
		if _, err := fresh.Freeze(ctx, "copy"); err != nil {
			t.Fatalf("Freeze: %v", err)
		}
		s := newStoreOn(t, dsn)
		if _, err := s.Append(ctx, storeBody(1)); err == nil {
			t.Fatal("appended to a ledger frozen before any core held it")
		}
	})

	t.Run("a freeze needs a reason", func(t *testing.T) {
		if _, err := leases.Freeze(ctx, "  "); err == nil {
			t.Fatal("Freeze with no reason succeeded")
		}
	})
}

// newStoreOn opens a plain store on an already migrated database.
func newStoreOn(t *testing.T, dsn string) *Store {
	t.Helper()
	s, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}
