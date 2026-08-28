// SPDX-License-Identifier: Apache-2.0

package event

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"strings"
	"testing"
)

// buildGate is the compile-time assertion in canonical.go, quoted exactly.
// A duplicate constant key in a map literal is a compile error, so the two
// version constants cannot drift apart without `go build ./...` failing.
const buildGate = `map[bool]struct{}{false: {}, SerializerVersion == SchemaVersion: {}}`

// TestSER005VersionTagCannotDriftFromSchemaVersion is SER-005: a serializer
// version bump without a new version tag must fail the build.
func TestSER005VersionTagCannotDriftFromSchemaVersion(t *testing.T) {
	if SerializerVersion != SchemaVersion {
		t.Fatalf("SerializerVersion = %q, SchemaVersion = %q", SerializerVersion, SchemaVersion)
	}

	// The gate has to actually be in the shipped source. Deleting it must fail
	// SER-005 rather than quietly removing the protection.
	src, err := os.ReadFile("canonical.go")
	if err != nil {
		t.Fatalf("read canonical.go: %v", err)
	}
	if !bytes.Contains(src, []byte(buildGate)) {
		t.Fatalf("the compile-time version gate is missing from canonical.go; expected:\n\t%s",
			buildGate)
	}

	// And it has to bite. Type-check the gate against constants that agree and
	// against constants that do not.
	t.Run("versions agree: compiles", func(t *testing.T) {
		if err := typeCheckGate(t, "1", "1"); err != nil {
			t.Errorf("matching versions failed to compile: %v", err)
		}
	})
	t.Run("versions diverge: does not compile", func(t *testing.T) {
		err := typeCheckGate(t, "2", "1")
		if err == nil {
			t.Fatal("a serializer version bump with no schema version bump compiled")
		}
		if !strings.Contains(err.Error(), "duplicate key") {
			t.Errorf("compile failed for the wrong reason: %v", err)
		}
		t.Logf("build failure as designed: %v", err)
	})
}

// typeCheckGate compiles the build gate with the two version constants set to
// the given values, and reports the compiler's verdict.
func typeCheckGate(t *testing.T, serializerVersion, schemaVersion string) error {
	t.Helper()

	src := "package gate\n\n" +
		"const SerializerVersion = \"" + serializerVersion + "\"\n" +
		"const SchemaVersion = \"" + schemaVersion + "\"\n\n" +
		"var _ = " + buildGate + "\n"

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "gate.go", src, 0)
	if err != nil {
		t.Fatalf("parse gate: %v", err)
	}
	_, err = new(types.Config).Check("gate", fset, []*ast.File{f}, nil)
	return err
}

// TestSER005UnregisteredVersionIsRejected is SER-005: a version tag with no
// registered spec cannot serialize anything.
func TestSER005UnregisteredVersionIsRejected(t *testing.T) {
	if _, err := LookupFormat("2"); !errors.Is(err, ErrUnregisteredSerializer) {
		t.Errorf(`LookupFormat("2"): err = %v, want %v`, err, ErrUnregisteredSerializer)
	}
	if _, err := LookupFormat(""); !errors.Is(err, ErrUnregisteredSerializer) {
		t.Errorf(`LookupFormat(""): err = %v, want %v`, err, ErrUnregisteredSerializer)
	}

	spec, err := LookupFormat(SerializerVersion)
	if err != nil {
		t.Fatalf("LookupFormat(%q): %v", SerializerVersion, err)
	}
	if spec.Version != SerializerVersion || spec.SchemaVersion != SchemaVersion {
		t.Errorf("spec = %+v", spec)
	}
	if spec.GenesisSeed != GenesisSeed {
		t.Errorf("spec.GenesisSeed = %q, want %q", spec.GenesisSeed, GenesisSeed)
	}

	current, err := CurrentFormat()
	if err != nil {
		t.Fatalf("CurrentFormat: %v", err)
	}
	if current != spec {
		t.Errorf("CurrentFormat() = %+v, want %+v", current, spec)
	}

	// With the tag unregistered, nothing may be hashed under it: an event_hash
	// produced by an unknown serializer is an unverifiable record.
	withoutCurrentSpec(t, func() {
		f := loadFixture(t, "01-run_registered").input
		if _, err := CurrentFormat(); !errors.Is(err, ErrUnregisteredSerializer) {
			t.Errorf("CurrentFormat: err = %v, want %v", err, ErrUnregisteredSerializer)
		}
		if _, err := f.Preimage(); !errors.Is(err, ErrUnregisteredSerializer) {
			t.Errorf("Preimage: err = %v, want %v", err, ErrUnregisteredSerializer)
		}
		if _, err := f.EventHash(); !errors.Is(err, ErrUnregisteredSerializer) {
			t.Errorf("EventHash: err = %v, want %v", err, ErrUnregisteredSerializer)
		}
		if _, err := f.Finalize(); !errors.Is(err, ErrUnregisteredSerializer) {
			t.Errorf("Finalize: err = %v, want %v", err, ErrUnregisteredSerializer)
		}
		if err := VerifyFormat(); !errors.Is(err, ErrUnregisteredSerializer) {
			t.Errorf("VerifyFormat: err = %v, want %v", err, ErrUnregisteredSerializer)
		}
	})
}

// withoutCurrentSpec runs fn with SerializerVersion unregistered, simulating a
// version bump that forgot to register the new tag.
func withoutCurrentSpec(t *testing.T, fn func()) {
	t.Helper()
	saved, ok := serializerRegistry[SerializerVersion]
	if !ok {
		t.Fatalf("SerializerVersion %q is not registered", SerializerVersion)
	}
	delete(serializerRegistry, SerializerVersion)
	defer func() { serializerRegistry[SerializerVersion] = saved }()
	fn()
}

// TestSER005FormatFingerprintIsFrozen is SER-005: the serializer's observable
// behaviour is pinned to a constant, so it cannot change under an unchanged
// version tag.
func TestSER005FormatFingerprintIsFrozen(t *testing.T) {
	fixture := string(readFixtureFile(t, "format-probe.hash"))

	got, err := FormatFingerprint()
	if err != nil {
		t.Fatalf("FormatFingerprint: %v", err)
	}
	if got != fixture {
		t.Errorf("the serializer no longer emits the frozen format:\n got  %s\n want %s\n"+
			"This is a protected surface. Revert the serializer; do not update the fixture.",
			got, fixture)
	}

	spec, err := CurrentFormat()
	if err != nil {
		t.Fatalf("CurrentFormat: %v", err)
	}
	if spec.Fingerprint != fixture {
		t.Errorf("registry fingerprint = %s, fixture = %s", spec.Fingerprint, fixture)
	}
	if verr := VerifyFormat(); verr != nil {
		t.Errorf("VerifyFormat: %v", verr)
	}

	// The probe's canonical bytes are frozen too, so a diff shows what moved
	// rather than only that something did.
	probe, err := Canonicalize(formatProbe())
	if err != nil {
		t.Fatalf("Canonicalize(probe): %v", err)
	}
	if want := readFixtureFile(t, "format-probe.canonical.json"); !bytes.Equal(probe, want) {
		t.Errorf("format probe bytes differ\n got  %s\n want %s", probe, want)
	}
}

// TestSER005FormatDriftIsDetected is SER-005: the fingerprint check has to
// fail when the serializer's output moves, not merely exist.
func TestSER005FormatDriftIsDetected(t *testing.T) {
	spec, err := CurrentFormat()
	if err != nil {
		t.Fatalf("CurrentFormat: %v", err)
	}

	drifted := spec
	drifted.Fingerprint = HashPrefix + strings.Repeat("0", 64)
	if err := verifyFormatAgainst(drifted); !errors.Is(err, ErrFormatDrift) {
		t.Errorf("drifted fingerprint: err = %v, want %v", err, ErrFormatDrift)
	}

	// The genuine spec still passes, so the check is not simply always red.
	if err := verifyFormatAgainst(spec); err != nil {
		t.Errorf("genuine spec: %v", err)
	}
}
