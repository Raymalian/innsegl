// SPDX-License-Identifier: Apache-2.0

package trustbackup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
)

// StatusFileName is the producer's last result, beside the bundles.
const StatusFileName = "status.json"

// ErrNoBundle is Latest's answer for a store that holds none.
var ErrNoBundle = errors.New("trust backup: no bundle is kept")

// nameLayout is the time in a bundle's name, UTC to the second.
const nameLayout = "20060102T150405Z"

var bundleName = regexp.MustCompile(`^trust-backup-([0-9]{8}T[0-9]{6}Z)\.tar\.age$`)

// Store is a directory of bundles, each with a sha256 file beside it, newest
// kept. The core writes its own bundles into one; the operator's machine
// keeps the copies it fetched in another. Only ciphertext is ever in it.
type Store struct {
	Dir string
	// Keep is how many bundles to keep; older ones are removed after each
	// new one. Zero or less keeps one.
	Keep int
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Owner, when set, is given every file written, and the directory's
	// group: the core writes as root, to read every key volume, and serves
	// as uid 1000.
	Owner *Owner
}

// Owner is a uid and gid.
type Owner struct{ UID, GID int }

// ParseOwner reads "UID:GID".
func ParseOwner(s string) (*Owner, error) {
	u, g, ok := strings.Cut(s, ":")
	uid, uerr := strconv.Atoi(u)
	gid, gerr := strconv.Atoi(g)
	if !ok || uerr != nil || gerr != nil || uid < 0 || gid < 0 {
		return nil, fmt.Errorf("trust backup: owner %q is not UID:GID", s)
	}
	return &Owner{UID: uid, GID: gid}, nil
}

// own gives path to the Store's owner, if it has one.
func (s *Store) own(path string) error {
	if s.Owner == nil {
		return nil
	}
	if err := os.Lchown(path, s.Owner.UID, s.Owner.GID); err != nil {
		return fmt.Errorf("trust backup: %w", err)
	}
	return nil
}

// Entry is one kept bundle. SHA256 is of the ciphertext, the outer checksum
// a copy is checked against before it is kept.
type Entry struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

// Status is the producer's last run. Error is empty when it succeeded.
type Status struct {
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	Latest      string    `json:"latest,omitempty"`
	Error       string    `json:"error,omitempty"`
}

func (s *Store) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// ensureDir makes the directory, 0700. With an Owner it stays the writer's
// and is given to the owner's group, 0750: a root writer with no
// DAC_OVERRIDE can still write into it on the next run, and the owner can
// list it.
func (s *Store) ensureDir() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("trust backup: %w", err)
	}
	if s.Owner == nil {
		return nil
	}
	if err := os.Lchown(s.Dir, -1, s.Owner.GID); err != nil {
		return fmt.Errorf("trust backup: %w", err)
	}
	if err := os.Chmod(s.Dir, 0o750); err != nil {
		return fmt.Errorf("trust backup: %w", err)
	}
	return nil
}

// Create writes a new bundle of sources, encrypted to recipients, then removes
// all but the newest Keep. A bundle appears only complete: it is written
// under a temporary name and renamed, and its checksum file is written last.
func (s *Store) Create(recipients []age.Recipient, sources []Source) (Entry, Manifest, error) {
	if len(recipients) == 0 {
		return Entry{}, Manifest{}, ErrNoRecipients
	}
	if err := s.ensureDir(); err != nil {
		return Entry{}, Manifest{}, err
	}
	now := s.now()
	name := "trust-backup-" + now.Format(nameLayout) + ".tar.age"
	if _, err := os.Lstat(filepath.Join(s.Dir, name)); err == nil {
		return Entry{}, Manifest{}, fmt.Errorf("trust backup: %s already exists", name)
	}
	var m Manifest
	e, err := s.write(name, func(w io.Writer) error {
		var werr error
		m, werr = WriteBundle(w, recipients, sources, now)
		return werr
	}, "")
	if err != nil {
		return Entry{}, Manifest{}, err
	}
	return e, m, s.prune()
}

// Put keeps a bundle fetched from elsewhere, if its ciphertext matches
// wantSHA. A bundle already kept under that name is left as it is.
func (s *Store) Put(name string, r io.Reader, wantSHA string) (Entry, error) {
	if !bundleName.MatchString(name) {
		return Entry{}, fmt.Errorf("trust backup: %q is not a bundle name", name)
	}
	if b, err := hex.DecodeString(wantSHA); err != nil || len(b) != sha256.Size {
		return Entry{}, fmt.Errorf("trust backup: %q is not a sha256", wantSHA)
	}
	if e, err := s.entry(name); err == nil && e.SHA256 == wantSHA {
		return e, nil
	}
	if err := s.ensureDir(); err != nil {
		return Entry{}, err
	}
	e, err := s.write(name, func(w io.Writer) error {
		_, cerr := io.Copy(w, r)
		return cerr
	}, wantSHA)
	if err != nil {
		return Entry{}, err
	}
	return e, s.prune()
}

// write streams a bundle to a temporary file, checks it against wantSHA when
// one is given, and publishes it with its checksum file.
func (s *Store) write(name string, fill func(io.Writer) error, wantSHA string) (Entry, error) {
	tmp, err := os.CreateTemp(s.Dir, ".tmp-")
	if err != nil {
		return Entry{}, fmt.Errorf("trust backup: %w", err)
	}
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	h := sha256.New()
	if err := fill(io.MultiWriter(tmp, h)); err != nil {
		return Entry{}, err
	}
	sha := hex.EncodeToString(h.Sum(nil))
	if wantSHA != "" && sha != wantSHA {
		return Entry{}, fmt.Errorf("trust backup: %s: sha256 %s, the core said %s", name, sha, wantSHA)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return Entry{}, fmt.Errorf("trust backup: %w", err)
	}
	if err := s.own(tmp.Name()); err != nil {
		return Entry{}, err
	}
	if err := tmp.Sync(); err != nil {
		return Entry{}, fmt.Errorf("trust backup: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return Entry{}, fmt.Errorf("trust backup: %w", err)
	}
	final := filepath.Join(s.Dir, name)
	if err := os.Rename(tmp.Name(), final); err != nil {
		return Entry{}, fmt.Errorf("trust backup: %w", err)
	}
	done = true
	sumFile := final + ".sha256"
	if err := s.writeAtomic(sumFile, []byte(sha+"  "+name+"\n")); err != nil {
		_ = os.Remove(final)
		return Entry{}, err
	}
	return s.entry(name)
}

func (s *Store) writeAtomic(path string, body []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("trust backup: %w", err)
	}
	if err := s.own(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("trust backup: %w", err)
	}
	return nil
}

// entry reads one kept bundle's size, checksum file and time.
func (s *Store) entry(name string) (Entry, error) {
	m := bundleName.FindStringSubmatch(name)
	if m == nil {
		return Entry{}, fmt.Errorf("trust backup: %q is not a bundle name", name)
	}
	created, err := time.Parse(nameLayout, m[1])
	if err != nil {
		return Entry{}, fmt.Errorf("trust backup: %q: %w", name, err)
	}
	fi, err := os.Stat(filepath.Join(s.Dir, name))
	if err != nil {
		return Entry{}, fmt.Errorf("trust backup: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(s.Dir, name+".sha256"))
	if err != nil {
		return Entry{}, fmt.Errorf("trust backup: %s has no checksum: %w", name, err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 2 || fields[1] != name {
		return Entry{}, fmt.Errorf("trust backup: %s: malformed checksum file", name)
	}
	if b, err := hex.DecodeString(fields[0]); err != nil || len(b) != sha256.Size {
		return Entry{}, fmt.Errorf("trust backup: %s: malformed checksum", name)
	}
	return Entry{Name: name, Size: fi.Size(), SHA256: fields[0], CreatedAt: created.UTC()}, nil
}

// List answers the complete bundles kept, newest first. A missing directory
// holds none. A bundle with no valid checksum file is not complete.
func (s *Store) List() ([]Entry, error) {
	des, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust backup: %w", err)
	}
	var out []Entry
	for _, d := range des {
		if !bundleName.MatchString(d.Name()) {
			continue
		}
		e, err := s.entry(d.Name())
		if err != nil {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// Latest answers the newest complete bundle.
func (s *Store) Latest() (Entry, error) {
	list, err := s.List()
	if err != nil {
		return Entry{}, err
	}
	if len(list) == 0 {
		return Entry{}, ErrNoBundle
	}
	return list[0], nil
}

// Open opens a complete bundle by name.
func (s *Store) Open(name string) (*os.File, Entry, error) {
	e, err := s.entry(name)
	if err != nil {
		return nil, Entry{}, err
	}
	f, err := os.Open(filepath.Join(s.Dir, name))
	if err != nil {
		return nil, Entry{}, fmt.Errorf("trust backup: %w", err)
	}
	return f, e, nil
}

// prune removes all but the newest Keep complete bundles, with their
// checksum files.
func (s *Store) prune() error {
	keep := max(s.Keep, 1)
	list, err := s.List()
	if err != nil {
		return err
	}
	for _, e := range list[min(keep, len(list)):] {
		for _, p := range []string{e.Name + ".sha256", e.Name} {
			if err := os.Remove(filepath.Join(s.Dir, p)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("trust backup: prune: %w", err)
			}
		}
	}
	return nil
}

// WriteStatus records the producer's last run.
func (s *Store) WriteStatus(st Status) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return s.writeAtomic(filepath.Join(s.Dir, StatusFileName), append(b, '\n'))
}

// ReadStatus reads the producer's last run.
func (s *Store) ReadStatus() (Status, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, StatusFileName))
	if err != nil {
		return Status{}, fmt.Errorf("trust backup: %w", err)
	}
	var st Status
	if err := json.Unmarshal(b, &st); err != nil {
		return Status{}, fmt.Errorf("trust backup: status: %w", err)
	}
	return st, nil
}
