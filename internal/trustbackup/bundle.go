// SPDX-License-Identifier: Apache-2.0

package trustbackup

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
)

// Format names the bundle layout. A reader refuses any other.
const Format = "innsegl-trust-backup/1"

// ManifestPath is the bundle's last tar entry.
const ManifestPath = "manifest.json"

// partSize bounds how much of a command's output is held in memory: the
// output goes into the bundle in parts of this size, so a large log database
// is streamed and never written to disk in the clear. A variable for tests.
var partSize = 8 << 20

// maxFileSize bounds one file read from a volume. Key material is small; a
// file this large in a key volume is a mistake to report, not to copy.
var maxFileSize int64 = 64 << 20

// Manifest is the bundle's table of contents. It is the last entry, inside
// the encryption, and it names every file with its size and sha256.
type Manifest struct {
	Format    string    `json:"format"`
	CreatedAt time.Time `json:"created_at"`
	Items     []Item    `json:"items"`
}

// Item is one backed-up thing: a volume, a file, a database export, a value.
type Item struct {
	Name  string `json:"name"`
	Files []File `json:"files"`
}

// File is one file of an item. Parts is set when the file was streamed in
// more than one tar entry ("<path>.part-000001", …); joined in order they are
// the file.
type File struct {
	Path   string      `json:"path"`
	Mode   fs.FileMode `json:"mode"`
	Size   int64       `json:"size"`
	SHA256 string      `json:"sha256"`
	Parts  int         `json:"parts,omitempty"`
}

// Files is how many files the manifest names.
func (m Manifest) Files() int {
	n := 0
	for _, it := range m.Items {
		n += len(it.Files)
	}
	return n
}

// Bytes is the plaintext size of every file the manifest names.
func (m Manifest) Bytes() int64 {
	var n int64
	for _, it := range m.Items {
		for _, f := range it.Files {
			n += f.Size
		}
	}
	return n
}

// Source is one item to back up.
type Source struct {
	name string
	// exactly one of these
	path    string
	produce func(io.Writer) error
	value   []byte
	// file is the file name for a stream or a value.
	file string
	kind int
}

const (
	kindPath = iota + 1
	kindStream
	kindValue
)

// PathSource backs up a file, or a directory with every regular file under
// it. A symlink, socket or device in it is refused: a key volume holds files.
func PathSource(name, p string) Source { return Source{name: name, path: p, kind: kindPath} }

// StreamSource backs up what produce writes as one file. It is streamed into
// the bundle in parts, never held whole and never written to disk; an error
// from produce fails the bundle.
func StreamSource(name, file string, produce func(io.Writer) error) Source {
	return Source{name: name, file: file, produce: produce, kind: kindStream}
}

// ValueSource backs up a value held in configuration, such as a key's
// password, as one file.
func ValueSource(name, file string, value []byte) Source {
	return Source{name: name, file: file, value: value, kind: kindValue}
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// WriteBundle writes one encrypted bundle of the sources to w. Plaintext
// exists only in memory, a file or one part at a time; what reaches w is
// ciphertext.
func WriteBundle(w io.Writer, recipients []age.Recipient, sources []Source, now time.Time) (Manifest, error) {
	if len(recipients) == 0 {
		return Manifest{}, ErrNoRecipients
	}
	if len(sources) == 0 {
		return Manifest{}, errors.New("trust backup: nothing to back up")
	}
	seen := map[string]bool{}
	for _, s := range sources {
		if !namePattern.MatchString(s.name) || seen[s.name] {
			return Manifest{}, fmt.Errorf("trust backup: item name %q is malformed or repeated", s.name)
		}
		seen[s.name] = true
		if s.kind != kindPath && !namePattern.MatchString(s.file) {
			return Manifest{}, fmt.Errorf("trust backup: %s: file name %q is malformed", s.name, s.file)
		}
	}
	enc, err := age.Encrypt(w, recipients...)
	if err != nil {
		return Manifest{}, fmt.Errorf("trust backup: encrypt: %w", err)
	}
	m, err := writeTar(enc, sources, now)
	if err != nil {
		return Manifest{}, err
	}
	if err := enc.Close(); err != nil {
		return Manifest{}, fmt.Errorf("trust backup: %w", err)
	}
	return m, nil
}

// writeTar writes the plaintext tar stream: every source's files, then the
// manifest. w is the encryptor.
func writeTar(w io.Writer, sources []Source, now time.Time) (Manifest, error) {
	tw := tar.NewWriter(w)
	m := Manifest{Format: Format, CreatedAt: now.UTC()}
	for _, s := range sources {
		it, err := writeSource(tw, s, now)
		if err != nil {
			return Manifest{}, fmt.Errorf("trust backup: %s: %w", s.name, err)
		}
		m.Items = append(m.Items, it)
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err := writeEntry(tw, ManifestPath, 0o600, body, now); err != nil {
		return Manifest{}, fmt.Errorf("trust backup: manifest: %w", err)
	}
	if err := tw.Close(); err != nil {
		return Manifest{}, fmt.Errorf("trust backup: %w", err)
	}
	return m, nil
}

func writeEntry(tw *tar.Writer, name string, mode fs.FileMode, body []byte, now time.Time) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: int64(mode.Perm()), Size: int64(len(body)),
		Typeflag: tar.TypeReg, ModTime: now.UTC(), Format: tar.FormatPAX}); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

func writeSource(tw *tar.Writer, s Source, now time.Time) (Item, error) {
	it := Item{Name: s.name}
	switch s.kind {
	case kindValue:
		if len(s.value) == 0 {
			return it, errors.New("the value is empty")
		}
		f := File{Path: s.file, Mode: 0o600, Size: int64(len(s.value)), SHA256: hexSum(s.value)}
		if err := writeEntry(tw, s.name+"/"+s.file, f.Mode, s.value, now); err != nil {
			return it, err
		}
		it.Files = []File{f}
		return it, nil
	case kindStream:
		f, err := writeStream(tw, s, now)
		if err != nil {
			return it, err
		}
		it.Files = []File{f}
		return it, nil
	}
	root, files, err := listFiles(s.path)
	if err != nil {
		return it, err
	}
	for _, rel := range files {
		f, err := writeTarFile(tw, s.name, rel, filepath.Join(root, filepath.FromSlash(rel)), now)
		if err != nil {
			return it, err
		}
		it.Files = append(it.Files, f)
	}
	return it, nil
}

// listFiles answers a root and the slash-separated paths under it of the
// regular files at p: p's own base name when p is a file, every file under it
// when p is a directory.
func listFiles(p string) (string, []string, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return "", nil, err
	}
	if fi.Mode().IsRegular() {
		return filepath.Dir(p), []string{filepath.Base(p)}, nil
	}
	if !fi.IsDir() {
		return "", nil, fmt.Errorf("%s is not a file or a directory", p)
	}
	var out []string
	err = filepath.WalkDir(p, func(q string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", q)
		}
		rel, rerr := filepath.Rel(p, q)
		if rerr != nil {
			return rerr
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	if len(out) == 0 {
		return "", nil, fmt.Errorf("%s holds no files", p)
	}
	sort.Strings(out)
	return p, out, nil
}

func writeTarFile(tw *tar.Writer, item, rel, full string, now time.Time) (File, error) {
	fh, err := os.Open(full)
	if err != nil {
		return File{}, err
	}
	defer func() { _ = fh.Close() }()
	fi, err := fh.Stat()
	if err != nil {
		return File{}, err
	}
	body, err := io.ReadAll(io.LimitReader(fh, maxFileSize+1))
	if err != nil {
		return File{}, err
	}
	if int64(len(body)) > maxFileSize {
		return File{}, fmt.Errorf("%s is larger than %d bytes", full, maxFileSize)
	}
	f := File{Path: rel, Mode: fi.Mode().Perm(), Size: int64(len(body)), SHA256: hexSum(body)}
	return f, writeEntry(tw, item+"/"+rel, f.Mode, body, now)
}

// partWriter cuts a stream into tar entries of partSize, hashing as it goes.
type partWriter struct {
	tw   *tar.Writer
	base string
	now  time.Time
	buf  []byte
	h    hash.Hash
	f    File
}

func (p *partWriter) Write(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		k := min(len(b), partSize-len(p.buf))
		p.buf = append(p.buf, b[:k]...)
		b, n = b[k:], n+k
		if len(p.buf) == partSize {
			if err := p.flush(); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

func (p *partWriter) flush() error {
	if len(p.buf) == 0 {
		return nil
	}
	p.f.Parts++
	p.f.Size += int64(len(p.buf))
	_, _ = p.h.Write(p.buf)
	err := writeEntry(p.tw, p.base+partSuffix(p.f.Parts), p.f.Mode, p.buf, p.now)
	p.buf = p.buf[:0]
	return err
}

func writeStream(tw *tar.Writer, s Source, now time.Time) (File, error) {
	if s.produce == nil {
		return File{}, errors.New("nothing produces this item")
	}
	p := &partWriter{tw: tw, base: s.name + "/" + s.file, now: now, buf: make([]byte, 0, partSize),
		h: sha256.New(), f: File{Path: s.file, Mode: 0o600}}
	if err := s.produce(p); err != nil {
		return File{}, err
	}
	if err := p.flush(); err != nil {
		return File{}, err
	}
	if p.f.Parts == 0 {
		return File{}, errors.New("it produced nothing")
	}
	p.f.SHA256 = hex.EncodeToString(p.h.Sum(nil))
	return p.f, nil
}

func partSuffix(n int) string { return fmt.Sprintf(".part-%06d", n) }

var partPattern = regexp.MustCompile(`^(.+)\.part-([0-9]{6})$`)

func hexSum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ReadBundle decrypts a bundle and checks every file against the manifest:
// each one present, with its size and sha256, and nothing the manifest does
// not name. With extractDir set it also writes each file under
// extractDir/<item>/<path>, mode 0600; the caller removes that directory if
// ReadBundle fails. With extractDir empty nothing is written anywhere.
func ReadBundle(r io.Reader, identities []age.Identity, extractDir string) (Manifest, error) {
	var root *os.Root
	if extractDir != "" {
		// Every file is opened through the root, which refuses a path that
		// leaves it: entryName refuses escapes too, and this is the second
		// lock on the same door.
		var rerr error
		if root, rerr = os.OpenRoot(extractDir); rerr != nil {
			return Manifest{}, fmt.Errorf("trust backup: extract: %w", rerr)
		}
		defer func() { _ = root.Close() }()
	}
	dec, err := age.Decrypt(r, identities...)
	if err != nil {
		return Manifest{}, fmt.Errorf("trust backup: decrypt: %w", err)
	}
	tr := tar.NewReader(dec)
	type got struct {
		h     hash.Hash
		size  int64
		parts int
	}
	files := map[string]*got{}
	var manifest *Manifest
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("trust backup: read: %w", err)
		}
		if manifest != nil {
			return Manifest{}, fmt.Errorf("trust backup: %q follows the manifest", hdr.Name)
		}
		if hdr.Name == ManifestPath {
			var m Manifest
			if derr := json.NewDecoder(io.LimitReader(tr, 16<<20)).Decode(&m); derr != nil {
				return Manifest{}, fmt.Errorf("trust backup: manifest: %w", derr)
			}
			if m.Format != Format {
				return Manifest{}, fmt.Errorf("trust backup: format %q, want %q", m.Format, Format)
			}
			manifest = &m
			continue
		}
		name, part, err := entryName(hdr)
		if err != nil {
			return Manifest{}, err
		}
		g, existed := files[name]
		if !existed {
			g = &got{h: sha256.New()}
			files[name] = g
		}
		if (part == 0 && existed) || (part > 0 && (part != g.parts+1 || existed && g.parts == 0)) {
			return Manifest{}, fmt.Errorf("trust backup: %q is out of order or repeated", hdr.Name)
		}
		g.parts = part
		var dst io.Writer = g.h
		var out *os.File
		if root != nil {
			out, err = openExtract(root, name, part <= 1)
			if err != nil {
				return Manifest{}, err
			}
			dst = io.MultiWriter(g.h, out)
		}
		n, err := io.Copy(dst, tr) //nolint:gosec // G110: the size is checked against the manifest
		if out != nil {
			if cerr := out.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("trust backup: %s: %w", name, err)
		}
		g.size += n
	}
	if manifest == nil {
		return Manifest{}, errors.New("trust backup: the bundle has no manifest; it is incomplete")
	}
	want := map[string]File{}
	for _, it := range manifest.Items {
		for _, f := range it.Files {
			want[it.Name+"/"+f.Path] = f
		}
	}
	for name, g := range files {
		f, ok := want[name]
		if !ok {
			return Manifest{}, fmt.Errorf("trust backup: %s is not in the manifest", name)
		}
		if g.size != f.Size || hex.EncodeToString(g.h.Sum(nil)) != f.SHA256 || g.parts != f.Parts {
			return Manifest{}, fmt.Errorf("trust backup: %s does not match its checksum in the manifest", name)
		}
	}
	for name := range want {
		if files[name] == nil {
			return Manifest{}, fmt.Errorf("trust backup: %s is in the manifest and not in the bundle", name)
		}
	}
	return *manifest, nil
}

// entryName answers the file a tar entry belongs to, and its part number (0
// for a whole file). It refuses anything but a regular file at
// "<item>/<path>" with no escaping component.
func entryName(hdr *tar.Header) (string, int, error) {
	bad := func() (string, int, error) {
		return "", 0, fmt.Errorf("trust backup: refusing entry %q", hdr.Name)
	}
	if hdr.Typeflag != tar.TypeReg {
		return bad()
	}
	clean := path.Clean(hdr.Name)
	if clean != hdr.Name || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || !strings.Contains(clean, "/") {
		return bad()
	}
	if m := partPattern.FindStringSubmatch(clean); m != nil {
		n, err := strconv.Atoi(m[2])
		if err != nil || n == 0 {
			return bad()
		}
		return m[1], n, nil
	}
	return clean, 0, nil
}

func openExtract(root *os.Root, name string, first bool) (*os.File, error) {
	p := filepath.FromSlash(name)
	if err := root.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, fmt.Errorf("trust backup: extract: %w", err)
	}
	flag := os.O_WRONLY | os.O_CREATE | os.O_APPEND
	if first {
		flag |= os.O_EXCL
	}
	f, err := root.OpenFile(p, flag, 0o600)
	if err != nil {
		return nil, fmt.Errorf("trust backup: extract: %w", err)
	}
	return f, nil
}
