// Package cfb reads Compound File Binary files (MS-CFB, "OLE2" structured
// storage): the container of Outlook .msg files and of legacy Office documents
// (.doc, .xls, .ppt and their macro storages).
//
// It is written from the published specification for hostile input. Sector
// chains that loop, directory trees that loop or share entries, sector numbers
// past the end of the file and stream sizes larger than the file are detected
// and cut, never followed without bound. Problems that leave the rest of the
// file readable are reported as Issues on the File instead of failing the whole
// open, and a stream whose chain ends early is returned as far as it goes, with
// ErrTruncated.
//
// Opening walks every chain once, so its work is proportional to the input
// size. Each ReadStream is proportional to the stream it returns, but streams
// whose chains share sectors (MS-CFB forbids it; Open reports it as an Issue)
// make reading every entry cost more than the file size: a consumer that reads
// everything from untrusted files should budget its reads, as mailparse does.
//
// Directory entries that are allocated but not linked into the tree — a way to
// hide a stream from tools that walk the tree — are listed in File.Unlinked.
//
// The whole file is held in memory (Limits.MaxSize bounds it). A File is not
// safe for concurrent use. The package only reads; it never writes a compound
// file.
package cfb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// Errors returned by Open and OpenBytes. Errors from Entry reads wrap
// ErrTruncated or ErrNotStream.
var (
	ErrNotCFB    = errors.New("cfb: not a compound file")
	ErrTooLarge  = errors.New("cfb: file larger than Limits.MaxSize")
	ErrCorrupt   = errors.New("cfb: compound file structure unreadable")
	ErrTruncated = errors.New("cfb: stream shorter than its declared size")
	ErrNotStream = errors.New("cfb: entry is not a stream")
)

// signature is the eight-byte header signature of every compound file.
var signature = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// Limits bounds what one Open reads. The zero value selects the defaults.
type Limits struct {
	MaxSize    int64 // bytes read from the input; default 64 MiB
	MaxEntries int   // directory entries read; default 4,096
}

const (
	defaultMaxSize    = 64 << 20
	defaultMaxEntries = 4096
)

func (l Limits) withDefaults() Limits {
	if l.MaxSize <= 0 {
		l.MaxSize = defaultMaxSize
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = defaultMaxEntries
	}
	return l
}

// Type is the object type of a directory entry.
type Type uint8

// Object types (MS-CFB 2.6.1).
const (
	TypeUnallocated Type = 0
	TypeStorage     Type = 1
	TypeStream      Type = 2
	TypeRoot        Type = 5
)

func (t Type) String() string {
	switch t {
	case TypeStorage:
		return "storage"
	case TypeStream:
		return "stream"
	case TypeRoot:
		return "root"
	}
	return "unallocated"
}

// Issue codes: something an open met in a structure and worked around.
const (
	IssueHeader    = "header"    // a header field held a value the specification does not allow; it was tolerated
	IssueFAT       = "fat"       // a FAT or DIFAT sector was out of range, looped or missing; chains through it end there
	IssueDirectory = "directory" // the directory chain or tree looped, pointed out of range or at an unused entry; that branch was cut
	IssueEntries   = "entries"   // more directory entries than Limits.MaxEntries; the rest were not read
	IssueName      = "name"      // a directory entry name had an invalid length, or two siblings share a name
	IssueUnlinked  = "unlinked"  // allocated directory entries are not linked into the tree; they are listed in File.Unlinked
	IssueChain     = "chain"     // a stream's chain loops, ends early, or shares sectors with another stream or the mini stream
)

// Issue is one structural problem an open worked around.
type Issue struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Entry is one storage or stream in the directory tree.
type Entry struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	Type     Type     `json:"type"`
	Size     int64    `json:"size"` // declared stream size (the mini stream size for the root)
	CLSID    [16]byte `json:"clsid"`
	Children []*Entry `json:"children,omitempty"` // in directory order; storages and the root only

	start uint32
}

// Child returns the direct child with the given name, compared without regard
// to case as MS-CFB 2.6.4 compares names, or nil.
func (e *Entry) Child(name string) *Entry {
	for _, c := range e.Children {
		if strings.EqualFold(c.Name, name) {
			return c
		}
	}
	return nil
}

// File is an opened compound file.
type File struct {
	Version int      // major version: 3 (512-byte sectors) or 4 (4,096-byte sectors)
	Root    *Entry   // the root storage
	Issues  []Issue  // structural problems worked around, in the order met
	Entries []*Entry // every entry reached from the root, by ID order of discovery
	// Unlinked holds allocated storage and stream entries that no tree links
	// to, in ID order; their Children are not filled. ReadStream reads them.
	Unlinked []*Entry

	b       []byte
	shift   uint
	ssz     int
	nsect   uint32 // sectors after the header that the file holds, counting a short last one
	fat     []uint32
	miniFAT []uint32
	mini    []byte
	seen    []uint64 // reusable cycle bitset over sector numbers

	issueCount map[string]int
}

// Special sector and stream numbers (MS-CFB 2.1, 2.6.1).
const (
	maxRegSect = 0xFFFFFFFA
	difSect    = 0xFFFFFFFC
	fatSect    = 0xFFFFFFFD
	endOfChain = 0xFFFFFFFE
	freeSect   = 0xFFFFFFFF
	noStream   = 0xFFFFFFFF

	miniCutoff = 4096
	miniSize   = 64
	entrySize  = 128
)

// Open reads a compound file from r, up to Limits.MaxSize.
func Open(r io.Reader, lim Limits) (*File, error) {
	lim = lim.withDefaults()
	b, err := io.ReadAll(io.LimitReader(r, lim.MaxSize+1))
	if err != nil {
		return nil, err
	}
	return OpenBytes(b, lim)
}

// OpenBytes reads a compound file held in b. The File keeps b; the caller must
// not change it while the File is in use.
func OpenBytes(b []byte, lim Limits) (*File, error) {
	lim = lim.withDefaults()
	if int64(len(b)) > lim.MaxSize {
		return nil, ErrTooLarge
	}
	if len(b) < 512 || !bytes.Equal(b[:8], signature) {
		return nil, ErrNotCFB
	}
	f := &File{b: b}
	if le16(b, 28) != 0xFFFE {
		return nil, fmt.Errorf("%w: byte order mark %#04x", ErrCorrupt, le16(b, 28))
	}
	major, shift := le16(b, 26), le16(b, 30)
	switch shift {
	case 9, 12:
	default:
		return nil, fmt.Errorf("%w: sector shift %d", ErrCorrupt, shift)
	}
	if ms := le16(b, 32); ms != 6 {
		return nil, fmt.Errorf("%w: mini sector shift %d", ErrCorrupt, ms)
	}
	f.Version = int(major)
	if (major != 3 && major != 4) || (major == 3) != (shift == 9) {
		f.issue(IssueHeader, "major version %d with sector shift %d", major, shift)
		f.Version = 3
		if shift == 12 {
			f.Version = 4
		}
	}
	if c := le32(b, 56); c != miniCutoff {
		f.issue(IssueHeader, "mini stream cutoff %d (4096 used)", c)
	}
	f.shift, f.ssz = uint(shift), 1<<shift
	if len(b) <= f.ssz {
		return nil, fmt.Errorf("%w: no sectors after the header", ErrCorrupt)
	}
	f.nsect = uint32((len(b) - f.ssz + f.ssz - 1) / f.ssz)
	f.seen = make([]uint64, (int(f.nsect)+63)/64)

	f.readFAT()
	dir, err := f.chainBytes(le32(b, 48), -1)
	if len(dir) < entrySize {
		return nil, fmt.Errorf("%w: directory unreadable: %v", ErrCorrupt, err)
	}
	if err != nil {
		f.issue(IssueDirectory, "directory chain: %v", err)
	}
	n := len(dir) / entrySize
	if n > lim.MaxEntries {
		n = lim.MaxEntries
		for i := n; i < len(dir)/entrySize; i++ {
			if dir[i*entrySize+66] != byte(TypeUnallocated) {
				f.issue(IssueEntries, "directory holds more than %d entries", lim.MaxEntries)
				break
			}
		}
	}
	if err := f.readTree(dir[:n*entrySize], n); err != nil {
		return nil, err
	}
	f.readMiniStream()
	f.claimChains()
	return f, nil
}

// maxIssuesPerCode bounds Issues: a hostile file can repeat one fault for
// every entry. Past it, one more Issue of the code says the rest were dropped.
const maxIssuesPerCode = 100

func (f *File) issue(code, format string, a ...any) {
	if f.issueCount == nil {
		f.issueCount = map[string]int{}
	}
	f.issueCount[code]++
	switch n := f.issueCount[code]; {
	case n <= maxIssuesPerCode:
		f.Issues = append(f.Issues, Issue{Code: code, Detail: fmt.Sprintf(format, a...)})
	case n == maxIssuesPerCode+1:
		f.Issues = append(f.Issues, Issue{Code: code, Detail: fmt.Sprintf("further %s issues after the first %d were not recorded", code, maxIssuesPerCode)})
	}
}

// sector returns the bytes of sector n, short if the file ends inside it, or
// nil when n is not a sector the file holds.
func (f *File) sector(n uint32) []byte {
	if n >= f.nsect {
		return nil
	}
	off := (int64(n) + 1) << f.shift
	end := min(off+int64(f.ssz), int64(len(f.b)))
	return f.b[off:end]
}

// readFAT assembles the FAT from the sectors the DIFAT names. A DIFAT position
// whose sector cannot be read keeps its place, filled with FREESECT, so the
// positions after it still index the right part of the FAT.
func (f *File) readFAT() {
	want := le32(f.b, 44)
	if want > f.nsect {
		f.issue(IssueFAT, "header declares %d FAT sectors; the file holds %d sectors", want, f.nsect)
		want = f.nsect
	}
	locs := make([]uint32, 0, min(want, 109))
	for i := 0; i < 109 && uint32(len(locs)) < want; i++ {
		locs = append(locs, le32(f.b, 76+4*i))
	}
	next, left := le32(f.b, 68), le32(f.b, 72)
	per := f.ssz/4 - 1
	f.resetSeen()
	for uint32(len(locs)) < want && next != endOfChain && next != freeSect {
		if left == 0 {
			f.issue(IssueFAT, "DIFAT chain longer than the declared %d sectors", le32(f.b, 72))
			break
		}
		left--
		s := f.sector(next)
		if len(s) < f.ssz {
			f.issue(IssueFAT, "DIFAT sector %d out of range", next)
			break
		}
		if f.mark(next) {
			f.issue(IssueFAT, "DIFAT chain loops at sector %d", next)
			break
		}
		for i := 0; i < per && uint32(len(locs)) < want; i++ {
			locs = append(locs, le32(s, 4*i))
		}
		next = le32(s, 4*per)
	}
	if uint32(len(locs)) < want {
		f.issue(IssueFAT, "found %d of %d declared FAT sectors", len(locs), want)
	}
	per = f.ssz / 4
	f.fat = make([]uint32, 0, len(locs)*per)
	for _, loc := range locs {
		s := f.sector(loc)
		if len(s) < f.ssz {
			f.issue(IssueFAT, "FAT sector %d out of range", loc)
			for range per {
				f.fat = append(f.fat, freeSect)
			}
			continue
		}
		for i := range per {
			f.fat = append(f.fat, le32(s, 4*i))
		}
	}
}

func (f *File) resetSeen() { clear(f.seen) }

// mark records sector n as visited and reports whether it already was.
func (f *File) mark(n uint32) bool {
	w, bit := n/64, uint64(1)<<(n%64)
	if int(w) >= len(f.seen) {
		return false
	}
	was := f.seen[w]&bit != 0
	f.seen[w] |= bit
	return was
}

// chainBytes concatenates the sectors of the FAT chain from start, up to want
// bytes (all of the chain when want < 0). The error says why the chain ended
// before want bytes, or before ENDOFCHAIN when want < 0.
func (f *File) chainBytes(start uint32, want int64) ([]byte, error) {
	limit := int64(f.nsect) * int64(f.ssz)
	if want >= 0 && want < limit {
		limit = want
	}
	// Grow as the chain is read: reserving the declared size would keep a
	// buffer as large as the file behind a stream that declares a huge size.
	out := make([]byte, 0, min(limit, int64(16*f.ssz)))
	f.resetSeen()
	s := start
	for int64(len(out)) < limit {
		switch {
		case s == endOfChain:
			if want < 0 {
				return out, nil
			}
			return out, fmt.Errorf("chain ends after %d bytes", len(out))
		case s > maxRegSect || s >= f.nsect:
			return out, fmt.Errorf("sector %#x out of range", s)
		case int(s) >= len(f.fat):
			return out, fmt.Errorf("sector %d has no FAT entry", s)
		case f.mark(s):
			return out, fmt.Errorf("chain loops at sector %d", s)
		}
		sec := f.sector(s)
		out = append(out, sec[:min(int64(len(sec)), limit-int64(len(out)))]...)
		if len(sec) < f.ssz && int64(len(out)) < limit {
			return out, fmt.Errorf("file ends inside sector %d", s)
		}
		s = f.fat[s]
	}
	if want < 0 && s != endOfChain {
		return out, fmt.Errorf("chain does not end within the file")
	}
	return out, nil
}

// readTree reads the directory entries and links the tree under the root,
// iteratively: each entry is attached at most once, so a loop or a shared
// entry is cut where it is met.
func (f *File) readTree(dir []byte, n int) error {
	raw := func(id int) []byte { return dir[id*entrySize : (id+1)*entrySize] }
	t := Type(raw(0)[66])
	if t != TypeRoot {
		if t != TypeStorage {
			return fmt.Errorf("%w: entry 0 is a %s, not the root", ErrCorrupt, t)
		}
		f.issue(IssueDirectory, "entry 0 has type storage, not root")
	}
	used := make([]bool, n)
	used[0] = true
	f.Root = f.entry(0, raw(0))
	f.Entries = append(f.Entries, f.Root)

	queue := []*Entry{f.Root}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		var stack []uint32
		names := map[string]bool{}
		cur := le32(raw(parent.ID), 76)
		for cur != noStream || len(stack) > 0 {
			for cur != noStream {
				id, ok := f.reachable(cur, n, used, raw)
				if !ok {
					break
				}
				used[id] = true
				stack = append(stack, cur)
				cur = le32(raw(id), 68)
			}
			if len(stack) == 0 {
				break
			}
			id := int(stack[len(stack)-1])
			stack = stack[:len(stack)-1]
			e := f.entry(id, raw(id))
			if k := strings.ToUpper(e.Name); names[k] {
				f.issue(IssueName, "%q holds two children named %q; Child returns the first", parent.Name, e.Name)
			} else {
				names[k] = true
			}
			parent.Children = append(parent.Children, e)
			f.Entries = append(f.Entries, e)
			if e.Type == TypeStorage {
				queue = append(queue, e)
			}
			cur = le32(raw(id), 72)
		}
	}
	for id := 1; id < n; id++ {
		if t := Type(raw(id)[66]); !used[id] && (t == TypeStorage || t == TypeStream) {
			f.Unlinked = append(f.Unlinked, f.entry(id, raw(id)))
		}
	}
	if len(f.Unlinked) > 0 {
		f.issue(IssueUnlinked, "%d allocated entries are not linked into the tree", len(f.Unlinked))
	}
	return nil
}

// readMiniStream loads the mini stream and the mini FAT, reporting damage to
// their chains.
func (f *File) readMiniStream() {
	var err error
	if f.Root.Size > 0 {
		f.mini, err = f.chainBytes(f.Root.start, f.Root.Size)
		if err != nil {
			f.issue(IssueChain, "mini stream: %v", err)
		}
	}
	if n := int64(le32(f.b, 64)); n > 0 {
		var mf []byte
		mf, err = f.chainBytes(le32(f.b, 60), n*int64(f.ssz))
		if err != nil {
			f.issue(IssueChain, "mini FAT: %v", err)
		}
		f.miniFAT = make([]uint32, len(mf)/4)
		for i := range f.miniFAT {
			f.miniFAT[i] = le32(mf, 4*i)
		}
	}
}

// claimChains walks every stream's chain once, recording which stream owns
// each sector, and reports chains that loop, end early or run into sectors
// another stream (or the mini stream) owns. Each sector is claimed at most
// once, so the walk is bounded by the file size however many entries there are.
func (f *File) claimChains() {
	const miniOwner = -1
	owner := make([]int32, f.nsect)
	nmini := (len(f.mini) + miniSize - 1) / miniSize
	miniOwners := make([]int32, nmini)
	if len(f.mini) > 0 {
		need := (int64(len(f.mini)) + int64(f.ssz) - 1) / int64(f.ssz)
		if why := chainWalk(f.Root.start, need, owner, miniOwner, f.fat); why != "" {
			f.issue(IssueChain, "mini stream: %s", why)
		}
	}
	streams := append(append([]*Entry(nil), f.Entries...), f.Unlinked...)
	for _, e := range streams {
		if e.Type != TypeStream || e.Size == 0 {
			continue
		}
		if e.Size < miniCutoff {
			need := (e.Size + miniSize - 1) / miniSize
			if why := chainWalk(e.start, need, miniOwners, int32(e.ID+1), f.miniFAT); why != "" {
				f.issue(IssueChain, "stream %q (mini): %s", e.Name, why)
			}
			continue
		}
		need := min((e.Size+int64(f.ssz)-1)/int64(f.ssz), int64(f.nsect))
		if why := chainWalk(e.start, need, owner, int32(e.ID+1), f.fat); why != "" {
			f.issue(IssueChain, "stream %q: %s", e.Name, why)
		}
	}
}

// chainWalk follows need links of a chain through next, claiming each sector
// in owner for id, and says why it stopped early ("" when it did not).
func chainWalk(start uint32, need int64, owner []int32, id int32, next []uint32) string {
	s := start
	for k := int64(0); k < need; k++ {
		switch {
		case s == endOfChain:
			return fmt.Sprintf("chain ends after %d of %d sectors", k, need)
		case int64(s) >= int64(len(owner)) || int64(s) >= int64(len(next)):
			return fmt.Sprintf("sector %#x out of range", s)
		case owner[s] == id:
			return fmt.Sprintf("chain loops at sector %d", s)
		case owner[s] != 0:
			if owner[s] < 0 {
				return fmt.Sprintf("sector %d belongs to the mini stream", s)
			}
			return fmt.Sprintf("sector %d is shared with entry %d", s, owner[s]-1)
		}
		owner[s] = id
		s = next[s]
	}
	return ""
}

// reachable checks a stream ID taken from a sibling or child field.
func (f *File) reachable(sid uint32, n int, used []bool, raw func(int) []byte) (int, bool) {
	switch {
	case sid > maxRegSect:
		f.issue(IssueDirectory, "stream ID %#x is reserved", sid)
		return 0, false
	case int64(sid) >= int64(n):
		f.issue(IssueDirectory, "stream ID %d beyond the %d entries read", sid, n)
		return 0, false
	case used[sid]:
		f.issue(IssueDirectory, "entry %d is linked more than once (loop or shared entry)", sid)
		return 0, false
	}
	switch Type(raw(int(sid))[66]) {
	case TypeStorage, TypeStream:
		return int(sid), true
	}
	f.issue(IssueDirectory, "entry %d is linked but has type %d", sid, raw(int(sid))[66])
	return 0, false
}

func (f *File) entry(id int, r []byte) *Entry {
	e := &Entry{ID: id, Type: Type(r[66]), start: le32(r, 116)}
	copy(e.CLSID[:], r[80:96])
	nl := int(le16(r, 64))
	if nl > 64 || nl%2 != 0 {
		f.issue(IssueName, "entry %d declares a name length of %d", id, nl)
		nl = 64
	}
	u := make([]uint16, 0, nl/2)
	for i := 0; i+1 < nl; i += 2 {
		c := binary.LittleEndian.Uint16(r[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	e.Name = string(utf16.Decode(u))
	size := binary.LittleEndian.Uint64(r[120:])
	if f.Version == 3 {
		size &= 0xFFFFFFFF // MS-CFB 2.6.1: older writers leave garbage in the high half
	}
	if size > 1<<62 {
		size = 1 << 62
	}
	e.Size = int64(size)
	return e
}

// ReadStream returns a copy of a stream's bytes. When the chain ends before
// the declared size, it returns what the chain holds and an error wrapping
// ErrTruncated.
func (f *File) ReadStream(e *Entry) ([]byte, error) {
	if e == nil || e.Type != TypeStream {
		return nil, ErrNotStream
	}
	if e.Size < miniCutoff {
		return f.readMini(e)
	}
	b, err := f.chainBytes(e.start, e.Size)
	if err != nil {
		return b, fmt.Errorf("%w: %s: %v", ErrTruncated, e.Name, err)
	}
	return b, nil
}

func (f *File) readMini(e *Entry) ([]byte, error) {
	if e.Size == 0 {
		return []byte{}, nil
	}
	nmini := uint32(len(f.mini) / miniSize)
	if len(f.mini)%miniSize != 0 {
		nmini++
	}
	out := make([]byte, 0, e.Size)
	seen := make(map[uint32]bool)
	s := e.start
	for int64(len(out)) < e.Size {
		var why string
		switch {
		case s == endOfChain:
			why = "chain ends early"
		case s >= nmini:
			why = fmt.Sprintf("mini sector %#x out of range", s)
		case int(s) >= len(f.miniFAT):
			why = fmt.Sprintf("mini sector %d has no mini FAT entry", s)
		case seen[s]:
			why = fmt.Sprintf("mini chain loops at %d", s)
		}
		if why != "" {
			return out, fmt.Errorf("%w: %s: %s after %d bytes", ErrTruncated, e.Name, why, len(out))
		}
		seen[s] = true
		off := int(s) * miniSize
		need := min(miniSize, int(e.Size)-len(out))
		if off+need > len(f.mini) {
			out = append(out, f.mini[off:]...)
			return out, fmt.Errorf("%w: %s: mini stream ends inside mini sector %d", ErrTruncated, e.Name, s)
		}
		out = append(out, f.mini[off:off+need]...)
		s = f.miniFAT[s]
	}
	return out, nil
}

func le16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
