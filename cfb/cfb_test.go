package cfb_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/nlink-jp/mailparse/cfb"
	"github.com/nlink-jp/mailparse/internal/cfbtest"
)

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i*7)
	}
	return b
}

func sample() []*cfbtest.Node {
	return []*cfbtest.Node{
		cfbtest.Stream("small", pattern(100, 1)),
		cfbtest.Stream("big", pattern(10000, 2)),
		cfbtest.Stream("empty", nil),
		cfbtest.Dir("Store",
			cfbtest.Stream("inner", pattern(4095, 3)),
			cfbtest.Stream("exact", pattern(4096, 4)),
			cfbtest.Dir("deeper", cfbtest.Stream("leaf", []byte("leaf"))),
		),
		cfbtest.Stream("名前", []byte("unicode")),
	}
}

func readAll(t *testing.T, f *cfb.File, e *cfb.Entry) []byte {
	t.Helper()
	b, err := f.ReadStream(e)
	if err != nil {
		t.Fatalf("ReadStream(%s): %v", e.Name, err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	for _, v := range []int{3, 4} {
		b, _ := cfbtest.Build(v, sample()...)
		f, err := cfb.OpenBytes(b, cfb.Limits{})
		if err != nil {
			t.Fatalf("v%d: %v", v, err)
		}
		if f.Version != v || len(f.Issues) != 0 {
			t.Fatalf("v%d: version %d, issues %v", v, f.Version, f.Issues)
		}
		if f.Root.Type != cfb.TypeRoot || f.Root.Name != "Root Entry" {
			t.Fatalf("root %+v", f.Root)
		}
		var names []string
		for _, c := range f.Root.Children {
			names = append(names, c.Name)
		}
		// CFB order: shorter names first, then uppercased.
		if got := strings.Join(names, ","); got != "名前,big,empty,small,Store" {
			t.Fatalf("v%d: children %s", v, got)
		}
		want := map[string][]byte{"small": pattern(100, 1), "big": pattern(10000, 2), "empty": {}, "名前": []byte("unicode")}
		for name, data := range want {
			if got := readAll(t, f, f.Root.Child(name)); !bytes.Equal(got, data) {
				t.Fatalf("v%d %s: %d bytes differ", v, name, len(got))
			}
		}
		st := f.Root.Child("store") // case-insensitive
		if st == nil || st.Type != cfb.TypeStorage {
			t.Fatalf("store %+v", st)
		}
		if got := readAll(t, f, st.Child("inner")); !bytes.Equal(got, pattern(4095, 3)) {
			t.Fatal("inner (mini, 4095) differs")
		}
		if got := readAll(t, f, st.Child("exact")); !bytes.Equal(got, pattern(4096, 4)) {
			t.Fatal("exact (regular, 4096) differs")
		}
		if got := readAll(t, f, st.Child("deeper").Child("leaf")); string(got) != "leaf" {
			t.Fatalf("leaf %q", got)
		}
		if len(f.Entries) != 10 {
			t.Fatalf("entries %d", len(f.Entries))
		}
		if _, err := f.ReadStream(st); !errors.Is(err, cfb.ErrNotStream) {
			t.Fatalf("storage read: %v", err)
		}
	}
}

func TestOpenReader(t *testing.T) {
	b, _ := cfbtest.Build(3, sample()...)
	if _, err := cfb.Open(bytes.NewReader(b), cfb.Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cfb.Open(bytes.NewReader(b), cfb.Limits{MaxSize: int64(len(b) - 1)}); !errors.Is(err, cfb.ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestDIFAT(t *testing.T) {
	// More than 109 FAT sectors (109 * 128 * 512 bytes) needs DIFAT sectors.
	data := pattern(7_300_000, 5)
	b, lay := cfbtest.Build(3, cfbtest.Stream("huge", data))
	if len(lay.FATSectors) <= 109 {
		t.Fatalf("only %d FAT sectors", len(lay.FATSectors))
	}
	f, err := cfb.OpenBytes(b, cfb.Limits{})
	if err != nil || len(f.Issues) != 0 {
		t.Fatalf("%v %v", err, f.Issues)
	}
	if got := readAll(t, f, f.Root.Child("huge")); !bytes.Equal(got, data) {
		t.Fatal("huge differs")
	}
}

func TestRefused(t *testing.T) {
	good, _ := cfbtest.Build(3, sample()...)
	mutate := func(off int, v ...byte) []byte {
		b := bytes.Clone(good)
		copy(b[off:], v)
		return b
	}
	cases := []struct {
		name string
		b    []byte
		want error
	}{
		{"empty", nil, cfb.ErrNotCFB},
		{"text", []byte(strings.Repeat("From: a@example.com\r\n", 40)), cfb.ErrNotCFB},
		{"short", good[:300], cfb.ErrNotCFB},
		{"header only", good[:512], cfb.ErrCorrupt},
		{"byte order", mutate(28, 0xFF, 0xFF), cfb.ErrCorrupt},
		{"sector shift", mutate(30, 10, 0), cfb.ErrCorrupt},
		{"mini shift", mutate(32, 7, 0), cfb.ErrCorrupt},
		{"directory out of range", mutate(48, 0x00, 0x10, 0, 0), cfb.ErrCorrupt},
	}
	for _, c := range cases {
		if _, err := cfb.OpenBytes(c.b, cfb.Limits{}); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func put32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

func hasIssue(f *cfb.File, code string) bool {
	for _, i := range f.Issues {
		if i.Code == code {
			return true
		}
	}
	return false
}

func TestDamagedChains(t *testing.T) {
	data := pattern(10000, 2) // 20 sectors of 512
	t.Run("fat loop", func(t *testing.T) {
		b, lay := cfbtest.Build(3, cfbtest.Stream("big", data))
		s := lay.Starts["/big"]
		put32(b, lay.FATOffset(s+3), s) // the 4th sector links back to the first
		f, err := cfb.OpenBytes(b, cfb.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := f.ReadStream(f.Root.Child("big"))
		if !errors.Is(err, cfb.ErrTruncated) || !strings.Contains(err.Error(), "loops") {
			t.Fatalf("err %v", err)
		}
		if !bytes.Equal(got, data[:4*512]) {
			t.Fatalf("kept %d bytes", len(got))
		}
	})
	t.Run("sector out of range", func(t *testing.T) {
		b, lay := cfbtest.Build(3, cfbtest.Stream("big", data))
		s := lay.Starts["/big"]
		put32(b, lay.FATOffset(s+1), 0x00FFFFFF)
		f, _ := cfb.OpenBytes(b, cfb.Limits{})
		got, err := f.ReadStream(f.Root.Child("big"))
		if !errors.Is(err, cfb.ErrTruncated) || len(got) != 2*512 {
			t.Fatalf("%v, %d bytes", err, len(got))
		}
	})
	t.Run("chain ends early", func(t *testing.T) {
		b, lay := cfbtest.Build(3, cfbtest.Stream("big", data))
		s := lay.Starts["/big"]
		put32(b, lay.FATOffset(s+4), 0xFFFFFFFE)
		f, _ := cfb.OpenBytes(b, cfb.Limits{})
		got, err := f.ReadStream(f.Root.Child("big"))
		if !errors.Is(err, cfb.ErrTruncated) || len(got) != 5*512 {
			t.Fatalf("%v, %d bytes", err, len(got))
		}
	})
	t.Run("huge declared size", func(t *testing.T) {
		b, lay := cfbtest.Build(4, cfbtest.Stream("big", data))
		binary.LittleEndian.PutUint64(b[lay.EntryOffset(lay.IDs["/big"])+120:], 1<<40)
		f, _ := cfb.OpenBytes(b, cfb.Limits{})
		e := f.Root.Child("big")
		got, err := f.ReadStream(e)
		if !errors.Is(err, cfb.ErrTruncated) || !bytes.Equal(got[:len(data)], data) {
			t.Fatalf("%v, %d bytes", err, len(got))
		}
	})
	t.Run("v3 high size bits ignored", func(t *testing.T) {
		b, lay := cfbtest.Build(3, cfbtest.Stream("big", data))
		put32(b, lay.EntryOffset(lay.IDs["/big"])+124, 0xDEADBEEF)
		f, _ := cfb.OpenBytes(b, cfb.Limits{})
		if got := readAll(t, f, f.Root.Child("big")); !bytes.Equal(got, data) {
			t.Fatal("differs")
		}
	})
	t.Run("mini loop", func(t *testing.T) {
		small := pattern(300, 9) // 5 mini sectors
		b, lay := cfbtest.Build(3, cfbtest.Stream("small", small))
		f, _ := cfb.OpenBytes(b, cfb.Limits{})
		_ = f
		// The mini FAT is the sector after the directory in Build's layout.
		mfat := lay.Offset(lay.DirStart + 1)
		put32(b, mfat+4*2, 0) // mini sector 2 links back to 0
		f, _ = cfb.OpenBytes(b, cfb.Limits{})
		got, err := f.ReadStream(f.Root.Child("small"))
		if !errors.Is(err, cfb.ErrTruncated) || !bytes.Equal(got, small[:3*64]) {
			t.Fatalf("%v, %d bytes", err, len(got))
		}
	})
	t.Run("fat sector out of range", func(t *testing.T) {
		b, _ := cfbtest.Build(3, cfbtest.Stream("big", data))
		put32(b, 44, 2)         // two FAT sectors declared
		put32(b, 80, 0x0FFFFFF) // the second does not exist
		f, err := cfb.OpenBytes(b, cfb.Limits{})
		if err != nil || !hasIssue(f, cfb.IssueFAT) {
			t.Fatalf("%v %v", err, f.Issues)
		}
		if got := readAll(t, f, f.Root.Child("big")); !bytes.Equal(got, data) {
			t.Fatal("differs")
		}
	})
	t.Run("difat loop", func(t *testing.T) {
		b, lay := cfbtest.Build(3, cfbtest.Stream("huge", pattern(7_300_000, 5)))
		difat := lay.FATSectors[len(lay.FATSectors)-1] + 1 // Build puts DIFAT sectors after the FAT
		put32(b, lay.Offset(difat)+508, difat)             // the only DIFAT sector names itself as next
		put32(b, 44, uint32(len(lay.FATSectors)+200))      // and more FAT sectors are declared than exist
		put32(b, 72, 5)
		f, err := cfb.OpenBytes(b, cfb.Limits{})
		if err != nil || !hasIssue(f, cfb.IssueFAT) {
			t.Fatalf("%v %v", err, f.Issues)
		}
	})
}

func TestDamagedTree(t *testing.T) {
	nodes := func() []*cfbtest.Node {
		return []*cfbtest.Node{
			cfbtest.Stream("a", []byte("A")),
			cfbtest.Stream("b", []byte("B")),
			cfbtest.Dir("s", cfbtest.Stream("c", []byte("C"))),
		}
	}
	t.Run("sibling loop", func(t *testing.T) {
		b, lay := cfbtest.Build(3, nodes()...)
		put32(b, lay.EntryOffset(lay.IDs["/b"])+72, uint32(lay.IDs["/a"])) // b's right sibling is a again
		f, err := cfb.OpenBytes(b, cfb.Limits{})
		if err != nil || !hasIssue(f, cfb.IssueDirectory) {
			t.Fatalf("%v %v", err, f.Issues)
		}
		if f.Root.Child("a") == nil || f.Root.Child("b") == nil {
			t.Fatal("lost entries before the loop")
		}
	})
	t.Run("child points to ancestor", func(t *testing.T) {
		b, lay := cfbtest.Build(3, nodes()...)
		put32(b, lay.EntryOffset(lay.IDs["/s/c"])+76, 0) // a stream's child is ignored
		put32(b, lay.EntryOffset(lay.IDs["/s"])+76, 0)   // the storage's child is the root
		f, err := cfb.OpenBytes(b, cfb.Limits{})
		if err != nil || !hasIssue(f, cfb.IssueDirectory) || len(f.Root.Child("s").Children) != 0 {
			t.Fatalf("%v %v", err, f.Issues)
		}
	})
	t.Run("self loop on left", func(t *testing.T) {
		b, lay := cfbtest.Build(3, nodes()...)
		id := lay.IDs["/a"]
		put32(b, lay.EntryOffset(id)+68, uint32(id))
		f, err := cfb.OpenBytes(b, cfb.Limits{})
		if err != nil || !hasIssue(f, cfb.IssueDirectory) {
			t.Fatalf("%v %v", err, f.Issues)
		}
	})
	t.Run("unallocated and out of range", func(t *testing.T) {
		b, lay := cfbtest.Build(3, nodes()...)
		put32(b, lay.EntryOffset(lay.IDs["/s"])+72, 7)     // an unused entry in the last directory sector
		put32(b, lay.EntryOffset(lay.IDs["/s/c"])+72, 999) // beyond the directory
		f, err := cfb.OpenBytes(b, cfb.Limits{})
		if err != nil || len(f.Issues) != 2 {
			t.Fatalf("%v %v", err, f.Issues)
		}
	})
	t.Run("root not a storage", func(t *testing.T) {
		b, lay := cfbtest.Build(3, nodes()...)
		b[lay.EntryOffset(0)+66] = 2
		if _, err := cfb.OpenBytes(b, cfb.Limits{}); !errors.Is(err, cfb.ErrCorrupt) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad name length", func(t *testing.T) {
		b, lay := cfbtest.Build(3, nodes()...)
		binary.LittleEndian.PutUint16(b[lay.EntryOffset(lay.IDs["/a"])+64:], 99)
		f, err := cfb.OpenBytes(b, cfb.Limits{})
		if err != nil || !hasIssue(f, cfb.IssueName) || f.Root.Child("a") == nil {
			t.Fatalf("%v %v", err, f.Issues)
		}
	})
	t.Run("entry limit", func(t *testing.T) {
		var many []*cfbtest.Node
		for i := range 40 {
			many = append(many, cfbtest.Stream(string(rune('A'+i%26))+strings.Repeat("x", i/26), []byte{byte(i)}))
		}
		b, _ := cfbtest.Build(3, many...)
		f, err := cfb.OpenBytes(b, cfb.Limits{MaxEntries: 10})
		if err != nil || !hasIssue(f, cfb.IssueEntries) || len(f.Entries) > 10 {
			t.Fatalf("%v %v %d", err, f.Issues, len(f.Entries))
		}
	})
}

func FuzzOpen(f *testing.F) {
	b3, _ := cfbtest.Build(3, sample()...)
	b4, _ := cfbtest.Build(4, cfbtest.Stream("x", pattern(5000, 1)))
	f.Add(b3)
	f.Add(b4)
	f.Fuzz(func(t *testing.T, b []byte) {
		file, err := cfb.OpenBytes(b, cfb.Limits{})
		if err != nil {
			return
		}
		for _, e := range file.Entries {
			if e.Type == cfb.TypeStream {
				got, _ := file.ReadStream(e)
				if int64(len(got)) > e.Size {
					t.Fatalf("read %d bytes from a stream declaring %d", len(got), e.Size)
				}
			}
		}
	})
}
