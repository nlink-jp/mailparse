// Package cfbtest builds compound files (MS-CFB) for tests: a small writer that
// lays out a tree of storages and streams the way the specification describes,
// plus the sector map tests need to damage the result on purpose. It is used by
// tests only; the library itself never writes a compound file.
package cfbtest

import (
	"encoding/binary"
	"sort"
	"strings"
	"unicode/utf16"
)

// Node is a storage (Storage true, or with Children) or a stream (Data).
type Node struct {
	Name     string
	Data     []byte
	Storage  bool
	Children []*Node
}

// Stream returns a stream node.
func Stream(name string, data []byte) *Node { return &Node{Name: name, Data: data} }

// Dir returns a storage node.
func Dir(name string, children ...*Node) *Node {
	return &Node{Name: name, Storage: true, Children: children}
}

// Layout tells a test where Build put things, so it can damage them.
type Layout struct {
	SectorSize int
	FATSectors []uint32       // sector numbers of the FAT sectors, in DIFAT order
	DirStart   uint32         // first directory sector
	IDs        map[string]int // "/storage/stream" -> directory entry ID ("" is the root)
	Starts     map[string]uint32
}

// Offset returns the file offset of sector n.
func (l *Layout) Offset(n uint32) int { return (int(n) + 1) * l.SectorSize }

// EntryOffset returns the file offset of directory entry id, assuming the
// directory chain is contiguous (Build lays it out that way).
func (l *Layout) EntryOffset(id int) int { return l.Offset(l.DirStart) + id*128 }

// FATOffset returns the file offset of the FAT entry for sector n.
func (l *Layout) FATOffset(n uint32) int {
	per := uint32(l.SectorSize / 4)
	return l.Offset(l.FATSectors[n/per]) + int(n%per)*4
}

const (
	endOfChain = 0xFFFFFFFE
	freeSect   = 0xFFFFFFFF
	fatSect    = 0xFFFFFFFD
	difSect    = 0xFFFFFFFC
	noStream   = 0xFFFFFFFF
)

type flat struct {
	node            *Node
	path            string
	id              int
	child, right    uint32
	mini            bool
	start           uint32
	size            int
	sectors         int
	typ             byte
}

// Build lays out the children of the root storage as a compound file of the
// given major version (3 or 4). Streams under 4,096 bytes go to the mini stream.
// Sibling sets are written as all-black right-leaning chains in CFB order,
// which MS-CFB 2.6.4 allows.
func Build(version int, children ...*Node) ([]byte, *Layout) {
	ssz, shift := 512, 9
	if version == 4 {
		ssz, shift = 4096, 12
	}
	root := &flat{node: &Node{Name: "Root Entry", Storage: true, Children: children}, typ: 5, child: noStream, right: noStream}
	all := []*flat{root}
	queue := []*flat{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		kids := append([]*Node(nil), p.node.Children...)
		sort.SliceStable(kids, func(i, j int) bool { return less(kids[i].Name, kids[j].Name) })
		var prev *flat
		for _, k := range kids {
			e := &flat{node: k, path: p.path + "/" + k.Name, id: len(all), child: noStream, right: noStream, typ: 2}
			if k.Storage || len(k.Children) > 0 {
				e.typ = 1
				queue = append(queue, e)
			}
			all = append(all, e)
			if prev == nil {
				p.child = uint32(e.id)
			} else {
				prev.right = uint32(e.id)
			}
			prev = e
		}
	}

	var ministream []byte
	var miniFAT []uint32
	for _, e := range all {
		if e.typ != 2 {
			continue
		}
		e.size = len(e.node.Data)
		if e.size < 4096 {
			e.mini = true
			e.start = endOfChain
			if e.size == 0 {
				continue
			}
			first := uint32(len(ministream) / 64)
			e.start = first
			n := (e.size + 63) / 64
			for i := range n {
				next := uint32(endOfChain)
				if i < n-1 {
					next = first + uint32(i) + 1
				}
				miniFAT = append(miniFAT, next)
			}
			ministream = append(ministream, e.node.Data...)
			for len(ministream)%64 != 0 {
				ministream = append(ministream, 0)
			}
		} else {
			e.sectors = (e.size + ssz - 1) / ssz
		}
	}
	per := ssz / 4
	dirSectors := (len(all)*128 + ssz - 1) / ssz
	miniFATSectors := (len(miniFAT)*4 + ssz - 1) / ssz
	miniSectors := (len(ministream) + ssz - 1) / ssz
	other := dirSectors + miniFATSectors + miniSectors
	for _, e := range all {
		other += e.sectors
	}
	nfat, ndifat := 1, 0
	for {
		ndifat = 0
		if nfat > 109 {
			ndifat = (nfat - 109 + per - 2) / (per - 1)
		}
		if nfat*per >= other+nfat+ndifat {
			break
		}
		nfat++
	}

	fat := make([]uint32, nfat*per)
	for i := range fat {
		fat[i] = freeSect
	}
	next := uint32(0)
	alloc := func(n int, mark uint32) uint32 {
		first := next
		for i := range n {
			s := next + uint32(i)
			switch {
			case mark != 0:
				fat[s] = mark
			case i == n-1:
				fat[s] = endOfChain
			default:
				fat[s] = s + 1
			}
		}
		next += uint32(n)
		if n == 0 {
			return endOfChain
		}
		return first
	}
	fatStart := alloc(nfat, fatSect)
	difatStart := alloc(ndifat, difSect)
	dirStart := alloc(dirSectors, 0)
	miniFATStart := alloc(miniFATSectors, 0)
	miniStart := alloc(miniSectors, 0)
	for _, e := range all {
		if e.typ == 2 && !e.mini {
			e.start = alloc(e.sectors, 0)
		}
	}
	root.start, root.size = miniStart, len(ministream)
	if len(ministream) == 0 {
		root.start = endOfChain
	}

	out := make([]byte, ssz*(1+int(next)))
	h := out[:512]
	copy(h, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	le16(h[24:], 0x3E)
	le16(h[26:], uint16(version))
	le16(h[28:], 0xFFFE)
	le16(h[30:], uint16(shift))
	le16(h[32:], 6)
	if version == 4 {
		le32(h[40:], uint32(dirSectors))
	}
	le32(h[44:], uint32(nfat))
	le32(h[48:], dirStart)
	le32(h[56:], 4096)
	le32(h[60:], miniFATStart)
	le32(h[64:], uint32(miniFATSectors))
	le32(h[68:], difatStart)
	le32(h[72:], uint32(ndifat))
	lay := &Layout{SectorSize: ssz, DirStart: dirStart, IDs: map[string]int{}, Starts: map[string]uint32{}}
	for i := range nfat {
		lay.FATSectors = append(lay.FATSectors, fatStart+uint32(i))
	}
	for i := range 109 {
		v := uint32(freeSect)
		if i < nfat {
			v = fatStart + uint32(i)
		}
		le32(h[76+4*i:], v)
	}
	off := func(s uint32) []byte { return out[(int(s)+1)*ssz : (int(s)+2)*ssz] }
	for d := range ndifat {
		sec := off(difatStart + uint32(d))
		for i := range per - 1 {
			idx := 109 + d*(per-1) + i
			v := uint32(freeSect)
			if idx < nfat {
				v = fatStart + uint32(idx)
			}
			le32(sec[4*i:], v)
		}
		nx := uint32(endOfChain)
		if d < ndifat-1 {
			nx = difatStart + uint32(d) + 1
		}
		le32(sec[4*(per-1):], nx)
	}
	for i, v := range fat {
		le32(out[(int(fatStart)+1)*ssz+4*i:], v)
	}
	dir := out[(int(dirStart)+1)*ssz : (int(dirStart)+1+dirSectors)*ssz]
	for i := range dirSectors * ssz / 128 {
		r := dir[i*128 : (i+1)*128]
		le32(r[68:], noStream)
		le32(r[72:], noStream)
		le32(r[76:], noStream)
	}
	for _, e := range all {
		r := dir[e.id*128 : (e.id+1)*128]
		name := e.node.Name
		u := utf16.Encode([]rune(name))
		for i, c := range u {
			le16(r[2*i:], c)
		}
		le16(r[64:], uint16(2*len(u)+2))
		r[66] = e.typ
		r[67] = 1
		le32(r[68:], noStream)
		le32(r[72:], e.right)
		le32(r[76:], e.child)
		if e.typ != 1 {
			le32(r[116:], e.start)
			binary.LittleEndian.PutUint64(r[120:], uint64(e.size))
		}
		lay.IDs[e.path] = e.id
		lay.Starts[e.path] = e.start
	}
	if miniFATSectors > 0 {
		mf := out[(int(miniFATStart)+1)*ssz : (int(miniFATStart)+1+miniFATSectors)*ssz]
		for i := range len(mf) / 4 {
			v := uint32(freeSect)
			if i < len(miniFAT) {
				v = miniFAT[i]
			}
			le32(mf[4*i:], v)
		}
	}
	if miniSectors > 0 {
		copy(out[(int(miniStart)+1)*ssz:], ministream)
	}
	for _, e := range all {
		if e.typ == 2 && !e.mini {
			copy(out[(int(e.start)+1)*ssz:], e.node.Data)
		}
	}
	return out, lay
}

// less is the MS-CFB 2.6.4 order: shorter names first, then by uppercased code
// units.
func less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(strings.ToUpper(a))), utf16.Encode([]rune(strings.ToUpper(b)))
	if len(ua) != len(ub) {
		return len(ua) < len(ub)
	}
	for i := range ua {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return false
}

func le16(b []byte, v uint16) { binary.LittleEndian.PutUint16(b, v) }
func le32(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }
