package mailparse

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/nlink-jp/mailparse/internal/cfbtest"
)

// Test values for building .msg files from MS-OXMSG: a property is a tag and a
// Go value whose type picks the MAPI type.
type (
	s8   []byte // PtypString8, stored as written (no terminator added)
	mapi struct {
		id  uint16
		val any // string (PtypString), s8, []byte (PtypBinary), uint32, bool, time.Time
	}
)

func u16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u)+2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func filetime(t time.Time) uint64 { return uint64(t.UnixNano()/100) + filetimeEpoch }

// msgObject returns the streams of one MS-OXMSG object: its property stream
// (with a header of hdr bytes) and one __substg1.0_ stream per variable-length
// value, followed by extra children (recipient, attachment, embedded storages).
func msgObject(hdr int, ps []mapi, extra ...*cfbtest.Node) []*cfbtest.Node {
	stream := make([]byte, hdr)
	var nodes []*cfbtest.Node
	for _, p := range ps {
		var typ uint16
		var val [8]byte
		var data []byte
		switch v := p.val.(type) {
		case string:
			typ, data = ptUnicode, u16le(v)
		case s8:
			typ, data = ptString8, append([]byte(v), 0)
		case []byte:
			typ, data = ptBinary, v
		case uint32:
			typ = ptInt32
			binary.LittleEndian.PutUint32(val[:], v)
		case bool:
			typ = ptBoolean
			if v {
				val[0] = 1
			}
		case time.Time:
			typ = ptTime
			binary.LittleEndian.PutUint64(val[:], filetime(v))
		default:
			panic(fmt.Sprintf("unsupported test value %T", v))
		}
		tag := uint32(p.id)<<16 | uint32(typ)
		if data != nil {
			binary.LittleEndian.PutUint32(val[:], uint32(len(data)))
			nodes = append(nodes, cfbtest.Stream(fmt.Sprintf("__substg1.0_%08X", tag), data))
		}
		var e [16]byte
		binary.LittleEndian.PutUint32(e[0:], tag)
		binary.LittleEndian.PutUint32(e[4:], 6) // PROPATTR_READABLE | PROPATTR_WRITABLE
		copy(e[8:], val[:])
		stream = append(stream, e[:]...)
	}
	nodes = append(nodes, cfbtest.Stream(propsStream, stream))
	return append(nodes, extra...)
}

func recip(i int, ps ...mapi) *cfbtest.Node {
	return cfbtest.Dir(fmt.Sprintf("%s%08X", recipPrefix, i), msgObject(8, ps)...)
}

func attach(i int, ps []mapi, extra ...*cfbtest.Node) *cfbtest.Node {
	return cfbtest.Dir(fmt.Sprintf("%s%08X", attachPrefix, i), msgObject(8, ps, extra...)...)
}

func embedded(ps []mapi, extra ...*cfbtest.Node) *cfbtest.Node {
	return cfbtest.Dir(embeddedMessageStorage, msgObject(24, ps, extra...)...)
}

// buildMSG builds a top-level .msg (version 3 compound file).
func buildMSG(ps []mapi, extra ...*cfbtest.Node) []byte {
	b, _ := cfbtest.Build(3, msgObject(32, ps, extra...)...)
	return b
}
