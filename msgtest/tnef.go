package msgtest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// TNEF attribute levels and IDs (MS-OXTNEF 2.1.3, the ID bytes read as a
// little-endian 32-bit value).
const (
	LevelMessage    = 0x01
	LevelAttachment = 0x02

	AttOemCodepage    = 0x00069007
	AttSubject        = 0x00018004
	AttMessageID      = 0x00018009
	AttBody           = 0x0002800C
	AttMsgProps       = 0x00069003
	AttRecipTable     = 0x00069004
	AttAttachRendData = 0x00069002
	AttAttachTitle    = 0x00018010
	AttAttachData     = 0x0006800F
	AttAttachment     = 0x00069005
)

// IIDMessage is the interface identifier of an attached message object; a
// PtypObject value starting with it holds a TNEF stream.
var IIDMessage = []byte{0x07, 0x03, 0x02, 0x00, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46}

// TNEFProp is one encapsulated MAPI property (MS-OXTNEF 2.1.3.4). Tag is
// id<<16|type (see Tag). Value: []byte for a variable-length type (String8,
// Unicode, Binary, Object — pass the encoded bytes, e.g. UTF16(s) for
// PtypString, IIDMessage+stream for an attached message), [][]byte for a
// multi-valued one, uint32, uint16, bool, time.Time. NameID or NameString make
// it a named property (ID >= 0x8000): a GUID, then a numeric ID or a name.
type TNEFProp struct {
	Tag        uint32
	Value      any
	NameID     uint32
	NameString string
}

// Tag makes a property tag.
func Tag(id, typ uint16) uint32 { return uint32(id)<<16 | uint32(typ) }

func u32le(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// TNEFProps encodes a property list: a count, then each property with values
// padded to 4 bytes.
func TNEFProps(props ...TNEFProp) []byte {
	out := u32le(uint32(len(props)))
	for _, p := range props {
		out = append(out, u32le(p.Tag)...)
		if p.Tag>>16 >= 0x8000 {
			out = append(out, bytes.Repeat([]byte{0xAB}, 16)...) // a GUID
			if p.NameString != "" {
				name := UTF16(p.NameString)
				out = append(out, u32le(1)...)
				out = append(out, u32le(uint32(len(name)))...)
				out = append(out, pad4(name)...)
			} else {
				out = append(out, u32le(0)...)
				out = append(out, u32le(p.NameID)...)
			}
		}
		switch v := p.Value.(type) {
		case []byte:
			out = append(out, u32le(1)...)
			out = append(out, u32le(uint32(len(v)))...)
			out = append(out, pad4(append([]byte{}, v...))...)
		case [][]byte:
			out = append(out, u32le(uint32(len(v)))...)
			for _, x := range v {
				out = append(out, u32le(uint32(len(x)))...)
				out = append(out, pad4(append([]byte{}, x...))...)
			}
		case uint32:
			out = append(out, u32le(v)...)
		case uint16:
			out = append(out, pad4(binary.LittleEndian.AppendUint16(nil, v))...)
		case bool:
			x := uint16(0)
			if v {
				x = 1
			}
			out = append(out, pad4(binary.LittleEndian.AppendUint16(nil, x))...)
		case time.Time:
			out = append(out, binary.LittleEndian.AppendUint64(nil, FILETIME(v))...)
		default:
			panic(fmt.Sprintf("msgtest: unsupported TNEF property value %T", v))
		}
	}
	return out
}

// TNEFRecipients encodes attRecipTable: a row count, then one property list
// per row.
func TNEFRecipients(rows ...[]TNEFProp) []byte {
	out := u32le(uint32(len(rows)))
	for _, r := range rows {
		out = append(out, TNEFProps(r...)...)
	}
	return out
}

// TNEFAttr encodes one attribute: level, ID, length, data and the checksum
// (the sum of the data bytes, modulo 65536).
func TNEFAttr(level byte, id uint32, data []byte) []byte {
	out := []byte{level}
	out = append(out, u32le(id)...)
	out = append(out, u32le(uint32(len(data)))...)
	out = append(out, data...)
	var sum uint16
	for _, c := range data {
		sum += uint16(c)
	}
	return binary.LittleEndian.AppendUint16(out, sum)
}

// TNEF returns a TNEF stream (winmail.dat): the signature, a legacy key and the
// attributes.
func TNEF(attrs ...[]byte) []byte {
	out := append(u32le(0x223E9F78), 0x01, 0x00)
	for _, a := range attrs {
		out = append(out, a...)
	}
	return out
}
