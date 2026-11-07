package msgtest

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"
)

// MAPI property types (MS-OXCDATA 2.11.1) used by Prop.
const (
	PtypInteger32 = 0x0003
	PtypBoolean   = 0x000B
	PtypObject    = 0x000D
	PtypString8   = 0x001E
	PtypString    = 0x001F
	PtypTime      = 0x0040
	PtypBinary    = 0x0102
)

// Property IDs often needed in fixtures (MS-OXPROPS). Any other ID works too.
const (
	PidTagSubject                     = 0x0037
	PidTagClientSubmitTime            = 0x0039
	PidTagSentRepresentingName        = 0x0042
	PidTagSentRepresentingEmail       = 0x0065
	PidTagTransportMessageHeaders     = 0x007D
	PidTagRecipientType               = 0x0C15
	PidTagSenderName                  = 0x0C1A
	PidTagSenderEmailAddress          = 0x0C1F
	PidTagDisplayBcc                  = 0x0E02
	PidTagDisplayCc                   = 0x0E03
	PidTagDisplayTo                   = 0x0E04
	PidTagMessageDeliveryTime         = 0x0E06
	PidTagBody                        = 0x1000
	PidTagRtfCompressed               = 0x1009
	PidTagHtml                        = 0x1013
	PidTagInternetMessageID           = 0x1035
	PidTagInternetReferences          = 0x1039
	PidTagInReplyToID                 = 0x1042
	PidTagDisplayName                 = 0x3001
	PidTagEmailAddress                = 0x3003
	PidTagAttachDataBinary            = 0x3701
	PidTagAttachFilename              = 0x3704
	PidTagAttachMethod                = 0x3705
	PidTagAttachLongFilename          = 0x3707
	PidTagAttachMimeTag               = 0x370E
	PidTagAttachContentID             = 0x3712
	PidTagAttachFlags                 = 0x3714
	PidTagSMTPAddress                 = 0x39FE
	PidTagInternetCodepage            = 0x3FDE
	PidTagMessageCodepage             = 0x3FFD
	PidTagSenderSMTPAddress           = 0x5D01
	PidTagSentRepresentingSMTPAddress = 0x5D02
	PidTagAttachmentHidden            = 0x7FFE
)

// Attachment methods (PidTagAttachMethod) and recipient types.
const (
	AttachByValue         = 1
	AttachEmbeddedMessage = 5
	AttachOLE             = 6
	RecipientTo           = 1
	RecipientCc           = 2
	RecipientBcc          = 3
)

// Property stream header sizes (MS-OXMSG 2.4).
const (
	HeaderTopLevel = 32
	HeaderEmbedded = 24
	HeaderObject   = 8 // recipients and attachments
)

// String8 is a PtypString8 value, stored as given in the object's code page
// (a terminating NUL is added).
type String8 []byte

// Prop is one MAPI property. The Go type of Value picks the MAPI type: string
// (PtypString, UTF-16LE), String8, []byte (PtypBinary), uint32
// (PtypInteger32), bool (PtypBoolean), time.Time (PtypTime).
type Prop struct {
	ID    uint16
	Value any
}

// P makes a Prop.
func P(id uint16, v any) Prop { return Prop{ID: id, Value: v} }

// UTF16 returns s as UTF-16LE with a terminating NUL, as PtypString is stored.
func UTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u)+2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// FILETIME returns t as a FILETIME (100 ns units since 1601).
func FILETIME(t time.Time) uint64 { return uint64(t.UnixNano()/100) + 116444736000000000 }

// Object returns the streams of one MS-OXMSG object: its property stream (with
// a header of header bytes: HeaderTopLevel, HeaderEmbedded or HeaderObject)
// and one __substg1.0_ stream per variable-length value, followed by extra
// children (recipient, attachment and embedded-message storages).
func Object(header int, props []Prop, extra ...*Node) []*Node {
	stream := make([]byte, header)
	var nodes []*Node
	for _, p := range props {
		var typ uint16
		var val [8]byte
		var data []byte
		switch v := p.Value.(type) {
		case string:
			typ, data = PtypString, UTF16(v)
		case String8:
			typ, data = PtypString8, append(append([]byte{}, v...), 0)
		case []byte:
			typ, data = PtypBinary, v
		case uint32:
			typ = PtypInteger32
			binary.LittleEndian.PutUint32(val[:], v)
		case bool:
			typ = PtypBoolean
			if v {
				val[0] = 1
			}
		case time.Time:
			typ = PtypTime
			binary.LittleEndian.PutUint64(val[:], FILETIME(v))
		default:
			panic(fmt.Sprintf("msgtest: unsupported property value %T", v))
		}
		tag := uint32(p.ID)<<16 | uint32(typ)
		if data != nil {
			binary.LittleEndian.PutUint32(val[:], uint32(len(data)))
			nodes = append(nodes, Stream(fmt.Sprintf("__substg1.0_%08X", tag), data))
		}
		var e [16]byte
		binary.LittleEndian.PutUint32(e[0:], tag)
		binary.LittleEndian.PutUint32(e[4:], 6) // PROPATTR_READABLE | PROPATTR_WRITABLE
		copy(e[8:], val[:])
		stream = append(stream, e[:]...)
	}
	nodes = append(nodes, Stream("__properties_version1.0", stream))
	return append(nodes, extra...)
}

// Recipient returns recipient storage i (__recip_version1.0_#XXXXXXXX).
func Recipient(i int, props ...Prop) *Node {
	return Dir(fmt.Sprintf("__recip_version1.0_#%08X", i), Object(HeaderObject, props)...)
}

// Attachment returns attachment storage i (__attach_version1.0_#XXXXXXXX);
// extra holds an Embedded message for AttachEmbeddedMessage.
func Attachment(i int, props []Prop, extra ...*Node) *Node {
	return Dir(fmt.Sprintf("__attach_version1.0_#%08X", i), Object(HeaderObject, props, extra...)...)
}

// Embedded returns the storage of an embedded message (__substg1.0_3701000D),
// to put inside an Attachment.
func Embedded(props []Prop, extra ...*Node) *Node {
	return Dir("__substg1.0_3701000D", Object(HeaderEmbedded, props, extra...)...)
}

// Message returns a top-level .msg file (a version 3 compound file) with the
// message's properties and extra recipient and attachment storages.
func Message(props []Prop, extra ...*Node) []byte {
	b, _ := Build(3, Object(HeaderTopLevel, props, extra...)...)
	return b
}
