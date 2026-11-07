package mailparse

import (
	"github.com/nlink-jp/mailparse/msgtest"
)

// The tests build .msg files with the exported msgtest package; these short
// names keep the test tables readable.
type (
	s8   = msgtest.String8 // PtypString8, stored as written (a NUL is added)
	mapi struct {          // {id, value}: the Go type of the value picks the MAPI type
		id  uint16
		val any
	}
)

func toProps(ps []mapi) []msgtest.Prop {
	out := make([]msgtest.Prop, len(ps))
	for i, p := range ps {
		out[i] = msgtest.P(p.id, p.val)
	}
	return out
}

func u16le(s string) []byte { return msgtest.UTF16(s) }

func msgObject(hdr int, ps []mapi, extra ...*msgtest.Node) []*msgtest.Node {
	return msgtest.Object(hdr, toProps(ps), extra...)
}

func recip(i int, ps ...mapi) *msgtest.Node { return msgtest.Recipient(i, toProps(ps)...) }

func attach(i int, ps []mapi, extra ...*msgtest.Node) *msgtest.Node {
	return msgtest.Attachment(i, toProps(ps), extra...)
}

func embedded(ps []mapi, extra ...*msgtest.Node) *msgtest.Node {
	return msgtest.Embedded(toProps(ps), extra...)
}

func buildMSG(ps []mapi, extra ...*msgtest.Node) []byte {
	return msgtest.Message(toProps(ps), extra...)
}
