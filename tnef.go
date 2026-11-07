package mailparse

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
)

// TNEF (winmail.dat, MS-OXTNEF).

// Attribute levels and IDs (MS-OXTNEF 2.1.3.1, the ID bytes read as a
// little-endian 32-bit value).
const (
	tnefLevelMessage    = 0x01
	tnefLevelAttachment = 0x02

	attOemCodepage    = 0x00069007
	attSubject        = 0x00018004
	attMessageID      = 0x00018009
	attBody           = 0x0002800C
	attMsgProps       = 0x00069003
	attRecipTable     = 0x00069004
	attAttachRendData = 0x00069002
	attAttachTitle    = 0x00018010
	attAttachData     = 0x0006800F
	attAttachment     = 0x00069005
)

// iidMessage is the interface identifier of an attached message object
// (IID_IMessage); such a PtypObject value is itself a TNEF stream.
var iidMessage = []byte{0x07, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

// tnefAttachment collects the attributes of one attachment.
type tnefAttachment struct {
	title string
	data  []byte
	props *props
	part  string
}

// parseTNEF reads a TNEF stream. It returns an error only when b does not
// start with the TNEF signature; damage after it is warned about.
func (st *state) parseTNEF(b []byte, depth int, part string) (*Message, error) {
	if len(b) < 6 || binary.LittleEndian.Uint32(b) != tnefSignature {
		return nil, fmt.Errorf("no TNEF signature")
	}
	m := &Message{Format: FormatTNEF, Size: int64(len(b)), Bodies: []Body{}, Attachments: []Attachment{}, Warnings: []Warning{}}
	warn := warner(m)

	msgProps := &props{fixed: map[uint32][8]byte{}, part: part, warn: warn}
	var vars map[uint32][]byte
	msgProps.varLoad = st.tnefLoader(&vars, part, warn)
	var recips []*props
	var atts []*tnefAttachment
	attsCut := false
	var subject string
	var legacyBody []byte
	oemCP := uint32(0)
	bad := 0

	i := 6 // signature and legacy key
	for i < len(b) {
		if len(b)-i < 11 {
			warn(Warning{Code: WarnTNEFDamaged, Detail: fmt.Sprintf("%d trailing bytes do not form an attribute; they were skipped", len(b)-i), Part: part})
			break
		}
		level := b[i]
		id := binary.LittleEndian.Uint32(b[i+1:])
		n := int64(binary.LittleEndian.Uint32(b[i+5:]))
		i += 9
		if n > int64(len(b)-i-2) {
			warn(Warning{Code: WarnTNEFDamaged, Detail: fmt.Sprintf("attribute %#08x declares %d bytes, more than remain; reading stopped", id, n), Part: part})
			break
		}
		data := b[i : i+int(n)]
		sum := binary.LittleEndian.Uint16(b[i+int(n):])
		i += int(n) + 2
		if tnefChecksum(data) != sum {
			bad++
		}

		switch level {
		case tnefLevelMessage:
			switch id {
			case attOemCodepage:
				if len(data) >= 4 {
					oemCP = binary.LittleEndian.Uint32(data)
				}
			case attSubject:
				subject = string(trimNUL(data))
			case attMessageID:
				// MS-OXTNEF 2.1.3.3.6: this is PidTagSearchKey written as hex,
				// not the internet Message-ID, so it is not reported as one.
			case attBody:
				legacyBody = data
			case attMsgProps:
				fixed, v := st.tnefProps(data, part, warn)
				for k, x := range fixed {
					msgProps.fixed[k] = x
				}
				if vars == nil {
					vars = v
				} else {
					for k, x := range v {
						vars[k] = x
					}
				}
			case attRecipTable:
				recips = append(recips, st.tnefRecipients(data, part, warn)...)
			}
		case tnefLevelAttachment:
			if id == attAttachRendData || len(atts) == 0 {
				// Records stop at MaxParts: a stream of empty attachments must
				// not allocate without bound before the part count is applied.
				if attsCut || len(atts) >= st.opt.MaxParts {
					attsCut = true
					continue
				}
				ap := part + "/attach/" + strconv.Itoa(len(atts))
				atts = append(atts, &tnefAttachment{part: ap})
			} else if attsCut {
				continue
			}
			a := atts[len(atts)-1]
			switch id {
			case attAttachTitle:
				a.title = string(trimNUL(data))
			case attAttachData:
				a.data = data
			case attAttachment:
				fixed, v := st.tnefProps(data, a.part, warn)
				q := &props{fixed: fixed, part: a.part, warn: warn}
				q.varLoad = st.tnefLoader(&v, a.part, warn)
				a.props = q
			}
		default:
			warn(Warning{Code: WarnTNEFDamaged, Detail: fmt.Sprintf("attribute %#08x has an unknown level %d; it was skipped", id, level), Part: part})
		}
	}
	if bad > 0 {
		warn(Warning{Code: WarnTNEFDamaged, Detail: fmt.Sprintf("%d attributes failed their checksum; their values were kept", bad), Part: part})
	}

	if attsCut {
		warn(Warning{Code: WarnPartLimit, Detail: fmt.Sprintf("TNEF attachments after the first %d were not read", st.opt.MaxParts), Part: part})
	}
	// MS-OXTNEF 2.3.3.2: 8-bit strings, legacy attributes included, are in the
	// OEM code page; the HTML body follows the internet code page.
	internetCP, msgCP := cpCharset(msgProps, pidInternetCodepage), cpCharset(msgProps, pidMessageCodepage)
	charset := firstNonEmpty(codePageCharset(oemCP), internetCP, msgCP)
	msgProps.charset = charset
	msgProps.bodyCharset = charset
	msgProps.htmlCharset = firstNonEmpty(internetCP, charset)
	legacy := func(s string) string {
		if s == "" || isASCII([]byte(s)) {
			return s
		}
		return decodeText("text/plain", charset, "codepage", []byte(s), part, warn).content
	}

	if raw, ok := msgProps.rawString(pidTransportHeaders); ok && len(bytes.TrimSpace(raw)) > 0 {
		h, _ := st.readHeader(append(raw, "\r\n\r\n"...), part+"/headers", warn)
		m.Header = h
		st.fillIdentity(m, warn)
		compareIdentity(m, msgProps, part, warn)
	} else {
		identityFromProps(m, msgProps, part, warn)
		for _, q := range recips {
			q.charset = charset
		}
		setRecipients(m, recips, part, warn)
	}
	if m.Subject == "" {
		m.Subject = legacy(subject)
	}

	before := len(m.Bodies)
	st.propBodies(m, msgProps, part, warn)
	hasText := false
	for _, bd := range m.Bodies[before:] {
		hasText = hasText || bd.Part == part+"/body"
	}
	if !hasText && legacyBody != nil {
		body := st.budgeted(bytes.Clone(trimNUL(legacyBody)), part+"/body", warn)
		r := decodeText("text/plain", charset, "codepage", body, part+"/body", warn)
		m.Bodies = append(m.Bodies, Body{MediaType: "text/plain", Content: r.content, Charset: r.charset, CharsetSource: r.source, Size: len(body), Part: part + "/body"})
	}

	for _, ta := range atts {
		if !st.countPart(ta.part, warn) {
			break
		}
		m.Attachments = append(m.Attachments, st.tnefAttach(ta, charset, depth, warn))
	}
	return m, nil
}

// tnefAttach turns collected attachment attributes into an Attachment. The
// MAPI properties (attAttachment) win over the legacy attributes.
func (st *state) tnefAttach(ta *tnefAttachment, charset string, depth int, warn func(Warning)) Attachment {
	a := Attachment{Part: ta.part, Disposition: "attachment"}
	data := ta.data
	charged := false // values read through props are charged when loaded
	var embedded []byte
	if ta.props != nil {
		ta.props.charset = charset
		a = mapiAttachment(ta.props, ta.part)
		if v, ok := ta.props.varLoad(uint32(pidAttachData)<<16 | ptObject); ok {
			if len(v) >= 16 && bytes.Equal(v[:16], iidMessage) {
				embedded = v[16:]
			} else if data == nil && len(v) >= 16 {
				data, charged = v[16:], true
			}
		}
		if data == nil {
			if v, ok := ta.props.varLoad(uint32(pidAttachData)<<16 | ptBinary); ok {
				data, charged = v, true
			}
		}
	}
	if a.Filename == "" && ta.title != "" {
		a.Filename = ta.title
		if !isASCII([]byte(a.Filename)) {
			a.Filename = decodeText("text/plain", charset, "codepage", []byte(a.Filename), ta.part, warn).content
		}
	}
	if embedded != nil {
		if a.MediaType == "" {
			a.MediaType = "application/vnd.ms-tnef"
		}
		if depth+1 > st.opt.MaxMessageDepth {
			warn(Warning{Code: WarnMessageDepthLimit, Detail: fmt.Sprintf("a message nested deeper than %d layers was not opened", st.opt.MaxMessageDepth), Part: ta.part})
			return a
		}
		if nm, err := st.parseTNEF(embedded, depth+1, "tnef"); err == nil {
			a.Message = nm
		} else {
			warn(Warning{Code: WarnNestedUnreadable, Detail: "an attached message object is not a TNEF stream", Part: ta.part})
		}
		return a
	}
	if data == nil {
		warn(Warning{Code: WarnAttachmentNotExtracted, Detail: "a TNEF attachment carries no data", Part: ta.part})
		return a
	}
	if charged {
		a.Data = data
	} else {
		a.Data = st.budgeted(bytes.Clone(data), ta.part, warn)
	}
	a.Size = len(a.Data)
	if a.MediaType == "" {
		a.MediaType = "application/octet-stream"
	}
	a.Message = st.openByContent(a.Data, a.MediaType, a.Filename, depth, ta.part, warn)
	return a
}

func tnefChecksum(b []byte) uint16 {
	var s uint16
	for _, c := range b {
		s += uint16(c)
	}
	return s
}

// tnefRecipients reads attRecipTable: a row count and one property list per
// row.
func (st *state) tnefRecipients(data []byte, part string, warn func(Warning)) []*props {
	if len(data) < 4 {
		warn(Warning{Code: WarnTNEFDamaged, Detail: "the recipient table is shorter than its row count", Part: part})
		return nil
	}
	rows := binary.LittleEndian.Uint32(data)
	rd := &tnefCursor{b: data, i: 4}
	var out []*props
	r := uint32(0)
	for ; r < rows && rd.left() >= 4; r++ {
		if r == maxTNEFRecipients {
			warn(Warning{Code: WarnTNEFDamaged, Detail: fmt.Sprintf("recipient rows after the first %d were not read", maxTNEFRecipients), Part: part})
			return out
		}
		fixed, v, ok := rd.propList()
		rp := part + "/recip/" + strconv.FormatUint(uint64(r), 10)
		q := &props{fixed: fixed, part: rp, warn: warn}
		q.varLoad = st.tnefLoader(&v, rp, warn)
		out = append(out, q)
		if !ok {
			warn(Warning{Code: WarnTNEFDamaged, Detail: "a recipient row ended inside a property; reading stopped", Part: part})
			return out
		}
	}
	switch {
	case r < rows:
		warn(Warning{Code: WarnTNEFDamaged, Detail: fmt.Sprintf("the recipient table declares %d rows and holds %d", rows, r), Part: part})
	case rd.left() > 0:
		warn(Warning{Code: WarnTNEFDamaged, Detail: fmt.Sprintf("%d bytes after the recipient table were skipped", rd.left()), Part: part})
	}
	return out
}

// maxTNEFRecipients bounds the recipient rows read: each costs far more memory
// than its 4 bytes of input.
const maxTNEFRecipients = 10000

// tnefProps reads one encapsulated property list (attMsgProps, attAttachment).
func (st *state) tnefProps(data []byte, part string, warn func(Warning)) (map[uint32][8]byte, map[uint32][]byte) {
	rd := &tnefCursor{b: data}
	fixed, vars, ok := rd.propList()
	switch {
	case !ok:
		warn(Warning{Code: WarnTNEFDamaged, Detail: "an encapsulated property list ended inside a property; the properties before it were kept", Part: part})
	case rd.left() > 0:
		warn(Warning{Code: WarnTNEFDamaged, Detail: fmt.Sprintf("%d bytes after an encapsulated property list were skipped", rd.left()), Part: part})
	}
	return fixed, vars
}

// tnefLoader returns a props.varLoad over values read from a TNEF property
// list, charging each value read to MaxDecoded as .msg stream reads are, and
// returning a copy so nothing aliases the input.
func (st *state) tnefLoader(vars *map[uint32][]byte, part string, warn func(Warning)) func(uint32) ([]byte, bool) {
	return func(tag uint32) ([]byte, bool) {
		v, ok := (*vars)[tag]
		if !ok {
			return nil, false
		}
		if st.decoded >= st.opt.MaxDecoded {
			st.limitWarn(part, warn)
			return nil, false
		}
		return st.budgeted(bytes.Clone(v), part, warn), true
	}
}

// tnefCursor reads encapsulated MAPI properties (MS-OXTNEF 2.1.3.4). Every
// read is checked against what remains, so a hostile count cannot run past
// the data.
type tnefCursor struct {
	b []byte
	i int
}

func (c *tnefCursor) left() int { return len(c.b) - c.i }

func (c *tnefCursor) u32() (uint32, bool) {
	if c.left() < 4 {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(c.b[c.i:])
	c.i += 4
	return v, true
}

// take returns n bytes and skips the padding to a 4-byte boundary.
func (c *tnefCursor) take(n int) ([]byte, bool) {
	if n < 0 || n > c.left() {
		return nil, false
	}
	v := c.b[c.i : c.i+n]
	c.i += n
	if pad := (4 - n%4) % 4; pad <= c.left() {
		c.i += pad
	} else {
		c.i = len(c.b)
	}
	return v, true
}

// scalarSize is the value size of a fixed-length property type, or 0.
func scalarSize(typ uint16) int {
	switch typ {
	case 0x0002, 0x000B: // Int16, Boolean
		return 2
	case 0x0003, 0x0004, 0x000A: // Int32, Flt32, Error
		return 4
	case 0x0005, 0x0006, 0x0007, 0x0014, 0x0040: // Flt64, Currency, AppTime, Int64, Systime
		return 8
	case 0x0048: // CLSID
		return 16
	}
	return 0
}

// propList reads a property count and the properties. Single-valued
// fixed-length values go to fixed (named properties are read past but not
// kept); the first value of variable-length ones goes to vars.
func (c *tnefCursor) propList() (map[uint32][8]byte, map[uint32][]byte, bool) {
	fixed, vars := map[uint32][8]byte{}, map[uint32][]byte{}
	count, ok := c.u32()
	if !ok {
		return fixed, vars, false
	}
	for p := uint32(0); p < count; p++ {
		tagv, ok := c.u32()
		if !ok {
			return fixed, vars, false
		}
		typ, id := uint16(tagv), uint16(tagv>>16)
		if id >= 0x8000 { // named property: GUID, kind, then an ID or a name
			if _, ok := c.take(16); !ok {
				return fixed, vars, false
			}
			kind, ok := c.u32()
			if !ok {
				return fixed, vars, false
			}
			if kind == 0 {
				if _, ok := c.u32(); !ok {
					return fixed, vars, false
				}
			} else {
				n, ok := c.u32()
				if !ok {
					return fixed, vars, false
				}
				if _, ok := c.take(int(min(n, uint32(c.left()+1)))); !ok {
					return fixed, vars, false
				}
			}
		}
		multi := typ&0x1000 != 0
		base := typ &^ 0x1000
		switch base {
		case ptString8, ptUnicode, ptBinary, ptObject:
			n, ok := c.u32() // value count (1 for single-valued)
			if !ok {
				return fixed, vars, false
			}
			for k := uint32(0); k < n; k++ {
				size, ok := c.u32()
				if !ok {
					return fixed, vars, false
				}
				v, ok := c.take(int(min(size, uint32(c.left()+1))))
				if !ok {
					return fixed, vars, false
				}
				if k == 0 && !multi && id < 0x8000 {
					vars[tagv] = v
				}
			}
		case 0x0001: // PtypNull: no value
		default:
			size := scalarSize(base)
			if size == 0 {
				return fixed, vars, false // an unknown type: its size cannot be known
			}
			n := uint32(1)
			if multi {
				if n, ok = c.u32(); !ok {
					return fixed, vars, false
				}
			}
			for k := uint32(0); k < n; k++ {
				v, ok := c.take(size)
				if !ok {
					return fixed, vars, false
				}
				if k == 0 && !multi && id < 0x8000 {
					var f [8]byte
					copy(f[:], v)
					fixed[tagv] = f
				}
			}
		}
	}
	return fixed, vars, true
}

// ParseTNEF reads a TNEF stream (winmail.dat).
func ParseTNEF(r io.Reader, opt Options) (*Message, error) {
	opt = opt.withDefaults()
	b, err := readLimited(r, opt.MaxSize)
	if err != nil {
		return nil, err
	}
	st := &state{opt: opt}
	m, err := st.parseTNEF(b, 0, "tnef")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotMessage, err)
	}
	return m, nil
}
