package mailparse

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/nlink-jp/mailparse/cfb"
)

// MAPI property IDs read from .msg files and TNEF (MS-OXPROPS).
const (
	pidSubject             = 0x0037
	pidClientSubmitTime    = 0x0039
	pidSentRepName         = 0x0042
	pidSentRepEmail        = 0x0065
	pidTransportHeaders    = 0x007D
	pidRecipientType       = 0x0C15
	pidSenderName          = 0x0C1A
	pidSenderEmail         = 0x0C1F
	pidDeliveryTime        = 0x0E06
	pidBody                = 0x1000
	pidRTFCompressed       = 0x1009
	pidHTML                = 0x1013
	pidInternetMessageID   = 0x1035
	pidDisplayName         = 0x3001
	pidEmailAddress        = 0x3003
	pidAttachData          = 0x3701
	pidAttachFilename      = 0x3704
	pidAttachMethod        = 0x3705
	pidAttachLongFilename  = 0x3707
	pidAttachMIMETag       = 0x370E
	pidAttachContentID     = 0x3712
	pidAttachFlags         = 0x3714
	pidSMTPAddress         = 0x39FE
	pidInternetCodepage    = 0x3FDE
	pidMessageCodepage     = 0x3FFD
	pidSenderSMTP          = 0x5D01
	pidSentRepSMTP         = 0x5D02
	pidAttachmentHidden    = 0x7FFE
	propsStream            = "__properties_version1.0"
	recipPrefix            = "__recip_version1.0_#"
	attachPrefix           = "__attach_version1.0_#"
	embeddedMessageStorage = "__substg1.0_3701000D"
)

// MAPI property types (MS-OXCDATA 2.11.1).
const (
	ptInt32   = 0x0003
	ptBoolean = 0x000B
	ptObject  = 0x000D
	ptString8 = 0x001E
	ptUnicode = 0x001F
	ptTime    = 0x0040
	ptBinary  = 0x0102
)

// Attachment methods (PidTagAttachMethod).
const (
	attachByValue  = 1
	attachEmbedded = 5
	attachOLE      = 6
)

// props is the set of MAPI properties of one object, whatever container it
// came from (.msg storage or TNEF): fixed-length values by tag, and
// variable-length values loaded on demand.
type props struct {
	fixed       map[uint32][8]byte
	varLoad     func(tag uint32) ([]byte, bool) // reads a variable-length value
	varHas      func(tag uint32) bool
	charset     string // for PtypString8 values; "" when unknown
	bodyCharset string // for an 8-bit PidTagBody; charset when unset
	htmlCharset string // for PidTagHtml; bodyCharset when unset
	part        string
	warn        func(Warning)
}

func (p *props) int32(id uint16) (uint32, bool) {
	v, ok := p.fixed[uint32(id)<<16|ptInt32]
	return binary.LittleEndian.Uint32(v[:]), ok
}

func (p *props) boolean(id uint16) bool {
	v, ok := p.fixed[uint32(id)<<16|ptBoolean]
	return ok && (v[0] != 0 || v[1] != 0)
}

// filetimeEpoch is the FILETIME offset of the Unix epoch, in 100 ns units.
const filetimeEpoch = 116444736000000000

func (p *props) time(id uint16) (time.Time, bool) {
	v, ok := p.fixed[uint32(id)<<16|ptTime]
	if !ok {
		return time.Time{}, false
	}
	ft := binary.LittleEndian.Uint64(v[:])
	if ft == 0 || ft < filetimeEpoch/2 || ft > 1<<62 {
		return time.Time{}, false
	}
	d := int64(ft) - filetimeEpoch
	return time.Unix(d/1e7, (d%1e7)*100).UTC(), true
}

func (p *props) binary(id uint16) ([]byte, bool) {
	if p.varLoad == nil {
		return nil, false
	}
	return p.varLoad(uint32(id)<<16 | ptBinary)
}

// str reads a string property in its Unicode form, else its 8-bit form decoded
// with the object's code page.
func (p *props) str(id uint16) (string, bool) {
	if p.varLoad == nil {
		return "", false
	}
	if b, ok := p.varLoad(uint32(id)<<16 | ptUnicode); ok {
		return utf16String(b), true
	}
	if b, ok := p.varLoad(uint32(id)<<16 | ptString8); ok {
		return decodeText("text/plain", p.charset, "codepage", trimNUL(b), p.part, p.warn).content, true
	}
	return "", false
}

// rawString reads the 8-bit form of a string property undecoded, else the
// Unicode form as UTF-8 (used for transport headers, which the header reader
// decodes itself).
func (p *props) rawString(id uint16) ([]byte, bool) {
	if p.varLoad == nil {
		return nil, false
	}
	if b, ok := p.varLoad(uint32(id)<<16 | ptUnicode); ok {
		return []byte(utf16String(b)), true
	}
	if b, ok := p.varLoad(uint32(id)<<16 | ptString8); ok {
		return trimNUL(b), true
	}
	return nil, false
}

func utf16String(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u))
}

func trimNUL(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

// msgReader reads the objects of one .msg compound file.
type msgReader struct {
	st *state
	f  *cfb.File
}

// parseMSG opens a .msg held in b.
func (st *state) parseMSG(b []byte, depth int) (*Message, error) {
	// The entry limit follows the file: a valid .msg with many recipients
	// holds far more than cfb's default 4,096 entries, and Open's work is
	// bounded by the file size anyway.
	f, err := cfb.OpenBytes(b, cfb.Limits{MaxSize: int64(len(b)) + 1, MaxEntries: len(b)/128 + 1})
	if err != nil {
		return nil, err
	}
	if f.Root.Child(propsStream) == nil {
		return nil, fmt.Errorf("no %s at the root", propsStream)
	}
	r := &msgReader{st: st, f: f}
	m := r.message(f.Root, 32, depth, "msg")
	m.Size = int64(len(b))
	warn := warner(m)
	for _, is := range f.Issues {
		warn(Warning{Code: WarnCFBDamaged, Detail: "compound file: " + is.Code + ": " + is.Detail, Part: "msg"})
	}
	return m, nil
}

// read reads one stream, charging it to the shared decoded budget. Reading
// stops once the budget is spent, so entries pointing at one large chain
// cannot multiply the work.
func (r *msgReader) read(e *cfb.Entry, part string, warn func(Warning)) ([]byte, bool) {
	if r.st.decoded >= r.st.opt.MaxDecoded {
		r.st.limitWarn(part, warn)
		return nil, false
	}
	data, err := r.f.ReadStream(e)
	if err != nil {
		if !errors.Is(err, cfb.ErrTruncated) {
			return nil, false
		}
		warn(Warning{Code: WarnCFBDamaged, Detail: "stream " + safeToken(e.Name) + " is shorter than declared; the bytes present were kept", Part: part})
	}
	return r.st.budgeted(data, part, warn), true
}

// object loads the property stream of a storage. hdr is the size of the
// stream's header: 32 for the top message, 24 for an embedded message, 8 for
// recipients and attachments (MS-OXMSG 2.4).
func (r *msgReader) object(dir *cfb.Entry, hdr int, part string, warn func(Warning)) (*props, []byte) {
	p := &props{fixed: map[uint32][8]byte{}, part: part, warn: warn}
	p.varHas = func(tag uint32) bool { return dir.Child(fmt.Sprintf("__substg1.0_%08X", tag)) != nil }
	p.varLoad = func(tag uint32) ([]byte, bool) {
		e := dir.Child(fmt.Sprintf("__substg1.0_%08X", tag))
		if e == nil || e.Type != cfb.TypeStream {
			return nil, false
		}
		return r.read(e, part, warn)
	}
	ps := dir.Child(propsStream)
	if ps == nil {
		warn(Warning{Code: WarnMSGStructure, Detail: "a storage has no property stream; only its variable-length properties were read", Part: part})
		return p, nil
	}
	data, ok := r.read(ps, part, warn)
	if !ok {
		return p, nil
	}
	if len(data) < hdr {
		warn(Warning{Code: WarnMSGStructure, Detail: fmt.Sprintf("a property stream of %d bytes is shorter than its %d-byte header", len(data), hdr), Part: part})
		return p, nil
	}
	head := data[:hdr]
	body := data[hdr:]
	if len(body)%16 != 0 {
		warn(Warning{Code: WarnMSGStructure, Detail: fmt.Sprintf("a property stream ends inside an entry; %d trailing bytes were skipped", len(body)%16), Part: part})
	}
	for i := 0; i+16 <= len(body); i += 16 {
		var v [8]byte
		copy(v[:], body[i+8:i+16])
		p.fixed[binary.LittleEndian.Uint32(body[i:])] = v
	}
	return p, head
}

// message reads a message object (the top one or an embedded one).
func (r *msgReader) message(dir *cfb.Entry, hdr, depth int, part string) *Message {
	m := &Message{Format: FormatMSG, Bodies: []Body{}, Attachments: []Attachment{}, Warnings: []Warning{}}
	warn := warner(m)
	p, _ := r.object(dir, hdr, part, warn)
	// MS-OXCMSG: PidTagMessageCodepage is the code page of the 8-bit string
	// properties; PidTagInternetCodepage that of the body and HTML.
	msgCP, internetCP := cpCharset(p, pidMessageCodepage), cpCharset(p, pidInternetCodepage)
	p.charset = firstNonEmpty(msgCP, internetCP)
	p.bodyCharset = firstNonEmpty(internetCP, msgCP)
	p.htmlCharset = p.bodyCharset

	if raw, ok := p.rawString(pidTransportHeaders); ok && len(strings.TrimSpace(string(raw))) > 0 {
		h, _ := r.st.readHeader(append(raw, "\r\n\r\n"...), part+"/headers", warn)
		m.Header = h
		r.st.fillIdentity(m, warn)
		compareIdentity(m, p, part, warn)
	} else {
		warn(Warning{Code: WarnNoTransportHeaders, Detail: "the message has no internet headers (no Received fields); sender, recipients, subject and date were taken from MAPI properties", Part: part})
		r.identityFromProps(m, p, dir, part, warn)
	}

	r.st.propBodies(m, p, part, warn)
	r.attachments(m, dir, depth, part, p.charset, warn)
	return m
}

// identityFromProps fills the identity fields of a message without transport
// headers. From is the "sent representing" mailbox Outlook displays; Sender is
// the mailbox that sent it, kept when it differs.
func (r *msgReader) identityFromProps(m *Message, p *props, dir *cfb.Entry, part string, warn func(Warning)) {
	identityFromProps(m, p, part, warn)
	var recips []*props
	for _, c := range sortedChildren(dir, recipPrefix) {
		if c.Type != cfb.TypeStorage {
			continue
		}
		q, _ := r.object(c, 8, part+"/recip/"+childIndex(c.Name, recipPrefix), warn)
		q.charset = p.charset
		recips = append(recips, q)
	}
	setRecipients(m, recips, part, warn)
}

func cpCharset(p *props, id uint16) string {
	if cp, ok := p.int32(id); ok {
		return codePageCharset(cp)
	}
	return ""
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// compareIdentity warns when the sender or subject Outlook displays (MAPI
// properties) differs from the internet headers the message was read from.
func compareIdentity(m *Message, p *props, part string, warn func(Warning)) {
	if subj, ok := p.str(pidSubject); ok && strings.TrimSpace(subj) != strings.TrimSpace(m.Subject) {
		warn(Warning{Code: WarnHeaderMismatch, Detail: "the MAPI subject differs from the Subject header", Part: part})
	}
	mapiFrom := mapiMailbox(p, pidSentRepName, pidSentRepEmail, pidSentRepSMTP, part, nil)
	if len(mapiFrom.Mailboxes) == 0 || mapiFrom.Mailboxes[0].Address == "" {
		return
	}
	want := strings.ToLower(mapiFrom.Mailboxes[0].Address)
	for _, l := range m.From {
		for _, mb := range l.Mailboxes {
			if strings.ToLower(mb.Address) == want {
				return
			}
		}
	}
	warn(Warning{Code: WarnHeaderMismatch, Detail: "the MAPI sender address differs from every From address in the headers", Part: part})
}

// identityFromProps fills sender, subject, message ID and date from MAPI
// properties (.msg without transport headers, TNEF).
func identityFromProps(m *Message, p *props, part string, warn func(Warning)) {
	from := mapiMailbox(p, pidSentRepName, pidSentRepEmail, pidSentRepSMTP, part, warn)
	sender := mapiMailbox(p, pidSenderName, pidSenderEmail, pidSenderSMTP, part, warn)
	if from.Raw == "" {
		from = sender
	}
	if from.Raw != "" {
		m.From = []AddressList{from}
	}
	if sender.Raw != "" && sender.Raw != from.Raw {
		m.Sender = []AddressList{sender}
	}
	m.Subject, _ = p.str(pidSubject)
	m.MessageID, _ = p.str(pidInternetMessageID)
	if t, ok := p.time(pidClientSubmitTime); ok {
		m.Date = t
	} else if t, ok := p.time(pidDeliveryTime); ok {
		m.Date = t
	}
}

// setRecipients sorts recipient objects into To, Cc and Bcc by
// PidTagRecipientType.
func setRecipients(m *Message, recips []*props, part string, warn func(Warning)) {
	var to, cc, bcc []AddressList
	for _, q := range recips {
		mb := mapiMailbox(q, pidDisplayName, pidEmailAddress, pidSMTPAddress, q.part, warn)
		if mb.Raw == "" {
			warn(Warning{Code: WarnRecipientType, Detail: "a recipient with no name or address was skipped", Part: q.part})
			continue
		}
		typ, _ := q.int32(pidRecipientType)
		switch t := typ & 0x0FFFFFFF; t { // high bits are flags (MAPI_P1, MAPI_SUBMITTED)
		case 1:
			to = append(to, mb)
		case 2:
			cc = append(cc, mb)
		case 3:
			bcc = append(bcc, mb)
		default:
			warn(Warning{Code: WarnRecipientType, Detail: fmt.Sprintf("a recipient of type %d was read as To", t), Part: q.part})
			to = append(to, mb)
		}
	}
	m.To, m.Cc, m.Bcc = joinLists(to), joinLists(cc), joinLists(bcc)
}

// mapiMailbox builds an address list of one mailbox from a display name, an
// address of any type (an Exchange "/O=..." DN is kept as written in Raw) and
// an SMTP address.
// A mailbox that shows one SMTP address and carries a different one is
// reported (warn may be nil when only comparing).
func mapiMailbox(p *props, nameID, emailID, smtpID uint16, part string, warn func(Warning)) AddressList {
	name, _ := p.str(nameID)
	email, _ := p.str(emailID)
	smtp, _ := p.str(smtpID)
	addr := smtp
	if !strings.Contains(addr, "@") {
		addr = ""
		if strings.Contains(email, "@") && !strings.HasPrefix(email, "/") {
			addr = email
		}
	} else if warn != nil && strings.Contains(email, "@") && !strings.HasPrefix(email, "/") && !strings.EqualFold(email, smtp) {
		warn(Warning{Code: WarnAddressMismatch, Detail: "a mailbox shows one address and carries a different SMTP address; Address holds the SMTP one, Raw the shown one", Part: part})
	}
	shown := email
	if shown == "" {
		shown = addr
	}
	raw := name
	switch {
	case raw == "":
		raw = shown
	case shown != "":
		raw += " <" + shown + ">"
	}
	if raw == "" {
		return AddressList{}
	}
	return AddressList{Raw: raw, Mailboxes: []Mailbox{{Name: name, Address: addr}}, Parsed: addr != ""}
}

// joinLists makes the recipients of one type a single list, as one header
// field would hold them.
func joinLists(ls []AddressList) []AddressList {
	if len(ls) == 0 {
		return nil
	}
	out := AddressList{Parsed: true}
	var raws []string
	for _, l := range ls {
		raws = append(raws, l.Raw)
		out.Mailboxes = append(out.Mailboxes, l.Mailboxes...)
		out.Parsed = out.Parsed && l.Parsed
	}
	out.Raw = strings.Join(raws, ", ")
	return []AddressList{out}
}

func sortedChildren(dir *cfb.Entry, prefix string) []*cfb.Entry {
	var out []*cfb.Entry
	for _, c := range dir.Children {
		if strings.HasPrefix(strings.ToLower(c.Name), strings.ToLower(prefix)) {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToUpper(out[i].Name) < strings.ToUpper(out[j].Name) })
	return out
}

// childIndex turns "__attach_version1.0_#0000000A" into "10".
func childIndex(name, prefix string) string {
	if n, err := strconv.ParseUint(name[len(prefix):], 16, 32); err == nil {
		return strconv.FormatUint(n, 10)
	}
	return safeToken(name[len(prefix):])
}

// propBodies adds the bodies a MAPI object holds: PidTagBody, PidTagHtml and,
// when present, the compressed RTF. Every source present is returned — an
// attacker can make them differ, and which one a client shows varies.
func (st *state) propBodies(m *Message, p *props, part string, warn func(Warning)) {
	bodyCS := firstNonEmpty(p.bodyCharset, p.charset)
	if b, ok := p.varLoad(uint32(pidBody)<<16 | ptUnicode); ok {
		for len(b) >= 2 && b[len(b)-1] == 0 && b[len(b)-2] == 0 {
			b = b[:len(b)-2]
		}
		m.Bodies = append(m.Bodies, Body{MediaType: "text/plain", Content: utf16String(b), Charset: "utf-16le", CharsetSource: "unicode", Size: len(b), Part: part + "/body"})
	} else if b, ok := p.rawString(pidBody); ok {
		r := decodeText("text/plain", bodyCS, "codepage", b, part+"/body", warn)
		m.Bodies = append(m.Bodies, Body{MediaType: "text/plain", Content: r.content, Charset: r.charset, CharsetSource: r.source, Size: len(b), Part: part + "/body"})
	}
	html, ok := p.binary(pidHTML)
	if !ok {
		html, ok = p.rawString(pidHTML)
	}
	if ok {
		r := decodeText("text/html", firstNonEmpty(p.htmlCharset, bodyCS), "codepage", trimNUL(html), part+"/html", warn)
		m.Bodies = append(m.Bodies, Body{MediaType: "text/html", Content: r.content, Charset: r.charset, CharsetSource: r.source, Size: len(html), Part: part + "/html"})
	}
	if rtf, ok := p.binary(pidRTFCompressed); ok {
		st.rtfBody(m, rtf, part+"/rtf", warn)
	}
}

// attachments reads the attachment storages of a message object.
// charset is the message's, reused for the attachments' 8-bit strings (they
// carry no code page of their own).
func (r *msgReader) attachments(m *Message, dir *cfb.Entry, depth int, part, charset string, warn func(Warning)) {
	for _, c := range sortedChildren(dir, attachPrefix) {
		if c.Type != cfb.TypeStorage {
			continue
		}
		ap := part + "/attach/" + childIndex(c.Name, attachPrefix)
		if !r.st.countPart(ap, warn) {
			return
		}
		q, _ := r.object(c, 8, ap, warn)
		q.charset = charset
		a := mapiAttachment(q, ap)
		method, hasMethod := q.int32(pidAttachMethod)
		switch {
		case method == attachEmbedded:
			sub := c.Child(embeddedMessageStorage)
			if sub == nil || sub.Type != cfb.TypeStorage {
				warn(Warning{Code: WarnMSGStructure, Detail: "an embedded-message attachment has no message storage", Part: ap})
				break
			}
			if a.MediaType == "" {
				a.MediaType = "application/vnd.ms-outlook"
			}
			if depth+1 > r.st.opt.MaxMessageDepth {
				warn(Warning{Code: WarnMessageDepthLimit, Detail: fmt.Sprintf("a message nested deeper than %d layers was not opened", r.st.opt.MaxMessageDepth), Part: ap})
				break
			}
			a.Message = r.message(sub, 24, depth+1, "msg")
		case method == attachByValue || !hasMethod:
			data, ok := q.binary(pidAttachData)
			if !ok {
				warn(Warning{Code: WarnMSGStructure, Detail: "an attachment has no data stream (and no method saying where its bytes are)", Part: ap})
				break
			}
			a.Data, a.Size = data, len(data)
			if a.MediaType == "" {
				a.MediaType = "application/octet-stream"
			}
			a.Message = r.st.openByContent(data, a.MediaType, a.Filename, depth, ap, warn)
		default:
			what := "a reference to a file outside the message"
			if method == attachOLE {
				what = "an OLE object storage"
			}
			warn(Warning{Code: WarnAttachmentNotExtracted, Detail: fmt.Sprintf("attachment method %d (%s); no bytes were extracted", method, what), Part: ap})
		}
		m.Attachments = append(m.Attachments, a)
	}
}

func mapiAttachment(q *props, part string) Attachment {
	a := Attachment{Part: part}
	a.Filename, _ = q.str(pidAttachLongFilename)
	if a.Filename == "" {
		a.Filename, _ = q.str(pidAttachFilename)
	}
	if a.Filename == "" {
		a.Filename, _ = q.str(pidDisplayName)
	}
	a.MediaType, _ = q.str(pidAttachMIMETag)
	a.MediaType = strings.ToLower(strings.TrimSpace(a.MediaType))
	cid, _ := q.str(pidAttachContentID)
	a.ContentID = strings.Trim(cid, "<>")
	flags, _ := q.int32(pidAttachFlags)
	a.Inline = q.boolean(pidAttachmentHidden) || flags&0x4 != 0 // attRenderedInBody
	a.Disposition = "attachment"
	if a.Inline {
		a.Disposition = "inline"
	}
	return a
}

// countPart charges one part against MaxParts.
func (st *state) countPart(p string, warn func(Warning)) bool {
	st.parts++
	if st.parts > st.opt.MaxParts {
		if st.parts == st.opt.MaxParts+1 {
			warn(Warning{Code: WarnPartLimit, Detail: fmt.Sprintf("parts after the first %d were not read", st.opt.MaxParts), Part: p})
		}
		return false
	}
	return true
}

// limitWarn reports, once per parse, that reading stopped at MaxDecoded.
func (st *state) limitWarn(p string, warn func(Warning)) {
	if st.limitHit {
		return
	}
	st.limitHit = true
	warn(Warning{Code: WarnDecodedLimit, Detail: fmt.Sprintf("decoded data beyond %d bytes in all was not kept; later streams were not read", st.opt.MaxDecoded), Part: p})
}

// openByContent opens attachment bytes that are a message, recognized by
// content: a .msg or TNEF always, an .eml when its type or name says message.
func (st *state) openByContent(data []byte, mediaType, filename string, depth int, p string, warn func(Warning)) *Message {
	switch f := Detect(data); f {
	case FormatEML:
		if mediaType == "application/octet-stream" || mediaType == "text/plain" || hasMessageExt(filename) || strings.HasPrefix(mediaType, "message/") {
			return st.nested(data, f, depth, p, warn)
		}
	case FormatMSG, FormatTNEF:
		return st.nested(data, f, depth, p, warn)
	}
	return nil
}

// ParseMSG reads an Outlook .msg file.
func ParseMSG(r io.Reader, opt Options) (*Message, error) {
	opt = opt.withDefaults()
	b, err := readLimited(r, opt.MaxSize)
	if err != nil {
		return nil, err
	}
	st := &state{opt: opt}
	m, err := st.parseMSG(b, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: .msg unreadable: %v", ErrNotMessage, err)
	}
	return m, nil
}
