package mailparse

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Format is what Detect recognized.
type Format string

// Formats.
const (
	FormatEML     Format = "eml"
	FormatMSG     Format = "msg"
	FormatTNEF    Format = "tnef"
	FormatUnknown Format = "unknown"
)

// Errors. Everything else a parse meets is a Warning, not an error.
var (
	ErrTooLarge   = errors.New("mailparse: input is larger than Options.MaxSize")
	ErrNotMessage = errors.New("mailparse: input is not a recognized message")
)

// Default limits (the RFP §2 table).
const (
	DefaultMaxSize         = 64 << 20 // a 25 MB attachment is about 34 MB in Base64; providers accept up to 50 MB and more
	DefaultMaxMessageDepth = 3
	DefaultMaxMIMEDepth    = 32
	DefaultMaxParts        = 1000
	DefaultMaxDecoded      = 120 << 20
	DefaultMaxHeaders      = 2000
	DefaultMaxHeaderBytes  = 1 << 20
)

// Options bound one parse. A zero field takes its default.
type Options struct {
	MaxSize         int64 // the whole input; beyond it, ErrTooLarge
	MaxMessageDepth int   // layers of nested messages opened below the top one
	MaxMIMEDepth    int   // depth of the MIME tree within one message
	MaxParts        int   // parts across every layer
	MaxDecoded      int64 // decoded bytes kept across every layer (an attached message's bytes and its parts each count)
	MaxHeaders      int   // header fields per header block
	MaxHeaderBytes  int   // header bytes per header block

	// AssumeEML reads input that Detect does not recognize as an RFC 5322
	// message anyway, with a not_detected_as_mail warning, instead of
	// returning ErrNotMessage. Set it when the caller knows the input is mail
	// (a .eml argument, a mail tool's stdin): Detect refuses some minimal mail
	// (cron's "From: root", no From at all, one well-known field). Input with
	// no header field at all is still ErrNotMessage. .msg and TNEF are not
	// affected.
	AssumeEML bool
}

func (o Options) withDefaults() Options {
	if o.MaxSize <= 0 {
		o.MaxSize = DefaultMaxSize
	}
	if o.MaxMessageDepth <= 0 {
		o.MaxMessageDepth = DefaultMaxMessageDepth
	}
	if o.MaxMIMEDepth <= 0 {
		o.MaxMIMEDepth = DefaultMaxMIMEDepth
	}
	if o.MaxParts <= 0 {
		o.MaxParts = DefaultMaxParts
	}
	if o.MaxDecoded <= 0 {
		o.MaxDecoded = DefaultMaxDecoded
	}
	if o.MaxHeaders <= 0 {
		o.MaxHeaders = DefaultMaxHeaders
	}
	if o.MaxHeaderBytes <= 0 {
		o.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	return o
}

// Message is one parsed message.
type Message struct {
	Format Format `json:"format"`
	Size   int64  `json:"size"`
	// Header holds every field of the top header block, in order, duplicates kept.
	Header Header `json:"header"`
	// One AddressList per occurrence of the field: a duplicated From is two
	// entries, each with all of its mailboxes.
	From    []AddressList `json:"from,omitempty"`
	Sender  []AddressList `json:"sender,omitempty"`
	ReplyTo []AddressList `json:"reply_to,omitempty"`
	To      []AddressList `json:"to,omitempty"`
	Cc      []AddressList `json:"cc,omitempty"`
	Bcc     []AddressList `json:"bcc,omitempty"`
	// ReturnPath holds each Return-Path field, parsed like the address fields;
	// a null reverse path "<>" (a bounce) has no mailboxes and Parsed true.
	ReturnPath []AddressList `json:"return_path,omitempty"`
	// Subject, MessageID and Date come from the first occurrence; the Header
	// keeps the others, and a duplicate is warned about.
	Subject   string    `json:"subject,omitempty"`
	MessageID string    `json:"message_id,omitempty"`
	Date      time.Time `json:"date,omitzero"`
	DateRaw   string    `json:"date_raw,omitempty"`
	// InReplyTo and References are the In-Reply-To and References fields
	// unfolded as written (message IDs in angle brackets); for a .msg or TNEF
	// without internet headers, PidTagInReplyToId and PidTagInternetReferences.
	InReplyTo  string `json:"in_reply_to,omitempty"`
	References string `json:"references,omitempty"`

	Bodies      []Body       `json:"bodies"`
	Attachments []Attachment `json:"attachments"`
	Parts       *Part        `json:"parts,omitempty"`
	Warnings    []Warning    `json:"warnings"`
}

// AddressList is one occurrence of an address field.
type AddressList struct {
	Raw       string    `json:"raw"`
	Mailboxes []Mailbox `json:"mailboxes"`
	// Parsed is false when the field did not parse as RFC 5322 and a lenient
	// reading produced Mailboxes.
	Parsed bool `json:"parsed"`
}

// Mailbox is one address. Name is the decoded display name; it is attacker text
// and may itself contain something that looks like an address.
//
// Address is empty when none was found: a lenient reading of a field that did
// not parse may yield only a name, and a .msg or TNEF mailbox may carry only an
// Exchange DN ("/O=...", kept in the AddressList's Raw). Raw then holds what was
// written.
type Mailbox struct {
	Name    string `json:"name,omitempty"` // decoded display name: attacker text that may look like an address
	Address string `json:"address"`
}

// String writes the mailbox in RFC 5322 form. A display name holding anything
// but atom characters and spaces is written as a quoted-string, so a name that
// decodes to "Bank <security@bank.example>" stays a name when the result is
// parsed again — joining Name and Address naively re-creates the spoof the
// parser prevented. A mailbox with no address is its quoted name alone (never
// "<>"); line breaks and other control characters in a name become spaces.
func (mb Mailbox) String() string {
	switch {
	case mb.Address == "" && mb.Name == "":
		return ""
	case mb.Address == "":
		return quoteName(mb.Name)
	case mb.Name == "":
		return mb.Address
	}
	return quoteName(mb.Name) + " <" + mb.Address + ">"
}

// quoteName returns a display name as an RFC 5322 phrase: as is when it is
// atoms (RFC 6532 non-ASCII included) and spaces, else a quoted-string.
func quoteName(name string) string {
	clean := []rune{}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		clean = append(clean, r)
	}
	name = string(clean)
	plain := strings.TrimSpace(name) == name && name != ""
	for _, r := range name {
		if r >= 0x80 || r == ' ' || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') || strings.ContainsRune("!#$%&'*+-/=?^_`{|}~", r) {
			continue
		}
		plain = false
		break
	}
	if plain {
		return name
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(name) + `"`
}

// Body is one text part, converted to UTF-8.
type Body struct {
	MediaType string `json:"media_type"` // text/plain or text/html
	Content   string `json:"content"`
	Charset   string `json:"charset"`
	// CharsetSource says how Charset was decided: "mime" (the Content-Type
	// parameter), "meta" (HTML <meta>), "codepage" (a .msg or TNEF code page),
	// "unicode" (a Unicode MAPI property), "rtf" (the RTF \ansicpg), "default"
	// (US-ASCII by RFC 2045), or "guessed".
	CharsetSource string `json:"charset_source"`
	Size          int    `json:"size"` // decoded bytes before charset conversion
	// Part names where the body came from: a MIME part path ("1.2"), or for a
	// .msg or TNEF the property ("msg/body", "msg/html", "msg/rtf",
	// "tnef/body"). A nested message names its parts from its own root.
	Part string `json:"part"`
	// Origin names the kind of source: "mime" (a MIME part), "mapi" (a .msg or
	// TNEF body property: PidTagBody, PidTagHtml), "rtf" (recovered from
	// compressed RTF — in a .msg usually a copy of a "mapi" body), or "tnef"
	// (TNEF's legacy attBody).
	Origin string `json:"origin"`
}

// Attachment is one non-body part. Data holds its decoded bytes (a copy).
type Attachment struct {
	Filename    string `json:"filename,omitempty"`
	MediaType   string `json:"media_type"`
	Disposition string `json:"disposition,omitempty"`
	ContentID   string `json:"content_id,omitempty"`
	Inline      bool   `json:"inline,omitempty"`
	Size        int    `json:"size"`
	// Charset is the charset a text/* attachment declared ("" otherwise);
	// Text converts the attachment with it.
	Charset string `json:"charset,omitempty"`
	Data    []byte `json:"-"`
	Part    string `json:"part"`
	// Message is the parsed message when the attachment is itself a message
	// (message/rfc822, or recognized by content) and the depth limit allowed
	// opening it.
	Message *Message `json:"message,omitempty"`
}

// Part is one node of the MIME tree.
type Part struct {
	Path             string            `json:"path"`
	MediaType        string            `json:"media_type"`
	Params           map[string]string `json:"params,omitempty"`
	Disposition      string            `json:"disposition,omitempty"`
	TransferEncoding string            `json:"transfer_encoding,omitempty"`
	Header           Header            `json:"header"`
	Children         []*Part           `json:"children,omitempty"`
}

// state is one parse's shared budget, carried into every nested message.
// maxWarningsPerCode bounds how many warnings of one code a message keeps: a
// hostile input can repeat one fault millions of times. Past it, one
// warning_limit warning says so.
const maxWarningsPerCode = 100

// warner returns the function that records warnings for m, capped per code.
func warner(m *Message) func(Warning) {
	counts := map[string]int{}
	return func(w Warning) {
		counts[w.Code]++
		switch n := counts[w.Code]; {
		case n <= maxWarningsPerCode:
			m.Warnings = append(m.Warnings, w)
		case n == maxWarningsPerCode+1:
			m.Warnings = append(m.Warnings, Warning{Code: WarnWarningLimit, Detail: fmt.Sprintf("further %s warnings after the first %d were not recorded", w.Code, maxWarningsPerCode), Part: w.Part})
		}
	}
}

type state struct {
	opt      Options
	decoded  int64
	parts    int
	limitHit bool // the MaxDecoded warning for skipped streams was given
}

// Parse reads r (at most Options.MaxSize bytes), recognizes the format and
// parses it.
func Parse(r io.Reader, opt Options) (*Message, error) {
	b, err := readLimited(r, opt.withDefaults().MaxSize)
	if err != nil {
		return nil, err
	}
	return ParseBytes(b, opt)
}

// ParseBytes recognizes the format of b and parses it.
func ParseBytes(b []byte, opt Options) (*Message, error) {
	opt = opt.withDefaults()
	if int64(len(b)) > opt.MaxSize {
		return nil, ErrTooLarge
	}
	switch Detect(b) {
	case FormatEML:
		st := &state{opt: opt}
		return st.parseEML(b, 0), nil
	case FormatMSG:
		st := &state{opt: opt}
		m, err := st.parseMSG(b, 0)
		if err != nil {
			return nil, fmt.Errorf("%w: .msg unreadable: %v", ErrNotMessage, err)
		}
		return m, nil
	case FormatTNEF:
		st := &state{opt: opt}
		m, err := st.parseTNEF(b, 0, "tnef")
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotMessage, err)
		}
		return m, nil
	default:
		if !opt.AssumeEML {
			return nil, ErrNotMessage
		}
		st := &state{opt: opt}
		m := st.parseEML(b, 0)
		if len(m.Header) == 0 {
			return nil, ErrNotMessage
		}
		m.Warnings = append([]Warning{{Code: WarnNotDetected, Detail: "the input was not recognized as mail; it was read as RFC 5322 because Options.AssumeEML is set"}}, m.Warnings...)
		return m, nil
	}
}

// ParseEML parses r as RFC 5322 without recognizing it first: the caller says
// it is a message. Use Parse when the input could be anything.
func ParseEML(r io.Reader, opt Options) (*Message, error) {
	opt = opt.withDefaults()
	b, err := readLimited(r, opt.MaxSize)
	if err != nil {
		return nil, err
	}
	st := &state{opt: opt}
	return st.parseEML(b, 0), nil
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	var buf bytes.Buffer
	n, err := buf.ReadFrom(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if n > max {
		return nil, ErrTooLarge
	}
	return buf.Bytes(), nil
}
