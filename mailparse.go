package mailparse

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
	DefaultMaxSize         = 30 << 20
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
	MaxDecoded      int64 // decoded bytes across every layer
	MaxHeaders      int   // header fields per header block
	MaxHeaderBytes  int   // header bytes per header block
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
	// ReturnPath is each Return-Path value as written (unfolded).
	ReturnPath []string `json:"return_path,omitempty"`
	// Subject, MessageID and Date come from the first occurrence; the Header
	// keeps the others, and a duplicate is warned about.
	Subject   string    `json:"subject,omitempty"`
	MessageID string    `json:"message_id,omitempty"`
	Date      time.Time `json:"date,omitzero"`
	DateRaw   string    `json:"date_raw,omitempty"`

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
type Mailbox struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
}

// Body is one text part, converted to UTF-8.
type Body struct {
	MediaType string `json:"media_type"` // text/plain or text/html
	Content   string `json:"content"`
	Charset   string `json:"charset"`
	// CharsetSource says how Charset was decided: "mime" (the Content-Type
	// parameter), "meta" (HTML <meta>), "codepage" (a .msg code page),
	// "unicode" (a .msg Unicode property), "default" (US-ASCII by RFC 2045), or
	// "guessed".
	CharsetSource string `json:"charset_source"`
	Size          int    `json:"size"` // decoded bytes before charset conversion
	// Part names where the body came from: a MIME part path ("1.2"), or for a
	// .msg or TNEF the property ("msg/body", "msg/html", "msg/rtf",
	// "tnef/body"; "msg/attach/2/body" inside an embedded message).
	Part string `json:"part"`
}

// Attachment is one non-body part. Data holds its decoded bytes (a copy).
type Attachment struct {
	Filename    string `json:"filename,omitempty"`
	MediaType   string `json:"media_type"`
	Disposition string `json:"disposition,omitempty"`
	ContentID   string `json:"content_id,omitempty"`
	Inline      bool   `json:"inline,omitempty"`
	Size        int    `json:"size"`
	Data        []byte `json:"-"`
	Part        string `json:"part"`
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
		return nil, ErrNotMessage
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
