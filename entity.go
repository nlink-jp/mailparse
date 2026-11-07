package mailparse

import (
	"bytes"
	"fmt"
	"net/mail"
	"path"
	"strconv"
	"strings"
)

// singletonFields are the fields RFC 5322 §3.6 allows at most once; a second
// one is a fact worth a warning (a forged one placed first must not hide it).
var singletonFields = []string{"From", "Sender", "Reply-To", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID", "In-Reply-To", "References"}

// parseEML parses one RFC 5322 message at nesting depth depth (0 = top).
func (st *state) parseEML(b []byte, depth int) *Message {
	m := &Message{Format: FormatEML, Size: int64(len(b)), Bodies: []Body{}, Attachments: []Attachment{}, Warnings: []Warning{}}
	warn := warner(m)
	if bytes.HasPrefix(b, []byte("\xEF\xBB\xBF")) {
		b = b[3:]
		warn(Warning{Code: WarnLeadingBOM, Detail: "the message started with a UTF-8 byte order mark; it was skipped", Part: ""})
	}

	h, body := st.readHeader(b, "", warn)
	m.Header = h
	st.fillIdentity(m, warn)
	m.Parts = st.entity(m, h, body, "", 0, depth, "", warn)
	return m
}

func (st *state) fillIdentity(m *Message, warn func(Warning)) {
	for _, f := range m.Header {
		switch strings.ToLower(f.Name) {
		case "from":
			m.From = append(m.From, parseAddressList(f, "", warn))
		case "sender":
			m.Sender = append(m.Sender, parseAddressList(f, "", warn))
		case "reply-to":
			m.ReplyTo = append(m.ReplyTo, parseAddressList(f, "", warn))
		case "to":
			m.To = append(m.To, parseAddressList(f, "", warn))
		case "cc":
			m.Cc = append(m.Cc, parseAddressList(f, "", warn))
		case "bcc":
			m.Bcc = append(m.Bcc, parseAddressList(f, "", warn))
		case "return-path":
			m.ReturnPath = append(m.ReturnPath, returnPath(f, warn))
		}
	}
	if f, ok := m.Header.First("Subject"); ok {
		m.Subject = f.Value
	}
	if f, ok := m.Header.First("Message-ID"); ok {
		m.MessageID = unfold([]byte(f.Raw))
	}
	if f, ok := m.Header.First("In-Reply-To"); ok {
		m.InReplyTo = collapse(unfold([]byte(f.Raw)))
	}
	if f, ok := m.Header.First("References"); ok {
		m.References = collapse(unfold([]byte(f.Raw)))
	}
	if f, ok := m.Header.First("Date"); ok {
		m.DateRaw = unfold([]byte(f.Raw))
		if t, err := mail.ParseDate(m.DateRaw); err == nil {
			m.Date = t
		} else {
			warn(Warning{Code: WarnInvalidDate, Detail: "the Date field did not parse; date_raw keeps it"})
		}
	}
	for _, name := range singletonFields {
		if n := len(m.Header.All(name)); n > 1 {
			warn(Warning{Code: WarnDuplicateField, Detail: fmt.Sprintf("%s appears %d times; every occurrence is kept", name, n)})
		}
	}
}

// returnPath reads a Return-Path value: one address in angle brackets, or "<>"
// for a null reverse path (a bounce), which is valid and holds no mailbox.
func returnPath(f Field, warn func(Warning)) AddressList {
	if v := strings.TrimSpace(unfold([]byte(f.Raw))); v == "<>" {
		return AddressList{Raw: v, Mailboxes: []Mailbox{}, Parsed: true}
	}
	return parseAddressList(f, "", warn)
}

// childPath names the i-th (1-based) child of parent.
func childPath(parent string, i int) string {
	if parent == "" {
		return strconv.Itoa(i)
	}
	return parent + "." + strconv.Itoa(i)
}

// entity reads one MIME entity (the top body or a part) into m and returns its
// node. Recursion is bounded: MIME depth by MaxMIMEDepth, nested messages by
// MaxMessageDepth (each nested message starts its own MIME depth), so the
// deepest call chain is about (MaxMessageDepth+1)·(MaxMIMEDepth+1) frames.
func (st *state) entity(m *Message, h Header, body []byte, p string, mimeDepth, msgDepth int, defaultType string, warn func(Warning)) *Part {
	node := &Part{Path: p, Header: h}
	st.parts++
	if st.parts > st.opt.MaxParts {
		if st.parts == st.opt.MaxParts+1 {
			warn(Warning{Code: WarnPartLimit, Detail: fmt.Sprintf("parts after the first %d were not read", st.opt.MaxParts), Part: p})
		}
		node.MediaType = "unread"
		return node
	}

	for _, name := range []string{"Content-Type", "Content-Transfer-Encoding", "Content-Disposition"} {
		if n := len(h.All(name)); n > 1 {
			warn(Warning{Code: WarnDuplicateField, Detail: fmt.Sprintf("%s appears %d times in one entity; the first was used", name, n), Part: p})
		}
	}
	mediaType, params := st.contentType(h, p, defaultType, warn)
	node.MediaType, node.Params = mediaType, params
	cte := ""
	if f, ok := h.First("Content-Transfer-Encoding"); ok {
		cte = strings.ToLower(f.Value)
	}
	node.TransferEncoding = cte
	disp, dparams := "", map[string]string{}
	if f, ok := h.First("Content-Disposition"); ok {
		d, dp, problems := parseParams(f.Value)
		for _, pr := range problems {
			warn(Warning{Code: WarnInvalidParameters, Detail: "Content-Disposition: " + pr, Part: p})
		}
		disp, dparams = d, dp
	}
	node.Disposition = disp

	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		if !st.multipart(m, node, params, body, p, mimeDepth, msgDepth, warn) {
			// Not split: a lenient client may still show it, so its bytes are
			// returned rather than dropped.
			data := st.budgeted(body, p, warn)
			m.Attachments = append(m.Attachments, st.attachment(h, mediaType, disp, "", data, p))
		}
		return node
	case mediaType == "message/rfc822" || mediaType == "message/global":
		data := st.budgeted(decodeTransfer(cte, body, p, warn), p, warn)
		att := st.attachment(h, mediaType, disp, filenameOf(dparams, params, p, warn), data, p)
		att.Message = st.nested(data, FormatEML, msgDepth, p, warn)
		m.Attachments = append(m.Attachments, att)
		return node
	}

	data := st.budgeted(decodeTransfer(cte, body, p, warn), p, warn)
	filename := filenameOf(dparams, params, p, warn)
	isText := mediaType == "text/plain" || mediaType == "text/html"
	if isText && disp != "attachment" && filename == "" {
		r := toUTF8(mediaType, params["charset"], data, p, warn)
		m.Bodies = append(m.Bodies, Body{MediaType: mediaType, Content: r.content, Charset: r.charset, CharsetSource: r.source, Size: len(data), Part: p, Origin: "mime"})
		return node
	}
	att := st.attachment(h, mediaType, disp, filename, data, p)
	if strings.HasPrefix(mediaType, "text/") {
		att.Charset = params["charset"]
	}
	// A message attached under another type (application/octet-stream, a .eml
	// or .msg name) is recognized by content and opened.
	att.Message = st.openByContent(data, mediaType, filename, msgDepth, p, warn)
	m.Attachments = append(m.Attachments, att)
	return node
}

func hasMessageExt(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".eml", ".msg", ".mht":
		return true
	}
	return false
}

// contentType reads Content-Type; a missing one is text/plain (RFC 2045), or
// message/rfc822 inside multipart/digest.
func (st *state) contentType(h Header, p, defaultType string, warn func(Warning)) (string, map[string]string) {
	f, ok := h.First("Content-Type")
	if !ok || strings.TrimSpace(f.Value) == "" {
		if defaultType != "" {
			return defaultType, map[string]string{}
		}
		return "text/plain", map[string]string{}
	}
	mt, params, problems := parseParams(f.Value)
	for _, pr := range problems {
		warn(Warning{Code: WarnInvalidParameters, Detail: "Content-Type: " + pr, Part: p})
	}
	if t, sub, ok := strings.Cut(mt, "/"); !ok || t == "" || sub == "" || strings.ContainsAny(mt, " \t\"") {
		warn(Warning{Code: WarnInvalidContentType, Detail: "Content-Type did not parse; application/octet-stream was assumed", Part: p})
		return "application/octet-stream", params
	}
	return mt, params
}

// multipart splits and reads a multipart entity. It returns false when the
// content could not be split at all; the caller then keeps the bytes.
func (st *state) multipart(m *Message, node *Part, params map[string]string, body []byte, p string, mimeDepth, msgDepth int, warn func(Warning)) bool {
	if mimeDepth >= st.opt.MaxMIMEDepth {
		warn(Warning{Code: WarnMIMEDepthLimit, Detail: fmt.Sprintf("a multipart deeper than %d levels was not opened; its bytes are kept as one attachment", st.opt.MaxMIMEDepth), Part: p})
		return false
	}
	boundary := params["boundary"]
	if boundary == "" {
		warn(Warning{Code: WarnMissingBoundary, Detail: "a multipart has no boundary parameter; its bytes are kept as one attachment", Part: p})
		return false
	}
	// Collect no more parts than the part budget can still read: an input of
	// nothing but delimiter lines must not allocate a slice per line.
	parts, closed, afterClose, cut := splitMultipart(body, boundary, max(st.opt.MaxParts-st.parts, 0)+1)
	if len(parts) == 0 {
		warn(Warning{Code: WarnNoParts, Detail: "a multipart has no delimiter line for its boundary; its bytes are kept as one attachment", Part: p})
		return false
	}
	if !closed && !cut {
		warn(Warning{Code: WarnUnclosedBoundary, Detail: "a multipart ended without its closing delimiter; the parts read so far are kept", Part: p})
	}
	if afterClose {
		warn(Warning{Code: WarnPartsAfterClose, Detail: "delimiter lines follow the closing delimiter; the parts after it were read too", Part: p})
	}
	childDefault := ""
	if node.MediaType == "multipart/digest" {
		childDefault = "message/rfc822"
	}
	for i, raw := range parts {
		cp := childPath(p, i+1)
		ph, pbody := st.readHeader(raw, cp, warn)
		child := st.entity(m, ph, pbody, cp, mimeDepth+1, msgDepth, childDefault, warn)
		node.Children = append(node.Children, child)
		if st.parts >= st.opt.MaxParts && (i < len(parts)-1 || cut) {
			// Said here as well: the cut may have happened inside a nested
			// message, whose warning this message does not carry.
			warn(Warning{Code: WarnPartLimit, Detail: fmt.Sprintf("parts after the first %d in all were not read", st.opt.MaxParts), Part: p})
			return true
		}
	}
	return true
}

// splitMultipart splits a multipart body on its delimiter lines ("--boundary",
// transport padding allowed) and reports whether the closing delimiter
// ("--boundary--") came. The line break before a delimiter belongs to the
// delimiter. The preamble is dropped, as RFC 2046 says; after the closing
// delimiter, further delimiter lines start parts again (some clients show
// them) and afterClose says so. At most limit parts are collected; cut says
// more followed.
func splitMultipart(body []byte, boundary string, limit int) (parts [][]byte, closed, afterClose, cut bool) {
	delim := []byte("--" + boundary)
	start := -1 // start of the current part's content, -1 before the first delimiter
	pos := 0
	for pos <= len(body) {
		lineEnd := bytes.IndexByte(body[pos:], '\n')
		var line []byte
		next := len(body) + 1
		if lineEnd < 0 {
			line = body[pos:]
		} else {
			line = body[pos : pos+lineEnd]
			next = pos + lineEnd + 1
		}
		t := trimRightBytes(line, " \t\r")
		if bytes.HasPrefix(t, delim) {
			rest := t[len(delim):]
			closing := bytes.Equal(rest, []byte("--"))
			if closing || len(rest) == 0 {
				if start >= 0 {
					end := pos
					// The CRLF (or LF) before the delimiter belongs to it.
					if end > start && body[end-1] == '\n' {
						end--
						if end > start && body[end-1] == '\r' {
							end--
						}
					}
					if len(parts) == limit {
						return parts, closed, afterClose, true
					}
					parts = append(parts, body[start:end])
				}
				if closing {
					closed, start = true, -1
				} else {
					if closed {
						afterClose = true
					}
					start = min(next, len(body))
				}
			}
		}
		if lineEnd < 0 {
			break
		}
		pos = next
	}
	if start >= 0 && start <= len(body) {
		if len(parts) == limit {
			return parts, closed, afterClose, true
		}
		parts = append(parts, body[start:])
		if closed {
			closed = false // the parts after the close were not closed again
		}
	}
	return parts, closed, afterClose, false
}

// budgeted charges decoded bytes against the shared MaxDecoded and cuts what
// does not fit.
func (st *state) budgeted(data []byte, p string, warn func(Warning)) []byte {
	left := st.opt.MaxDecoded - st.decoded
	if int64(len(data)) <= left {
		st.decoded += int64(len(data))
		return data
	}
	if left < 0 {
		left = 0
	}
	warn(Warning{Code: WarnDecodedLimit, Detail: fmt.Sprintf("decoded data beyond %d bytes in all was not kept; this part was cut from %d to %d bytes", st.opt.MaxDecoded, len(data), left), Part: p})
	st.decoded = st.opt.MaxDecoded
	return data[:left]
}

func (st *state) attachment(h Header, mediaType, disp, filename string, data []byte, p string) Attachment {
	a := Attachment{
		Filename:    filename,
		MediaType:   mediaType,
		Disposition: disp,
		Inline:      disp == "inline",
		Size:        len(data),
		Data:        data,
		Part:        p,
	}
	if f, ok := h.First("Content-ID"); ok {
		a.ContentID = strings.Trim(unfold([]byte(f.Raw)), "<>")
	}
	return a
}

// filenameOf reads Content-Disposition's filename (RFC 2231 handled by
// mime.ParseMediaType), else Content-Type's name, and decodes RFC 2047 words
// mailers put there although the RFC does not allow it.
func filenameOf(dparams, params map[string]string, p string, warn func(Warning)) string {
	name := dparams["filename"]
	if name == "" {
		name = params["name"]
	}
	if strings.Contains(name, "=?") {
		name = decodeWords(name, "a filename", p, warn)
	}
	return name
}

// nested opens an attached message when the depth limit allows.
func (st *state) nested(data []byte, f Format, msgDepth int, p string, warn func(Warning)) *Message {
	if msgDepth+1 > st.opt.MaxMessageDepth {
		warn(Warning{Code: WarnMessageDepthLimit, Detail: fmt.Sprintf("a message nested deeper than %d layers was not opened", st.opt.MaxMessageDepth), Part: p})
		return nil
	}
	switch f {
	case FormatEML:
		return st.parseEML(data, msgDepth+1)
	case FormatMSG:
		m, err := st.parseMSG(data, msgDepth+1)
		if err != nil {
			warn(Warning{Code: WarnNestedUnreadable, Detail: "an attached .msg could not be read: " + err.Error(), Part: p})
			return nil
		}
		return m
	case FormatTNEF:
		m, err := st.parseTNEF(data, msgDepth+1, "tnef")
		if err != nil {
			warn(Warning{Code: WarnNestedUnreadable, Detail: "an attached TNEF stream could not be read: " + err.Error(), Part: p})
			return nil
		}
		return m
	}
	return nil
}
