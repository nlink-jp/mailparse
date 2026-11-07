package mailparse

import (
	"bytes"
	"encoding/binary"
	"strings"
)

var cfbSignature = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// tnefSignature is MS-OXTNEF's 0x223E9F78, little-endian.
const tnefSignature = 0x223E9F78

// utf16le encodes ASCII s as UTF-16LE, as CFB directory entries spell names.
func utf16le(s string) []byte {
	b := make([]byte, 0, 2*len(s))
	for i := 0; i < len(s); i++ {
		b = append(b, s[i], 0)
	}
	return b
}

var (
	msgSubstg     = utf16le("__substg1.0_")
	msgProperties = utf16le("__properties_version1.0")
)

// Detect recognizes a message positively by its content. A file that is not
// recognized is FormatUnknown — a lenient reader must never turn a config file
// or a key file into a "message".
//
//   - .msg: the CFB signature and the MSG property stream names in the
//     directory (a plain OLE Office document is CFB too, and is not a message)
//   - TNEF: its signature
//   - .eml: a header block that starts with a field and names at least two
//     well-known message fields, one of them From, Received, Message-ID,
//     Return-Path or Date
func Detect(b []byte) Format {
	switch {
	case len(b) >= len(cfbSignature) && bytes.Equal(b[:len(cfbSignature)], cfbSignature):
		if bytes.Contains(b, msgSubstg) && bytes.Contains(b, msgProperties) {
			return FormatMSG
		}
		return FormatUnknown
	case len(b) >= 4 && binary.LittleEndian.Uint32(b) == tnefSignature:
		return FormatTNEF
	case looksLikeEML(b):
		return FormatEML
	}
	return FormatUnknown
}

var anchorFields = map[string]bool{"from": true, "received": true, "message-id": true, "return-path": true, "date": true}

var knownFields = map[string]bool{
	"from": true, "to": true, "cc": true, "bcc": true, "subject": true, "date": true, "message-id": true,
	"received": true, "return-path": true, "mime-version": true, "content-type": true, "reply-to": true,
	"sender": true, "delivered-to": true, "x-mailer": true, "dkim-signature": true, "authentication-results": true,
	"arc-seal": true, "received-spf": true, "in-reply-to": true, "references": true, "user-agent": true,
	"content-transfer-encoding": true, "x-originating-ip": true, "thread-topic": true, "thread-index": true,
}

// looksLikeEML reads at most the first 64 KiB.
func looksLikeEML(b []byte) bool {
	if len(b) > 64<<10 {
		b = b[:64<<10]
	}
	b = bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF"))
	lines := splitLines(b)
	i := 0
	if len(lines) > 0 && bytes.HasPrefix(lines[0], []byte("From ")) {
		i = 1 // an mbox separator line
	}
	if i >= len(lines) {
		return false
	}
	if _, _, ok := splitField(lines[i]); !ok {
		return false
	}
	known, anchor := 0, false
	for ; i < len(lines); i++ {
		l := lines[i]
		if len(bytes.TrimSpace(l)) == 0 {
			break
		}
		if l[0] == ' ' || l[0] == '\t' {
			continue
		}
		name, _, ok := splitField(l)
		if !ok {
			continue
		}
		n := strings.ToLower(name)
		if knownFields[n] {
			known++
		}
		if anchorFields[n] {
			anchor = true
		}
	}
	return anchor && known >= 2
}

// splitLines splits on LF, dropping a trailing CR from each line.
func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		var l []byte
		if i < 0 {
			l, b = b, nil
		} else {
			l, b = b[:i], b[i+1:]
		}
		out = append(out, bytes.TrimSuffix(l, []byte("\r")))
	}
	return out
}
