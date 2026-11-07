package mailparse

// Warning codes. A Warning records something a parse met and handled instead of
// failing: malformed input, a repair, or a limit that cut something. The codes
// are stable; Detail is our own wording (never text taken from the message,
// beyond a sanitized short token such as a charset name).
const (
	WarnMboxFromLine        = "mbox_from_line"            // a leading "From " line was skipped
	WarnMalformedHeaderLine = "malformed_header_line"     // a header line that is neither a field nor a continuation was skipped
	WarnRaw8BitHeader       = "raw_8bit_header"           // a header value held raw non-UTF-8 bytes; the charset was guessed
	WarnHeaderLimit         = "header_limit"              // header fields beyond Options.MaxHeaders / MaxHeaderBytes were not kept
	WarnRepairedEncodedWord = "repaired_encoded_word"     // an RFC 2047 encoded-word broken by whitespace was repaired
	WarnUndecodableWord     = "undecodable_encoded_word"  // an RFC 2047 encoded-word could not be decoded and was kept as written
	WarnDuplicateField      = "duplicate_field"           // a field RFC 5322 allows once (From, Sender, Subject, Date, Message-ID...) appeared more than once
	WarnInvalidAddress      = "invalid_address"           // an address field did not parse; a lenient reading was used
	WarnInvalidDate         = "invalid_date"              // the Date field did not parse; DateRaw keeps it
	WarnInvalidContentType  = "invalid_content_type"      // Content-Type did not parse; a default was used
	WarnInvalidParameters   = "invalid_parameters"        // a Content-Type or Content-Disposition parameter was malformed, duplicated or in an undecodable charset; what could be read was kept
	WarnPartsAfterClose     = "parts_after_close"         // delimiter lines followed a multipart's closing delimiter; the parts after it were read too
	WarnUnsplitMultipart    = "unsplit_multipart"         // a multipart could not be split (no boundary, no delimiter, too deep); its bytes are returned as one attachment
	WarnMissingBoundary     = "missing_boundary"          // a multipart had no boundary parameter
	WarnNoParts             = "no_parts"                  // a multipart had no delimiter at all
	WarnUnclosedBoundary    = "unclosed_boundary"         // a multipart ended without its closing delimiter
	WarnMIMEDepthLimit      = "mime_depth_limit"          // a multipart deeper than Options.MaxMIMEDepth was not opened
	WarnPartLimit           = "part_limit"                // parts beyond Options.MaxParts were not read
	WarnDecodedLimit        = "decoded_limit"             // decoded data beyond Options.MaxDecoded was not kept
	WarnMessageDepthLimit   = "message_depth_limit"       // a nested message deeper than Options.MaxMessageDepth was not opened
	WarnInvalidBase64       = "invalid_base64"            // Base64 data held characters outside the alphabet or a broken tail; they were skipped
	WarnInvalidQP           = "invalid_quoted_printable"  // quoted-printable data held a broken escape; it was kept as written
	WarnUnknownEncoding     = "unknown_transfer_encoding" // an unknown Content-Transfer-Encoding; the data was kept as is
	WarnUnknownCharset      = "unknown_charset"           // a declared charset is not known; the charset was guessed
	WarnCharsetMismatch     = "charset_mismatch"          // the declared charset did not fit the bytes; the charset was guessed
	WarnCharsetGuessed      = "charset_guessed"           // no charset was declared for non-ASCII text; it was guessed
	WarnUndecodableText     = "undecodable_text"          // text could not be decoded by any candidate; invalid bytes were replaced

	// .msg and TNEF.
	WarnCFBDamaged             = "cfb_damaged"              // the compound file structure was damaged (a loop, an out-of-range sector, a short stream); what was readable was kept
	WarnMSGStructure           = "msg_structure"            // a .msg storage lacked a stream the format requires, or a property stream was cut
	WarnNoTransportHeaders     = "no_transport_headers"     // a .msg had no internet headers; identity fields came from MAPI properties
	WarnAttachmentNotExtracted = "attachment_not_extracted" // an attachment held no bytes to extract (OLE storage, a reference to a file)
	WarnNestedUnreadable       = "nested_unreadable"        // an attached message was recognized but could not be read; it stays an attachment
	WarnRTFCRC                 = "rtf_crc_mismatch"         // compressed RTF failed its CRC check; the expanded text was kept as evidence
	WarnRTFDamaged             = "rtf_damaged"              // compressed RTF was cut, had an unknown type or did not expand to RTF
	WarnWarningLimit           = "warning_limit"            // one warning code repeated more than 100 times in a message; the rest were counted out, not recorded
	WarnAddressMismatch        = "mapi_address_mismatch"    // a .msg/TNEF mailbox shows one address and carries a different SMTP address; Address holds the SMTP one
	WarnHeaderMismatch         = "mapi_header_mismatch"     // the MAPI sender or subject Outlook displays differs from the internet headers that were used
	WarnRecipientType          = "recipient_type"           // a recipient had no known type (To, Cc, Bcc) and was read as To, or had no name or address and was skipped
	WarnTNEFDamaged            = "tnef_damaged"             // a TNEF stream was cut, had a bad checksum, an unknown level or a broken property list; what was readable was kept
)

// Warning is one thing a parse met and handled.
type Warning struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
	// Part is where the warning applies: a MIME part path ("" for the message
	// header, "1", "2.1" for parts), or for a .msg or TNEF a path such as
	// "msg", "msg/attach/0", "tnef/recip/1". Warnings of one code beyond 100 in
	// a message are summed up by one warning_limit warning.
	Part string `json:"part,omitempty"`
}
