# mailparse

A Go library that reads email messages into one shape every tool can read the same way: header fields in
order with duplicates kept, every sender and recipient list, the MIME tree, bodies converted to UTF-8,
attachment bytes, nested messages, and warnings about everything it met along the way.

It is written for messages composed by an attacker:

- **Order and duplicates are kept.** A forged `Authentication-Results: ... pass` placed on top must not hide
  the real `fail` after it, and a second `From:` is a fact, not noise.
- **Addresses are parsed before display names are decoded,** so an encoded display name cannot smuggle in an
  address.
- **Nothing is dropped silently.** A malformed header line, an unclosed boundary, damaged Base64, an unknown
  charset or a limit that cut something becomes a `Warning` with a stable code — never an empty result and
  never a failed parse.
- **Limits** on size, nesting, part count and decoded bytes are shared across one parse, nested messages
  included. It never panics on input; fuzz tests hold it to that.

> Status: v0.1.0 — the API may still change before v1.0 with mail-dissect, its first consumer. `.eml`, Outlook `.msg` (with compressed RTF) and winmail.dat
> (TNEF) are supported. `.msg` has been checked on a real Outlook message; TNEF only on samples built from the
> specification.

[日本語版 README](README.ja.md)

## Use

```go
m, err := mailparse.Parse(r, mailparse.Options{}) // zero Options = defaults
switch {
case errors.Is(err, mailparse.ErrNotMessage): // not recognized as a message — nothing was read as one
case errors.Is(err, mailparse.ErrTooLarge):
case err != nil:
}
for _, f := range m.Header.All("Received") { /* every hop, in order */ }
for _, from := range m.From { /* one entry per From field */ }
for _, a := range m.Attachments {
	if a.Message != nil { /* a forwarded message, opened */ }
}
for _, w := range m.Warnings { /* what the parse met */ }
```

`Detect(b)` recognizes a message positively by content (`eml` / `msg` / `tnef` / `unknown`); a config or key file
is `unknown` and is never "parsed" as mail. An `.eml` needs a field only mail carries (Received, Message-ID,
Return-Path, DKIM-Signature...), or a From with an address among field names that look like mail (none with `_`,
not all lowercase) — a minimal From/To/Subject message from a script is mail; a YAML file with `from:` and `to:`
keys or an HTTP header dump is not. **Not detected:** a From with no `@` (cron's `From: root`), no From at all
(To and Subject alone), and a block with only one well-known field. When the caller knows the input is mail (a
`.eml` argument, a mail tool's stdin), set `Options.AssumeEML`: such input is then read with a
`not_detected_as_mail` warning (input with no header field is still `ErrNotMessage`).

## What it reads, and what it leaves to you

Reads: header fields (raw and decoded), address lists (Return-Path included, a null `<>` too), the MIME tree,
RFC 2047 / 2231, transfer encodings, charsets (declared, HTML `<meta charset>`, or guessed for undeclared
Japanese), nested messages (message/rfc822, .msg embedded messages and messages recognized by content),
attachment bytes. Content-Type and Content-Disposition parameters are read leniently: one malformed parameter
does not discard the others (an attachment's name stays visible), a duplicate keeps the first, and RFC 2231
names decode in any charset — each with a warning. A multipart that cannot be split keeps its bytes as an
attachment, and parts placed after the closing delimiter are read and warned about.

From a `.msg`: the internet headers Outlook kept (`PR_TRANSPORT_MESSAGE_HEADERS`), else the sender, recipients,
subject and date from MAPI properties with a `no_transport_headers` warning (such a message has no Received
fields); every body it holds — text, HTML, and the compressed RTF (MS-OXRTFCP) with the HTML or text Outlook
encapsulated in it (MS-OXRTFEX) or the visible text of plain RTF — since an attacker can make them differ (a CRC
mismatch is warned about and the text kept as evidence); attachments with their bytes;
embedded messages; 8-bit strings decoded with the message code page and bodies with the internet code page,
including ISO-2022-JP (50220-50222) and EUC-JP (51932). Exchange `/O=...` addresses stay in `Raw`. When the MAPI
sender or subject Outlook displays differs from the headers, or a mailbox shows one address and carries another
SMTP address, a warning says so. In plain RTF, a HYPERLINK is written as its text followed by ` <target>`, as
Outlook renders it in plain text, so the target is not lost; hidden text is kept (an over-report beats a gap).

From winmail.dat (TNEF, usually an `application/ms-tnef` attachment, opened as a nested message of format
`tnef`): the bodies (the compressed RTF Outlook puts there, HTML, text), the attachments with their bytes and
names, embedded messages, recipients from the recipient table, and the sender, subject and date from the
encapsulated MAPI properties; 8-bit strings use the OEM code page. A failed checksum is warned about and the
value kept. The legacy attributes attFrom and attDateSent are not read, and attMessageID (a search key, not the
internet Message-ID) is not reported as one.

`ParseEML`, `ParseMSG` and `ParseTNEF` read one format without detection.

Leaves to the consumer: the meaning of Received or Authentication-Results, URL extraction, attachment type
detection, hashing.

## Reading the result safely

- **Write a mailbox back with `Mailbox.String()`**, never `Name + " <" + Address + ">"`. A display name is attacker
  text: one that decodes to `Bank <security@bank.example>` joined naively turns back into the spoofed address the
  parser kept inside the name. `String()` quotes such a name (RFC 5322), quotes a local part that is not a dot-atom,
  never writes something that is no valid address as one (it goes into the quoted display text), and writes a
  mailbox without an address as its quoted name alone — display text, with no address in it. Reading what it writes
  gives the same one mailbox back.
- **`Mailbox.Address` can be empty**: a lenient reading of a field that did not parse may find only a name, and a
  `.msg`/TNEF mailbox may carry only an Exchange DN (`/O=...`). `AddressList.Raw` then holds what was written.
- **`Field.Value` keeps folding whitespace** (tabs included), as RFC 5322 leaves it; `net/textproto` joined lines with
  one space. `Field.Collapsed()` gives that form. For address fields, `Value` is display text — read addresses from
  `From`, `To` and the other parsed lists.
- **Text attachments**: only text/plain and text/html are bodies. A text/calendar invitation or text/csv is an
  attachment with its declared `Charset`; `Attachment.Text()` converts it with the rules bodies use.
- **Nested messages**: `Walk` visits the message and every nested one with its path ("2>1"); `AllWarnings` returns all
  warnings with absolute `Part` paths.
- **Where a body came from**: `Body.Origin` — `mime`, `mapi` (a .msg/TNEF body property), `rtf` (compressed RTF,
  in a .msg usually a copy of a `mapi` body), `tnef` (TNEF's legacy body).
- **.msg recipients**: with internet headers, To, Cc and Bcc come from the headers. Received mail carries no Bcc header,
  so Bcc then comes from the MAPI recipient table (`bcc_from_mapi`); a table address missing from the headers, and a
  table recipient with only an Exchange DN (which cannot be compared), are reported (`mapi_header_mismatch`). Without headers or recipient objects, Outlook's display lists give names only.
  `InReplyTo` and `References` come from the headers, or from MAPI for a headerless `.msg`.

## Package msgtest (test support)

`github.com/nlink-jp/mailparse/msgtest` builds fictional `.msg` files, winmail.dat streams, compressed RTF and the
compound files under them, so consumers write fixtures instead of committing real messages:

```go
b := msgtest.Message([]msgtest.Prop{msgtest.P(msgtest.PidTagSubject, "Hello")},
	msgtest.Recipient(0, msgtest.P(msgtest.PidTagRecipientType, uint32(msgtest.RecipientTo)),
		msgtest.P(msgtest.PidTagSMTPAddress, "bob@example.org")))
```

It writes and does not check; keep it in tests.

## Package cfb

`github.com/nlink-jp/mailparse/cfb` reads Compound File Binary files (MS-CFB) — the container of `.msg` and of
legacy Office documents — for consumers who need to look inside one (a macro storage, say) without a community
dependency. Loops in sector chains or the directory tree, out-of-range sectors, chains shared between streams and
oversized stream claims are cut and reported (`Issues`, `ErrTruncated`); opening is proportional to the input
size. Allocated entries no tree links to — a way to hide a stream from tools that walk the tree — are listed in
`File.Unlinked`. Streams sharing sectors make reading every entry cost more than the file size, so budget reads
from untrusted files (mailparse does). A `File` is not safe for concurrent use.

```go
f, err := cfb.Open(r, cfb.Limits{}) // MaxSize 64 MiB, MaxEntries 4,096 by default
for _, e := range f.Root.Children { /* storages and streams, in directory order */ }
data, err := f.ReadStream(f.Root.Child("WordDocument"))
```

## Limits (Options, defaults)

| Option | Default |
|---|---|
| `MaxSize` | 64 MiB (a 25 MB attachment is about 34 MB in Base64) |
| `MaxMessageDepth` | 3 nested layers |
| `MaxMIMEDepth` | 32 |
| `MaxParts` | 1,000 across every layer |
| `MaxDecoded` | 120 MiB across every layer (Base64 and QP, .msg streams, expanded RTF, TNEF values) |
| `MaxHeaders` / `MaxHeaderBytes` | 2,000 / 1 MiB per header block |

`MaxDecoded` counts every decoded copy kept: an attached message's bytes and its decoded parts both count.
Warnings of one code beyond 100 in a message are summed up by one `warning_limit` warning.

## Dependencies

The standard library and two Go-team packages: `golang.org/x/text` (Japanese and other charsets) and
`golang.org/x/net/html` (HTML `<meta charset>`). No community dependencies.

## Documentation

[RFP](docs/en/mailparse-rfp.md) · [Phase 0 record](docs/en/mailparse-phase0.md) · [AGENTS.md](AGENTS.md)

## License

MIT — see [LICENSE](LICENSE).
