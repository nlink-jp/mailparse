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

> Status: in development (v0.x, not yet released). `.eml`, Outlook `.msg` (with compressed RTF) and winmail.dat
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
Return-Path, DKIM-Signature...) or a From with an address and a Date in RFC 5322 form — a YAML file with `from:`
and `date:` keys or an HTTP header dump is not mail.

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
| `MaxSize` | 30 MiB |
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
