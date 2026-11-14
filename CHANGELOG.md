# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-11-14

### Security

- **`golang.org/x/net` is updated from v0.52.0 to v0.62.0 and
  `golang.org/x/text` from v0.35.0 to v0.43.0.** Nothing mailparse itself
  calls is affected: it uses only the tokenizer of `x/net/html` (to read a
  `<meta charset>`), and the advisories `govulncheck` lists for that package
  are in `Parse` and `Render`. The reason to update is the consumers. A
  library's requirement is the lowest version a tool that imports it can
  build with, and two of the four mail tools pass the sender's display name —
  attacker-composed text — to `x/net/idna` and, through it, to
  `x/text/unicode/norm`, where GO-2026-5026 (a Punycode label that decodes to
  plain ASCII is accepted) and GO-2026-5970 (an endless loop on invalid UTF-8)
  apply. They are fixed in x/net v0.55.0 and x/text v0.39.0.

### Changed

- **Building needs Go 1.26 or later** (`go.mod`; it was 1.25). Both updated
  modules require it.

### Documentation

- mail-dissect, the planned first consumer, was withdrawn before release
  (2026-11-08). The README, README.ja and AGENTS now name the four util-series
  mail tools as the consumers; the RFP carries a dated note and is otherwise
  left as the design record.

## [0.3.0] - 2026-11-07

### Security

- **The lenient address reader is rewritten as a lexer and a small grammar.**
  It reads the address fields net/mail refuses. It used to find structure by
  searching a masked copy of the string and cut addresses out by byte position,
  trimming and dropping comments to fit; with no grammar and no stated output,
  each repair let other text through. An independent review over six rounds
  found, among others, an address in a malformed From vanishing (a missing
  comma), a comment's domain becoming the address's
  (`ceo@corp.example(@evil.example)`), two words glued into a domain that was
  not written (`co(x)rp.example` → `corp.example`), a quoted display name read
  as an address after 16 unclosed `(`, and an underscore dropped from an
  address. The field is now cut into RFC 5322 tokens once (`lenient.go`), and
  the output is held to one contract, checked by a property test on random
  hostile input:
  - an Address is a run of tokens that is an addr-spec as written — words and
    dots with at least one word (the obsolete forms Japanese carriers issued,
    `taro.@docomo.ne.jp`, included) or one quoted-string, `@`, then words
    joined by single dots or an IP literal; no control or format character, and
    no whitespace outside a quoted local part; a comment only beside a dot, the `@` or the edge, and never part of
    the Address. Every part is a whole word written in the field.
  - Each `<...>` gives its addresses, the text before it as the first one's
    name (a bare address there is display text, as in a name-addr); every
    other addr-spec in the item, separated by whitespace — the ideographic
    space and NBSP included — is a mailbox of its own, so
    `ceo@example.com attacker@evil.example`,
    `CEO <ceo@example.com> attacker@evil.example` and
    `CEO <ceo@example.com attacker@evil.example>` each give two.
  - An Exchange DN in `<...>` is kept exactly as written, parentheses
    included; nothing with an `@`, a control or a format character is. What
    fits nothing stays in `Raw` only, with the field's `invalid_address`
    warning.
  - Raw 8-bit bytes in an address are replaced, never guessed as Japanese
    (Shift_JIS 0x81 0x40 would take the `@`).
- **Unclosed parentheses in an address field no longer cost quadratic time.**
  The old masker called itself again after every delimiter that never closed:
  200,000 `(` in a From took a minute, and the recursion had no depth bound.
  The lexer computes where each quoted-string and comment closes beforehand;
  a test compares its quoted-strings and comments with the old masker's on
  random input (domain literals, which the old masker did not know, aside).
- **Compressed RTF with nested `\field` groups no longer panics.** An open
  field kept its instruction text in a `strings.Builder` held by value in a
  slice; when a nested field grew the slice, the copied Builder panicked on its
  next write (a crafted .msg could stop the consumer). Found by `FuzzRTF`; the
  failing input is kept as a fuzz seed.

### Documentation

- `Attachment.MediaType` is the declared type; what a `.msg`/TNEF attachment
  without `PidTagAttachMimeTag` gets, and that deciding a type from the name or
  the bytes is the consumer's (README, both languages; the type's comment).

## [0.2.0] - 2026-11-07

From moving the organization's four mail tools onto mailparse (issues #1–#10)
and their workarounds.

### Added

- `Mailbox.String()`: RFC 5322 form that keeps a spoofed display name a name
  (#10).
- `Attachment.Charset` and `Attachment.Text()`: text/* attachments (text/calendar,
  text/csv) convert to UTF-8 with the rules bodies use (#9).
- `Field.Collapsed()`: Value with whitespace runs made one space (#7).
- `Options.AssumeEML` and the `not_detected_as_mail` warning: read minimal mail
  Detect refuses when the caller knows the input is mail (#6).
- `Message.InReplyTo` and `Message.References`, from headers or, for a
  headerless .msg/TNEF, from MAPI (#2).
- `Message.Walk` and `Message.AllWarnings` for nested messages with absolute
  paths; `Body.Origin` (`mime`, `mapi`, `rtf`, `tnef`).
- Package `msgtest`: builders for .msg, TNEF, compressed RTF and compound files
  for consumers' fixtures (#5); mailparse's own tests use it.
- .msg/TNEF without recipient objects or headers: To/Cc/Bcc from Outlook's
  display lists, names only, with a warning (#3).

### Fixed

- A byte order mark (UTF-8, UTF-16LE/BE) decides a text's charset, wins over a
  declaration (warned) and is not left in the content; UTF-16 HTML in a .msg
  is no longer garbled (#1).
- .msg/TNEF with internet headers: the recipient table is read — Bcc comes from
  it (`bcc_from_mapi`) and a table address missing from To/Cc is reported
  (`mapi_header_mismatch`) (#4).

- From the pre-release review of these changes: `Mailbox.String` quotes a
  local part that is not a dot-atom and never writes something that is no
  addr-spec as an address (a list or a line break hidden in an address could
  otherwise become several mailboxes or a header); name-only mailboxes are
  always quoted; names holding `=?`, C1 controls or line separators are
  handled. The lenient address reading no longer finds `<` or `@` inside a
  quoted display name. A Bcc header that disagrees with the recipient table,
  and table recipients with only an Exchange DN, are reported; an SMTP property
  that is no address is warned about. `charset=utf-16` with either byte order
  mark is not a mismatch. A UTF-8 byte order mark before an .eml's header is
  skipped (`leading_bom`); it used to swallow the first field.
- From a second review round: `Mailbox.String` accepts only IP domain
  literals (as net/mail does) and treats Unicode whitespace as needing quotes
  in a local part and as invalid in a domain; a double space in a name is
  quoted. The lenient reading masks comments as well as quoted strings, treats
  a quote or parenthesis that never closes as text (so the address after it is
  found again), and keeps the words after a quoted part of a name.

### Changed

- msgtest's attachment-method and recipient-type constants are `uint32`, and
  `Prop` accepts an `int` for PtypInteger32.
- `DefaultMaxSize` is 64 MiB (was 30 MiB): a 25 MB attachment is about 34 MB in
  Base64, and two consumers had raised it themselves.
- Documented: Detect's refusals, `Field.Value` folding whitespace, an empty
  `Mailbox.Address` (#6, #7, #8).

## [0.1.0] - 2026-11-07

### Added

- RFP (en/ja) and the Phase 0 record: the three existing util-series parsers
  compared, their defects measured on 11 fictional fixtures and on a real .msg.
- `.eml` reading (Phase 1): positive recognition (`Detect`), a lenient header
  reader that keeps order, duplicates and raw values; address lists per
  occurrence, parsed before display names are decoded; RFC 2047 with the repair
  of whitespace-broken words; the MIME tree with an own multipart splitter that
  keeps what precedes an unclosed boundary; Base64 and quoted-printable that keep
  what decodes; charsets from the declaration, HTML `<meta charset>` or a guess
  for undeclared Japanese; nested messages (message/rfc822 and messages
  recognized by content); limits shared across one parse; a Warning for every
  repair, guess, skip or cut; a fuzz target.
- Package `cfb`: Compound File Binary (MS-CFB) read from the specification,
  replacing the community mscfb the existing tools used; loops in FAT, DIFAT,
  mini-FAT and directory trees, out-of-range sectors and oversized stream claims
  are cut and reported.
- `.msg` reading (MS-OXMSG): transport headers, or identity fields from MAPI
  properties with a `no_transport_headers` warning; text and HTML bodies;
  attachments with bytes; embedded messages (also inside an .eml); 8-bit strings
  by code page, including ISO-2022-JP (50220-50222) and EUC-JP (51932);
  `ParseMSG`.
- Compressed RTF in .msg (MS-OXRTFCP): LZFu expansion bounded by RAWSIZE and
  the remaining decoded budget; a CRC mismatch is warned about and the output
  kept. HTML or plain text encapsulated by Outlook (MS-OXRTFEX) is recovered,
  with `\ansicpg`, per-font `\fcharset` / `\cpg`, `\'hh` and `\uN`; plain RTF
  gives its visible text.
- TNEF / winmail.dat reading (MS-OXTNEF): bodies (compressed RTF, HTML,
  text), attachments with bytes, embedded messages, the recipient table and
  identity from the encapsulated MAPI properties; checksums verified; opened
  wherever it appears (an attachment of an .eml or .msg) and by `ParseTNEF`.

### Fixed

- Undeclared ISO-2022-JP text, being 7-bit, was taken for US-ASCII; its escape
  sequences are now recognized and the guess is reported.

### Security

Found by an independent pre-release review and fixed before the first
release:

- Memory: a cfb stream declaring a huge size kept a file-sized buffer;
  compressed RTF reserved its RAWSIZE and stacked groups without bound;
  multipart splitting collected every delimiter line; TNEF floods of
  attributes or warnings grew without bound. Every message now caps warnings
  at 100 per code (`warning_limit`), and TNEF values are charged to
  `MaxDecoded`.
- Hidden content: one malformed MIME parameter discarded the attachment name;
  an unsplittable multipart and parts after the closing delimiter were
  dropped; HTMLTAG content leaked from plain RTF and skipped destinations;
  HYPERLINK targets in plain RTF were lost; cfb entries not linked into the
  tree went unreported (now `File.Unlinked`).
- Misleading values: TNEF attMessageID was reported as the Message-ID; .msg
  and TNEF 8-bit strings used the wrong code page; a mailbox showing one
  address and carrying another, and MAPI identity differing from the headers,
  now warn; YAML and HTTP header dumps were detected as mail.
- A second review of those fixes found and fixed: cfb issues bypassing the
  warning cap, uncapped TNEF recipient rows, HYPERLINK targets decoded
  differently from Word (`\uN`, `\'hh`), a Shift_JIS trail byte injecting a
  mailbox when 8-bit names were converted before parsing, and Detect rejecting
  minimal script mail.

### Changed

- `Message.ReturnPath` is `[]AddressList` (parsed, null path included).
- `cfb.Signature` is no longer exported.

