# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

### Changed

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

