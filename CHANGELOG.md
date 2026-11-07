# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Fixed

- Undeclared ISO-2022-JP text, being 7-bit, was taken for US-ASCII; its escape
  sequences are now recognized and the guess is reported.
