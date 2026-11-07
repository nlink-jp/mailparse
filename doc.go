// Package mailparse reads email messages — .eml, Outlook .msg and winmail.dat
// (TNEF) — into one Message shape that every
// consumer can read the same way: the header fields in order with duplicates
// kept, every sender and recipient list, the MIME tree, bodies converted to
// UTF-8, attachment bytes, nested messages, and warnings about what happened
// while parsing.
//
// It is written for messages composed by an attacker. Nothing in a message is
// trusted: field order and duplicates are kept (a forged header placed first
// must not hide the real one after it), addresses are parsed before display
// names are decoded (so an encoded display name cannot smuggle in an address),
// and every place the input is malformed, cut or over a limit is reported as a
// Warning instead of being dropped silently. Limits in Options bound size,
// nesting, part count and decoded bytes, shared across one parse including the
// nested messages it opens. The package never panics on input; fuzz tests hold
// it to that.
//
// mailparse reads the container and no further: the meaning of Received or
// Authentication-Results, URL extraction, hashing and attachment type detection
// belong to the consumer.
package mailparse
