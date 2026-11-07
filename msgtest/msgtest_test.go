package msgtest_test

import (
	"testing"
	"time"

	"github.com/nlink-jp/mailparse"
	"github.com/nlink-jp/mailparse/msgtest"
)

// What msgtest builds reads back through mailparse as built.
func TestMessageReadsBack(t *testing.T) {
	sent := time.Date(2026, 11, 7, 1, 2, 3, 0, time.UTC)
	rtf := msgtest.CompressRTF([]byte(`{\rtf1\ansi\fromhtml1 {\*\htmltag <a href="https://rtf.example.com/">}x{\*\htmltag </a>}}`))
	b := msgtest.Message([]msgtest.Prop{
		msgtest.P(msgtest.PidTagSubject, "Hello"),
		msgtest.P(msgtest.PidTagSentRepresentingName, "Alice"),
		msgtest.P(msgtest.PidTagSentRepresentingSMTPAddress, "alice@example.com"),
		msgtest.P(msgtest.PidTagClientSubmitTime, sent),
		msgtest.P(msgtest.PidTagMessageCodepage, uint32(65001)),
		msgtest.P(msgtest.PidTagBody, msgtest.String8("plain")),
		msgtest.P(msgtest.PidTagRtfCompressed, rtf),
	},
		msgtest.Recipient(0, msgtest.P(msgtest.PidTagRecipientType, uint32(msgtest.RecipientTo)), msgtest.P(msgtest.PidTagSMTPAddress, "bob@example.org")),
		msgtest.Attachment(0, []msgtest.Prop{
			msgtest.P(msgtest.PidTagAttachMethod, uint32(msgtest.AttachByValue)),
			msgtest.P(msgtest.PidTagAttachLongFilename, "a.txt"),
			msgtest.P(msgtest.PidTagAttachDataBinary, []byte("data")),
		}),
		msgtest.Attachment(1, []msgtest.Prop{msgtest.P(msgtest.PidTagAttachMethod, uint32(msgtest.AttachEmbeddedMessage))},
			msgtest.Embedded([]msgtest.Prop{msgtest.P(msgtest.PidTagSubject, "inner")})),
	)
	if mailparse.Detect(b) != mailparse.FormatMSG {
		t.Fatal("not a .msg")
	}
	m, err := mailparse.ParseBytes(b, mailparse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Subject != "Hello" || !m.Date.Equal(sent) || m.From[0].Mailboxes[0].Address != "alice@example.com" || m.To[0].Mailboxes[0].Address != "bob@example.org" {
		t.Fatalf("%+v", m)
	}
	if len(m.Bodies) != 2 || m.Bodies[0].Content != "plain" || m.Bodies[1].Part != "msg/rtf" {
		t.Fatalf("%+v", m.Bodies)
	}
	if len(m.Attachments) != 2 || string(m.Attachments[0].Data) != "data" || m.Attachments[1].Message.Subject != "inner" {
		t.Fatalf("%+v", m.Attachments)
	}
	if u := msgtest.UncompressedRTF([]byte(`{\rtf1 hi}`)); len(u) != 16+len(`{\rtf1 hi}`) {
		t.Fatalf("uncompressed %d", len(u))
	}
}

func TestTNEFReadsBack(t *testing.T) {
	inner := msgtest.TNEF(msgtest.TNEFAttr(msgtest.LevelMessage, msgtest.AttMsgProps,
		msgtest.TNEFProps(msgtest.TNEFProp{Tag: msgtest.Tag(msgtest.PidTagSubject, msgtest.PtypString), Value: msgtest.UTF16("inner")})))
	b := msgtest.TNEF(
		msgtest.TNEFAttr(msgtest.LevelMessage, msgtest.AttSubject, []byte("Outer\x00")),
		msgtest.TNEFAttr(msgtest.LevelMessage, msgtest.AttRecipTable, msgtest.TNEFRecipients(
			[]msgtest.TNEFProp{
				{Tag: msgtest.Tag(msgtest.PidTagRecipientType, msgtest.PtypInteger32), Value: uint32(msgtest.RecipientTo)},
				{Tag: msgtest.Tag(msgtest.PidTagSMTPAddress, msgtest.PtypString), Value: msgtest.UTF16("bob@example.org")},
			})),
		msgtest.TNEFAttr(msgtest.LevelAttachment, msgtest.AttAttachRendData, nil),
		msgtest.TNEFAttr(msgtest.LevelAttachment, msgtest.AttAttachTitle, []byte("f.bin\x00")),
		msgtest.TNEFAttr(msgtest.LevelAttachment, msgtest.AttAttachData, []byte("bytes")),
		msgtest.TNEFAttr(msgtest.LevelAttachment, msgtest.AttAttachRendData, nil),
		msgtest.TNEFAttr(msgtest.LevelAttachment, msgtest.AttAttachment, msgtest.TNEFProps(
			msgtest.TNEFProp{Tag: msgtest.Tag(msgtest.PidTagAttachDataBinary, msgtest.PtypObject), Value: append(append([]byte{}, msgtest.IIDMessage...), inner...)})),
	)
	m, err := mailparse.ParseBytes(b, mailparse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != mailparse.FormatTNEF || m.Subject != "Outer" || m.To[0].Mailboxes[0].Address != "bob@example.org" || len(m.Warnings) != 0 {
		t.Fatalf("%+v", m)
	}
	if string(m.Attachments[0].Data) != "bytes" || m.Attachments[1].Message.Subject != "inner" {
		t.Fatalf("%+v", m.Attachments)
	}
}
