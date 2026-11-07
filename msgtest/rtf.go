package msgtest

import (
	"encoding/binary"
	"hash/crc32"
)

// rtfDictionary is the string MS-OXRTFCP's LZ77 dictionary starts with; the
// write offset starts after it, at 207.
const rtfDictionary = `{\rtf1\ansi\mac\deff0\deftab720{\fonttbl;}{\f0\fnil \froman ` +
	`\fswiss \fmodern \fscript \fdecor MS Sans SerifSymbolArialTimes New RomanCourier` +
	"{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"

func rtfCRC(b []byte) uint32 {
	var crc uint32
	for _, c := range b {
		crc = crc32.IEEETable[byte(crc)^c] ^ crc>>8
	}
	return crc
}

func rtfHeader(body []byte, raw int, typ, crc uint32) []byte {
	h := make([]byte, 16, 16+len(body))
	binary.LittleEndian.PutUint32(h[0:], uint32(len(body)+12))
	binary.LittleEndian.PutUint32(h[4:], uint32(raw))
	binary.LittleEndian.PutUint32(h[8:], typ)
	binary.LittleEndian.PutUint32(h[12:], crc)
	return append(h, body...)
}

// CompressRTF returns raw as a PidTagRtfCompressed value (MS-OXRTFCP, "LZFu"):
// a valid stream that uses only literals, ended by the end marker, with a
// correct CRC.
func CompressRTF(raw []byte) []byte {
	var body []byte
	wp := len(rtfDictionary)
	for i := 0; ; {
		ctrl := len(body)
		body = append(body, 0)
		for bit := 0; bit < 8; bit++ {
			if i == len(raw) {
				body[ctrl] |= 1 << bit
				ref := uint16(wp%4096) << 4
				body = append(body, byte(ref>>8), byte(ref))
				return rtfHeader(body, len(raw), 0x75465A4C, rtfCRC(body))
			}
			body = append(body, raw[i])
			i++
			wp++
		}
	}
}

// UncompressedRTF returns raw as an uncompressed PidTagRtfCompressed value
// ("MELA"; the CRC field is not used).
func UncompressedRTF(raw []byte) []byte { return rtfHeader(raw, len(raw), 0x414C454D, 0) }
