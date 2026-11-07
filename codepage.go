package mailparse

// codePageCharsets maps Windows code page numbers (PidTagInternetCodepage,
// PidTagMessageCodepage, TNEF idOemCodepage, RTF \ansicpg and \fcharset) to
// charset names golang.org/x/text/encoding/htmlindex knows. It includes the
// Japanese pages the existing tools lacked: ISO-2022-JP (50220-50222) and
// EUC-JP (51932, 20932). Pages htmlindex does not know (IBM437 and other OEM
// pages) are left out: guessing beats decoding with a wrong page.
var codePageCharsets = map[uint32]string{
	866:   "ibm866",
	874:   "windows-874",
	932:   "shift_jis",
	936:   "gbk",
	949:   "euc-kr",
	950:   "big5",
	1200:  "utf-16le",
	1201:  "utf-16be",
	1250:  "windows-1250",
	1251:  "windows-1251",
	1252:  "windows-1252",
	1253:  "windows-1253",
	1254:  "windows-1254",
	1255:  "windows-1255",
	1256:  "windows-1256",
	1257:  "windows-1257",
	1258:  "windows-1258",
	10000: "macintosh",
	20127: "us-ascii",
	20866: "koi8-r",
	20932: "euc-jp",
	21866: "koi8-u",
	28591: "iso-8859-1",
	28592: "iso-8859-2",
	28593: "iso-8859-3",
	28594: "iso-8859-4",
	28595: "iso-8859-5",
	28596: "iso-8859-6",
	28597: "iso-8859-7",
	28598: "iso-8859-8",
	28599: "iso-8859-9",
	28603: "iso-8859-13",
	28605: "iso-8859-15",
	38598: "iso-8859-8-i",
	50220: "iso-2022-jp",
	50221: "iso-2022-jp",
	50222: "iso-2022-jp",
	51932: "euc-jp",
	51936: "gbk",
	51949: "euc-kr",
	54936: "gb18030",
	65001: "utf-8",
}

// codePageCharset returns the charset name for a code page, or "".
func codePageCharset(cp uint32) string { return codePageCharsets[cp] }

// fontCharsetCodePage maps an RTF \fcharset value to a code page (the
// Windows CHARSET_* constants).
var fontCharsetCodePage = map[int]uint32{
	0:   1252, // ANSI
	2:   0,    // SYMBOL: not text
	77:  10000,
	128: 932,  // SHIFTJIS
	129: 949,  // HANGUL
	134: 936,  // GB2312
	136: 950,  // CHINESEBIG5
	161: 1253, // GREEK
	162: 1254, // TURKISH
	163: 1258, // VIETNAMESE
	177: 1255, // HEBREW
	178: 1256, // ARABIC
	186: 1257, // BALTIC
	204: 1251, // RUSSIAN
	222: 874,  // THAI
	238: 1250, // EASTEUROPE
	255: 437,  // OEM
}
