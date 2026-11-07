# mailparse

メールを、どのツールからも同じように読める 1 つの形に変える Go のライブラリです。ヘッダは出てきた順・重複込み、
差出人と宛先は欄ごとにすべて、MIME の木構造、UTF-8 に直した本文、添付のバイト列、入れ子のメール、そして途中で
起きたことの警告を返します。

攻撃者が作ったメールを読む前提で作っています。

- **順序と重複を保つ。** 先頭に置かれた偽の `Authentication-Results: ... pass` が、後ろの本物の `fail` を隠さない
  ようにします。2 つ目の `From:` も事実として返します。
- **アドレスを解析してから表示名を復号する。** 符号化した表示名にアドレスを仕込まれないようにします。
- **黙って捨てない。** 崩れたヘッダ行、閉じない境界、壊れた Base64、未知の文字コード、上限での打ち切りは、
  安定したコードを持つ `Warning` になります。空の結果にも、解析の失敗にもしません。
- **上限**（大きさ・入れ子・パーツ数・デコード後の大きさ）は、入れ子のメールも含めた 1 回の解析で共有します。
  入力で panic しないことは、ファジングで確かめています。

> 状態: 開発中（v0.x、未リリース）。`.eml` に対応。`.msg` と winmail.dat（TNEF）は次の段階で入ります。

[English README](README.md)

## 使い方

```go
m, err := mailparse.Parse(r, mailparse.Options{}) // Options のゼロ値は既定値
switch {
case errors.Is(err, mailparse.ErrNotMessage): // メールとして判別できない — 何もメールとして読んでいない
case errors.Is(err, mailparse.ErrTooLarge):
case err != nil:
}
for _, f := range m.Header.All("Received") { /* 経由の各段を順に */ }
for _, from := range m.From { /* From の欄ごとに 1 つ */ }
for _, a := range m.Attachments {
	if a.Message != nil { /* 転送されたメールを開いたもの */ }
}
for _, w := range m.Warnings { /* 解析中に起きたこと */ }
```

`Detect(b)` は中身でメールを積極的に判別します（`eml` / `msg` / `tnef` / `unknown`）。設定ファイルや鍵のファイルは
`unknown` で、メールとして「読まれる」ことはありません。

## 読むもの・使う側に任せるもの

読む: ヘッダ（生の値と復号した値）、アドレス、MIME の木、RFC 2047 / 2231、転送エンコーディング、文字コード（宣言、
HTML の `<meta charset>`、宣言の無い日本語の推定）、入れ子のメール（message/rfc822 と中身で判別したもの）、
添付のバイト列。

使う側に任せる: Received や Authentication-Results の意味、URL の取り出し、添付の種類の判別、ハッシュの計算。

## 上限（Options の既定値）

| 項目 | 既定 |
|---|---|
| `MaxSize` | 30 MiB |
| `MaxMessageDepth` | 入れ子 3 層 |
| `MaxMIMEDepth` | 32 |
| `MaxParts` | 全層で 1,000 |
| `MaxDecoded` | 全層で 120 MiB |
| `MaxHeaders` / `MaxHeaderBytes` | ヘッダのまとまりごとに 2,000 / 1 MiB |

## 依存

標準ライブラリと Go チーム製の 2 つです。`golang.org/x/text`（日本語などの文字コード）と、`golang.org/x/net/html`
（HTML の `<meta charset>`）。コミュニティ製の依存はありません。

## 文書

[RFP](docs/ja/mailparse-rfp.ja.md) · [段階 0 の記録](docs/ja/mailparse-phase0.ja.md) · [AGENTS.md](AGENTS.md)

## ライセンス

MIT — [LICENSE](LICENSE) を参照。
