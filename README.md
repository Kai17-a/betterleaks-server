# betterleaks-server

[betterleaks](https://github.com/betterleaks/betterleaks) v1.9.0 を Go パッケージとして組み込んだ、ローカル用のシークレット検出 API サーバー。

## 起動

```sh
go run .                       # 127.0.0.1:8080 で待ち受け
go run . -addr 127.0.0.1:9000  # アドレス変更
```

| 設定 | 既定値 | 説明 |
| --- | --- | --- |
| `-addr` / `BETTERLEAKS_SERVER_ADDR` | `127.0.0.1:8080` | 待ち受けアドレス（フラグが優先） |
| `-max-body-bytes` | `262144`（256 KiB） | `POST /v1/scan` のボディ上限 |
| `-max-line-bytes` | `4096` | `content` の 1 行あたりの上限 |
| `-max-concurrent-scans` | `2` | 同時に実行するスキャン数。超過分は 503 |
| `-scan-timeout` | `30s` | 1 回のスキャンの制限時間 |
| `-allowed-hosts` | なし | `Host` / `Origin` で追加で受け付けるホスト名や IP（カンマ区切り） |

認証はないため、ループバック以外にバインドすると警告ログを出す。

### 上限値について

スキャンの負荷は検出件数の二乗（時間）と「1 行の検出数 × 行の長さ」（メモリ）で増え、ライブラリの処理は途中で中断できない。そのため入力サイズ、行長、同時実行数で上限を決めている。既定値では、上限いっぱいの悪意ある入力 2 件の同時処理で約 1 秒、最大メモリ約 600 MB。ミニファイ済みファイルなど長い行を扱う場合は `-max-line-bytes` を上げる（その分メモリ消費の上限も上がる）。

### Host / Origin の検証

DNS リバインディングなどブラウザ経由のアクセスを防ぐため、`Host` と `Origin`（付いている場合）が `localhost`、ループバック IP、`-allowed-hosts` のいずれでもないリクエストは 403 で拒否する。`-addr` に特定のホストを指定した場合はそのホストも許可される。`0.0.0.0` のようなワイルドカードにバインドする場合は `-allowed-hosts` の指定が必要。

## API

### `GET /healthz`

```json
{"status":"ok"}
```

### `GET /v1/rules`

読み込まれている検出ルール（ID 昇順）。

```json
{"rules":[{"id":"github-pat","description":"...","tags":[]}],"count":463}
```

### `POST /v1/scan`

`Content-Type: application/json` が必須。

| フィールド | 型 | 説明 |
| --- | --- | --- |
| `content` | string | 必須。スキャン対象の文字列 |
| `path` | string | 任意。パス依存のルール・許可リストに使う仮想ファイル名。`.` に正規化される値（`.`、`a/..` など）は不可 |
| `redact` | bool | 任意。`true` で `secret` と `match` を `REDACTED` に置換 |

```sh
curl -s -X POST http://127.0.0.1:8080/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"content":"token = \"...\"","path":"conf/app.env","redact":true}'
```

```json
{
  "findings": [
    {
      "rule_id": "github-pat",
      "description": "...",
      "start_line": 1,
      "end_line": 1,
      "start_column": 10,
      "end_column": 49,
      "match": "REDACTED",
      "secret": "REDACTED",
      "file": "conf/app.env",
      "entropy": 5.17,
      "tags": [],
      "fingerprint": "conf/app.env:github-pat:1"
    }
  ],
  "count": 1
}
```

エラーは `{"error":"..."}` 形式。

| ステータス | 条件 |
| --- | --- |
| 400 | 不正な JSON、未知のフィールド、`content` が空、`path` が不正 |
| 403 | `Host` または `Origin` が許可されていない |
| 413 | ボディまたは 1 行の長さが上限超過 |
| 415 | `Content-Type` が `application/json` でない |
| 503 | 同時実行数の上限超過（`Retry-After` 付き）、スキャンのタイムアウト、リクエストのキャンセル |

未定義のパス（404）と不正なメソッド（405）は `net/http` 標準のプレーンテキスト応答になる。

## 仕様メモ

- betterleaks のデフォルト設定（組み込みルール）を使用。シークレットの有効性検証（外部への HTTP 通信）は行わない。
- リクエスト本文やシークレットはログに出力しない。アクセスログはメソッド、パス、ステータス、所要時間のみ。
- `redact` を指定しない場合、レスポンスに検出したシークレットがそのまま含まれる。
- `path` はパス依存のルールや許可リストの判定に使われるため、検出結果に影響する。信頼できない送信者が指定した `path` をそのまま渡さない。

## 開発

```sh
go test -race ./...
```
