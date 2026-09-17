# MCP + OAuth 2.1 + CIMD + PRM デモ

添付の構成図をそのまま動かせるようにした実装です。Chat UI からプロンプトを送ると、
ダミー LLM が MCP サーバーの `hello` ツール呼び出しを指示し、未認証のアクセス試行から
OAuth 2.1 の認可フローが始まり、最終的に「Hello, 〇〇!」が返ってきます。

すべてのコンポーネントは独立したプロセスとして起動し、**コンポーネント間は実際の HTTP
で通信します**(モックした関数呼び出しではありません)。

## 準拠している仕様

| 仕様 | 実装箇所 |
| --- | --- |
| MCP (Streamable HTTP, tools) | `src/mcp-server/server.ts` / `src/orchestrator/mcp-client.ts` |
| OAuth 2.1 (authorization code + PKCE 必須、implicit/password なし) | `src/auth-server/server.ts` |
| Client ID Metadata Document (CIMD) | `src/orchestrator/server.ts` (公開) / `src/client-registry/server.ts` (取得・検証) |
| Protected Resource Metadata — RFC 9728 | `src/mcp-server/server.ts` (公開) / `src/orchestrator/oauth-client.ts` (取得) |
| Authorization Server Metadata — RFC 8414 | `src/auth-server/server.ts` |
| Pushed Authorization Request — RFC 9126 | 図の 10 → 11 に対応 |
| Resource Indicators — RFC 8707 | `resource` パラメータとトークンの `aud` |
| Authorization Server Issuer Identification — RFC 9207 | callback の `iss` 検証 |

## 構成

| コンポーネント | ポート | 役割 |
| --- | --- | --- |
| Chat UI | 4000 | オーケストレーターが配信。SSE でフローを可視化 |
| オーケストレーター（信頼できる） | 4000 | MCP Client / OAuth Client。CIMD をホストし、callback を受ける |
| オーケストレーター（信頼できない） | 4001 | 同じ実装。CIMD は公開するが registry の許可リストに載っていない |
| LLM (ダミー) | 4100 | ルールベースでツール呼び出しと最終回答を返すだけ |
| MCP Server (Resource Server) | 4200 | `hello` ツール。PRM 公開、Bearer 検証 |
| Authorization Server | 4300 | PAR / 認可 / トークン発行。CIMD でクライアントを識別 |
| Client registry | 4400 | CIMD の取得・検証・キャッシュ、許可リストと登録状態の保持 |

## 動かし方

```bash
npm install
npm run dev
```

ブラウザで <http://localhost:4000> を開き、「太郎さんに挨拶して」などと送信します。
チャットに「ブラウザで認可する」ボタン (Elicitation URL Mode) が出るので、開いて
同意画面で「許可する」を押すと、そのままツール実行まで進みます。

右ペインに図の番号に対応したフローが出ます。6〜8 はサーバー間の処理なので、
ターミナルの `[mcp]` `[registry]` `[auth]` のログを見てください。

ブラウザを使わずに一通り流したい場合:

```bash
npm run smoke
```

同意画面の「許可する」まで自動で押して、1〜16 のフローをコンソールに出力します。

## 信頼できないオーケストレーターで試す

ヘッダーの「オーケストレーター」の設定で、リクエストを投げる先を切り替えられます。

| 選択肢 | client_id | 結果 |
| --- | --- | --- |
| 信頼できるオーケストレーター (4000) | `http://localhost:4000/oauth/client-metadata.json` | 認可され、`Hello, 〇〇!` が返る |
| 信頼できないオーケストレーター (4001) | `http://localhost:4001/oauth/client-metadata.json` | **PAR (10) で拒否され、ツールを実行できない** |

2 つのオーケストレーターは**実装が全く同じ**で、違うのは名乗る `client_id` と
待ち受けポートだけです (`ORCHESTRATOR_VARIANT` 環境変数で切り替え)。
それでも結果が変わるのは、Client registry の許可リスト
(`TRUSTED_CLIENT_IDS` in `src/shared/config.ts`) に 4000 番しか載っていないためです。

信頼できない側で起こること:

1. CIMD 自体は正しく取得・検証できる (registry は「Unknown Orchestrator (未登録)」と認識する)
2. MCP Server が AS にクライアント登録を依頼する (8) が、**registry が 403 で拒否**する
3. 未登録のまま認可リクエスト (10) に進むので、**AS が `invalid_client` で拒否**する
4. アクセストークンが出ないため、MCP のツールは実行されない

つまり「CIMD が取得できること」と「そのクライアントを信頼してよいこと」は別だ、
という点を確認するための構成です。CIMD は名乗りの検証しかできません。

コマンドラインからも確認できます (拒否されれば成功として exit 0):

```bash
npm run smoke:untrusted
```

型チェック:

```bash
npm run typecheck
```

## 図の番号と実装の対応

| # | 内容 | 実装 |
| --- | --- | --- |
| 1 | プロンプト指示 (ユーザー → Chat UI) | `public/index.html` の送信フォーム |
| 2 | 起動 (Chat UI → オーケストレーター) | `POST /api/chat` |
| 3 | 推論指示 | `POST http://localhost:4100/v1/infer` |
| 4 | MCP Server 呼び出し指示 | ダミー LLM が `tool_calls` を返す |
| 5 | アクセス試行 | トークン無しで MCP `initialize` を POST → **401 + WWW-Authenticate** |
| 6 | CIMD 確認 | MCP Server → Client registry `POST /clients/resolve` |
| 7 | CIMD 返却 | Client registry が client_id の URL (= オーケストレーター) から取得して検証 |
| 8 | クライアント登録 (なければ) | MCP Server → AS `POST /clients/register` → registry に登録 |
| 9 | PRM 取得 | 401 の `resource_metadata` を辿って PRM を取得 |
| 10 | 認可リクエスト | AS の PAR エンドポイントに push |
| 11 | 認可 URL を指示 | AS が `request_uri` を返し、そこから認可 URL を組み立てる |
| 12 | Elicitation URL Mode | SSE で `elicitation/create` (mode: `url`) を Chat UI に送る |
| 13 | 認可 | AS の同意画面。表示内容は CIMD 由来 |
| 14 | Callback (認可コード) | `GET /oauth/callback` で `state` と `iss` を検証 |
| 15 | 認可コードとトークンを変換 | `POST /token` (PKCE 検証 + CIMD 再確認) |
| 15/16 | リソースアクセス | Bearer 付きで MCP 接続 → `tools/list` → `tools/call` |

## Client ID Metadata Document の要点

クライアントの `client_id` は **メタデータ文書の URL そのもの** です。

```
client_id = http://localhost:4000/oauth/client-metadata.json
```

AS はこの URL を取得してクライアントを識別するので、動的クライアント登録 (DCR) は不要です。
`src/client-registry/server.ts` では次を検証しています。

- `client_id` が絶対 URL で、https であること (localhost のみ http を許容)
- fragment / userinfo を含まないこと
- 取得時にリダイレクトを追わないこと
- **文書内の `client_id` が取得元 URL と完全一致すること**
- `redirect_uris` があり、すべて URL として妥当なこと
- `token_endpoint_auth_method` が `none` であること (パブリッククライアント)

## 確認済みの防御的な振る舞い

以下は実際に動かして確認しています。

- CIMD に登録されていない `redirect_uri` は PAR で拒否
- `code_challenge_method=plain` や不正な challenge は拒否 (S256 のみ)
- `resource` (RFC 8707) が無い認可リクエストは拒否
- `code_verifier` 不一致ではトークンを発行しない
- 認可コードは 1 回だけ有効 (再利用時は同一クライアント/ユーザーのトークンも失効)
- `request_uri` は 1 回だけ有効
- **`aud` が別リソースのトークンは MCP Server が 401 で拒否** (トークンの使い回し防止)
- リフレッシュトークンはワンタイム (使用時にローテーション)
- CIMD として解釈できない URL は `client_id` にできない
- **Client registry に登録されていないクライアントは、CIMD が正しくても認可されない**
  (登録は許可リストで制御。PAR・同意画面・トークン発行のいずれでも確認する)

## 設計上の判断

図には表現されていない部分について、次のように補いました。

**1. 6〜8 のために `MCP-Client-Id` ヘッダを使っています (デモ専用・非標準)**

図では、アクセス試行 (5) を受けた MCP Server が Client registry に CIMD を確認し、
未登録なら AS に登録します。ただし MCP の標準では、未認証リクエストの時点で
クライアントの識別子をサーバーに伝える方法がありません。そこで、オーケストレーターが
自分の `client_id` (= CIMD の URL) を `MCP-Client-Id` ヘッダで名乗る形にしました。
このヘッダは標準仕様ではありません。

なお CIMD の検証は AS 側 (PAR とトークン発行時) でも独立して行っているため、
このヘッダが無くても認可フロー自体は正しく動きます。

**2. 10 と 11 を PAR (RFC 9126) として実装しました**

「認可リクエスト → 認可 URL を指示」という往復は、クライアントが認可リクエストを AS に
push し、AS が `request_uri` を返す PAR とみなすのが自然だったためです。AS 側は
`require_pushed_authorization_requests: true` にしてあります。

**3. Elicitation URL Mode はオーケストレーター → Chat UI で実装しました**

MCP の elicitation は本来 server → client の方向ですが、図では
オーケストレーター → ブラウザ になっています。図に合わせて、オーケストレーターが
`elicitation/create` (mode: `url`) と同じ形のメッセージを SSE で Chat UI に送り、
UI がボタンとして描画する形にしました。

**4. LLM と MCP サーバーの中身はダミーです**

指示のとおり、LLM は正規表現ベースで「`hello` を呼ぶ」と決めるだけ、
MCP サーバーは挨拶を返すだけです。

**5. SSE のイベントを再送できるようにしています**

認可のためにブラウザが別ページへ移動すると SSE が切れて結果を取りこぼすため、
イベントにシリアル ID を振り、再接続時に `Last-Event-ID` 以降 (新規接続なら全履歴)
を送り直しています。

## 本番運用では足りないもの

学習・検証用のデモなので、次は意図的に省いています。

- すべて **http / localhost** 前提です。実運用では https が必須です
  (CIMD も PRM も https URL であることが前提の仕様です)
- 認可サーバーの署名鍵はプロセス起動ごとに生成され、再起動で失効します
- ユーザーは `taro@example.com` 固定で、ログイン処理がありません
- 同意の永続化、スコープの絞り込み UI、トークン失効エンドポイントがありません
- トークン・認可コード・CIMD キャッシュはすべてプロセス内メモリで、TTL 掃除もしていません
- CIMD 取得時の SSRF 対策 (内部アドレスの拒否、レスポンスサイズ上限) を入れていません
- レート制限、監査ログ、同意画面の CSRF 対策がありません
