/**
 * オーケストレーター (図の "オーケストレーター (MCP Client / Oauth Client)") と Chat UI。
 *
 * 図の流れをそのまま実装している:
 *   1. プロンプト指示    : ユーザー → Chat UI
 *   2. 起動              : Chat UI → オーケストレーター
 *   3. 推論指示          : オーケストレーター → LLM
 *   4. MCP Server 呼び出し指示 : LLM → オーケストレーター
 *   5. アクセス試行      : オーケストレーター → MCP Server (トークン無し → 401)
 *   6-8. CIMD 確認 / 返却 / クライアント登録 : MCP Server ↔ Client registry ↔ AS
 *   9. PRM 取得          : オーケストレーター → MCP Server
 *  10. 認可リクエスト    : オーケストレーター → AS (PAR)
 *  11. 認可 URL を指示   : AS → オーケストレーター (request_uri)
 *  12. Elicitation URL Mode : オーケストレーター → ブラウザ
 *  13. 認可              : ユーザー → ブラウザ (同意画面)
 *  14. Callback          : ブラウザ → オーケストレーター (認可コード)
 *  15. 認可コードとトークンを交換 : オーケストレーター → AS
 *  16. リソースアクセス  : オーケストレーター → MCP Server (Bearer 付き)
 */
import path from 'node:path';
import express, { type Response } from 'express';
import cors from 'cors';
import { AS_ISSUER, BASE, ORCHESTRATORS, RESOURCE_URI, SCOPE } from '../shared/config.js';
import { PROFILE } from './profile.js';
import { createLogger } from '../shared/log.js';
import {
  TokenStore,
  createAuthorizationRequest,
  exchangeAuthorizationCode,
  fetchAuthorizationServerMetadata,
  fetchProtectedResourceMetadata,
  guessResourceMetadataUrls,
  parseWwwAuthenticate,
  type AuthorizationServerMetadata,
  type TokenSet,
} from './oauth-client.js';
import * as mcp from './mcp-client.js';

const log = createLogger(PROFILE.variant === 'trusted' ? 'orchestrator' : 'orchestrator!');
const app = express();

// Chat UI は片方のオーケストレーターから配信されるが、設定でもう片方を
// 呼び出せるようにしているので、両方のオリジンからのアクセスを許可する。
app.use(
  cors({
    origin: [BASE.orchestrator, BASE.orchestratorUntrusted],
    methods: ['GET', 'POST', 'OPTIONS'],
  }),
);
app.use(express.json());

// ------------------------------------------------------------------ SSE
type FlowLevel = 'info' | 'ok' | 'warn' | 'error';
interface FlowEvent {
  step?: number | string;
  title: string;
  detail?: string;
  level?: FlowLevel;
}

const streams = new Map<string, Set<Response>>();

/**
 * 送信済みイベントの履歴。
 * 認可のためにブラウザが別ページへ移動すると SSE が切れるので、
 * 再接続時に取りこぼしを埋められるようにセッションごとに保持しておく。
 */
interface StoredEvent {
  id: number;
  event: string;
  data: unknown;
}
const history = new Map<string, StoredEvent[]>();
const HISTORY_LIMIT = 500;
let eventSeq = 0;

function frame(e: StoredEvent): string {
  return `id: ${e.id}\nevent: ${e.event}\ndata: ${JSON.stringify(e.data)}\n\n`;
}

function send(sessionId: string, event: string, data: unknown): void {
  const stored: StoredEvent = { id: ++eventSeq, event, data };

  const log = history.get(sessionId) ?? [];
  log.push(stored);
  if (log.length > HISTORY_LIMIT) log.splice(0, log.length - HISTORY_LIMIT);
  history.set(sessionId, log);

  for (const res of streams.get(sessionId) ?? []) res.write(frame(stored));
}

function flow(sessionId: string, e: FlowEvent): void {
  if (e.step !== undefined) log.step(e.step, `${e.title}${e.detail ? ` — ${e.detail}` : ''}`);
  else log.info(`${e.title}${e.detail ? ` — ${e.detail}` : ''}`);
  send(sessionId, 'flow', { ...e, at: new Date().toISOString() });
}

app.get('/api/events', (req, res) => {
  const sessionId = String(req.query.session ?? '');
  if (!sessionId) {
    res.status(400).end();
    return;
  }
  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache',
    connection: 'keep-alive',
  });
  res.write(': connected\n\n');

  // 再接続なら Last-Event-ID 以降を、新規接続ならこのセッションの全履歴を送り直す
  const lastEventId = Number(req.header('last-event-id') ?? req.query.lastEventId ?? 0);
  for (const stored of history.get(sessionId) ?? []) {
    if (stored.id > lastEventId) res.write(frame(stored));
  }

  const set = streams.get(sessionId) ?? new Set<Response>();
  set.add(res);
  streams.set(sessionId, set);

  const keepAlive = setInterval(() => res.write(': ping\n\n'), 20_000);
  req.on('close', () => {
    clearInterval(keepAlive);
    set.delete(res);
    if (set.size === 0) streams.delete(sessionId);
  });
});

// ------------------------------------------------------------------ CIMD の公開
/**
 * Client ID Metadata Document。
 * この URL そのものが client_id であり、AS / Client registry はここを読んで
 * クライアントを識別する (動的クライアント登録は不要)。
 */
app.get('/oauth/client-metadata.json', (_req, res) => {
  log.info('CIMD が取得されました');
  res.type('application/json').json({
    client_id: PROFILE.clientId,
    client_name: PROFILE.clientName,
    client_uri: PROFILE.base,
    logo_uri: `${PROFILE.base}/logo.svg`,
    redirect_uris: [PROFILE.redirectUri],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    scope: SCOPE,
    policy_uri: `${PROFILE.base}/policy`,
    tos_uri: `${PROFILE.base}/terms`,
    software_id: `mcp-oauth-cimd-demo-orchestrator-${PROFILE.variant}`,
    software_version: '1.0.0',
  });
});

app.get('/logo.svg', (_req, res) => {
  // 同意画面でどちらのクライアントか見分けられるように色を変えておく
  const fill = PROFILE.variant === 'trusted' ? '#2f6df6' : '#b91c1c';
  res
    .type('image/svg+xml')
    .send(
      `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="${fill}"/><path d="M18 42V22h6l8 12 8-12h6v20h-6V32l-8 11-8-11v10z" fill="#fff"/></svg>`,
    );
});
app.get('/policy', (_req, res) => res.type('html').send('<h1>プライバシーポリシー (デモ)</h1>'));
app.get('/terms', (_req, res) => res.type('html').send('<h1>利用規約 (デモ)</h1>'));

// ------------------------------------------------------------------ 認可待ちの管理
interface PendingAuthorization {
  sessionId: string;
  verifier: string;
  resource: string;
  as: AuthorizationServerMetadata;
  resolve: (code: string) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
}

const pending = new Map<string, PendingAuthorization>();
const tokens = new TokenStore();

function callbackPage(message: string, ok: boolean): string {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>認可</title>
<style>body{font-family:system-ui,"Hiragino Sans",sans-serif;display:grid;place-items:center;height:100vh;margin:0;background:#f4f5f7}
.box{background:#fff;padding:32px 40px;border-radius:14px;box-shadow:0 8px 30px rgba(0,0,0,.08);text-align:center;max-width:420px}
.icon{font-size:40px}p{color:#333;line-height:1.7}small{color:#888}
@media (prefers-color-scheme:dark){body{background:#15171b}.box{background:#1e2127}p{color:#e8eaed}}</style></head>
<body><div class="box"><div class="icon">${ok ? '✅' : '⚠️'}</div><p>${message}</p>
<small>このタブは閉じてかまいません。</small>
<script>setTimeout(()=>window.close(),${ok ? 2500 : 6000})</script></div></body></html>`;
}

/** (14) Callback。ブラウザから認可コードを受け取る。 */
app.get('/oauth/callback', (req, res) => {
  const state = String(req.query.state ?? '');
  const entry = pending.get(state);

  if (!entry) {
    res
      .status(400)
      .type('html')
      .send(callbackPage('この認可リクエストは見つかりませんでした。', false));
    return;
  }
  pending.delete(state);
  clearTimeout(entry.timer);

  // RFC 9207: どの AS から返ってきたのかを検証する
  const iss = req.query.iss ? String(req.query.iss) : undefined;
  if (iss && iss !== entry.as.issuer) {
    entry.reject(new Error(`予期しない issuer からの応答です: ${iss}`));
    res.status(400).type('html').send(callbackPage('issuer が一致しません。', false));
    return;
  }

  if (req.query.error) {
    const error = String(req.query.error);
    flow(entry.sessionId, {
      step: 14,
      title: 'Callback',
      detail: `認可が拒否されました (${error})`,
      level: 'error',
    });
    entry.reject(new Error(`認可されませんでした: ${error}`));
    res.type('html').send(callbackPage('認可をキャンセルしました。', false));
    return;
  }

  const code = String(req.query.code ?? '');
  if (!code) {
    entry.reject(new Error('認可コードがありません'));
    res.status(400).type('html').send(callbackPage('認可コードがありません。', false));
    return;
  }

  flow(entry.sessionId, {
    step: 14,
    title: 'Callback (認可コード)',
    detail: `code=${code.slice(0, 8)}… / state 検証 OK`,
    level: 'ok',
  });
  entry.resolve(code);
  res.type('html').send(callbackPage('認可が完了しました。チャット画面に戻ってください。', true));
});

// ------------------------------------------------------------------ LLM 呼び出し
interface LlmMessage {
  role: 'user' | 'assistant' | 'tool';
  content: string;
  tool_name?: string;
}
interface LlmToolCall {
  id: string;
  server: string;
  name: string;
  arguments: Record<string, unknown>;
}
type LlmResponse =
  | { type: 'tool_call'; tool_calls: LlmToolCall[] }
  | { type: 'message'; content: string };

async function infer(messages: LlmMessage[], tools: mcp.ToolSummary[]): Promise<LlmResponse> {
  const res = await fetch(`${BASE.llm}/v1/infer`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ messages, tools }),
  });
  if (!res.ok) throw new Error(`LLM の呼び出しに失敗しました (HTTP ${res.status})`);
  return (await res.json()) as LlmResponse;
}

/**
 * 接続前に LLM へ提示するツールカタログ。
 * 実際のクライアントも、未接続の MCP サーバーについては設定やキャッシュから
 * ツール一覧を持っていることが多い。接続後に listTools で必ず突き合わせる。
 */
const TOOL_CATALOG: mcp.ToolSummary[] = [
  { name: 'hello', description: '挨拶を返す (hello-mcp-server)' },
];

// ------------------------------------------------------------------ トークン取得 (5 → 15)
async function obtainAccessToken(sessionId: string): Promise<TokenSet> {
  const cached = tokens.get(sessionId, RESOURCE_URI);
  if (cached) {
    flow(sessionId, {
      step: 5,
      title: 'アクセストークンは取得済み',
      detail: '認可フローをスキップします',
      level: 'ok',
    });
    return cached;
  }

  // (5) アクセス試行 — トークン無しで MCP を叩いて 401 を受け取る
  const probe = await mcp.probeResource();
  flow(sessionId, {
    step: 5,
    title: 'アクセス試行 (トークン無し)',
    detail: `HTTP ${probe.status} / WWW-Authenticate: ${probe.wwwAuthenticate ?? 'なし'}`,
    level: probe.status === 401 ? 'ok' : 'warn',
  });
  flow(sessionId, {
    step: '6-8',
    title: 'MCP Server による CIMD 確認とクライアント登録',
    detail: 'MCP Server → Client registry → Authorization Server (各サーバーのログを参照)',
  });

  // (9) PRM 取得
  const parsed = parseWwwAuthenticate(probe.wwwAuthenticate);
  const candidates = parsed.resource_metadata
    ? [parsed.resource_metadata]
    : guessResourceMetadataUrls(RESOURCE_URI);

  let prm;
  let lastError: unknown;
  for (const url of candidates) {
    try {
      prm = await fetchProtectedResourceMetadata(url);
      flow(sessionId, {
        step: 9,
        title: 'PRM 取得',
        detail: `resource=${prm.resource} / authorization_servers=${(prm.authorization_servers ?? []).join(', ')}`,
        level: 'ok',
      });
      break;
    } catch (err) {
      lastError = err;
    }
  }
  if (!prm) throw new Error(`PRM を取得できません: ${(lastError as Error)?.message}`);

  // PRM の resource は、自分がアクセスしようとしている URI と一致していなければならない
  if (prm.resource !== RESOURCE_URI) {
    throw new Error(`PRM の resource が一致しません: ${prm.resource}`);
  }
  const issuer = prm.authorization_servers?.[0];
  if (!issuer) throw new Error('PRM に authorization_servers がありません');

  const as = await fetchAuthorizationServerMetadata(issuer);
  flow(sessionId, {
    title: 'AS メタデータ取得 (RFC 8414)',
    detail: `issuer=${as.issuer} / PAR=${as.pushed_authorization_request_endpoint ?? 'なし'} / CIMD対応=${as.client_id_metadata_document_supported ?? false}`,
    level: 'ok',
  });

  // (10) 認可リクエスト → (11) 認可 URL
  const request = await createAuthorizationRequest(as, { resource: RESOURCE_URI, scope: SCOPE });
  flow(sessionId, {
    step: 10,
    title: '認可リクエスト (PAR)',
    detail: `client_id=${PROFILE.clientId} / PKCE=S256 / resource=${RESOURCE_URI}`,
    level: 'ok',
  });
  flow(sessionId, {
    step: 11,
    title: '認可 URL を取得',
    detail: request.authorizationUrl,
    level: 'ok',
  });

  // (12) Elicitation URL Mode でユーザーに認可を促す
  const codePromise = new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(request.state);
      reject(new Error('認可がタイムアウトしました (3 分)'));
    }, 180_000);
    pending.set(request.state, {
      sessionId,
      verifier: request.pkce.verifier,
      resource: request.resource,
      as,
      resolve,
      reject,
      timer,
    });
  });

  flow(sessionId, {
    step: 12,
    title: 'Elicitation (URL Mode)',
    detail: 'ブラウザで認可を依頼します',
  });
  send(sessionId, 'elicitation', {
    // MCP の elicitation/create (URL モード) と同じ形で UI に渡す
    method: 'elicitation/create',
    params: {
      mode: 'url',
      message: 'MCP サーバー (Hello MCP Server) へのアクセスを許可してください。',
      url: request.authorizationUrl,
    },
  });

  // (13) ユーザーがブラウザで認可 → (14) Callback で code を受け取る
  const code = await codePromise;

  // (15) 認可コードとトークンを交換
  const token = await exchangeAuthorizationCode(as, {
    code,
    verifier: request.pkce.verifier,
    resource: request.resource,
  });
  tokens.set(sessionId, token);
  flow(sessionId, {
    step: 15,
    title: '認可コードとトークンを交換',
    detail: `scope=${token.scope} / 有効期限=${new Date(token.expires_at * 1000).toLocaleTimeString('ja-JP')}`,
    level: 'ok',
  });
  send(sessionId, 'elicitation-done', {});
  return token;
}

// ------------------------------------------------------------------ チャット本体
async function runChat(sessionId: string, prompt: string): Promise<void> {
  // チャットの内容もフローもすべてサーバー側の履歴に残す。
  // そうしておくと、認可でページを離れて戻ってきても画面を再現できる。
  send(sessionId, 'message', { role: 'user', content: prompt });
  flow(sessionId, { step: 1, title: 'プロンプト指示', detail: 'ユーザー → Chat UI' });
  flow(sessionId, { step: 2, title: '起動', detail: `プロンプト: ${prompt}` });

  // (3) 推論指示 → (4) MCP Server 呼び出し指示
  const messages: LlmMessage[] = [{ role: 'user', content: prompt }];
  flow(sessionId, { step: 3, title: '推論指示', detail: `LLM (${BASE.llm}) に問い合わせます` });
  const decision = await infer(messages, TOOL_CATALOG);

  if (decision.type === 'message') {
    flow(sessionId, { step: 4, title: 'LLM の応答', detail: 'ツール呼び出しなし' });
    send(sessionId, 'message', { role: 'assistant', content: decision.content });
    return;
  }

  const call = decision.tool_calls[0];
  flow(sessionId, {
    step: 4,
    title: 'MCP Server 呼び出し指示',
    detail: `${call.name}(${JSON.stringify(call.arguments)})`,
    level: 'ok',
  });

  // (5)〜(15) 必要ならアクセストークンを取得
  const token = await obtainAccessToken(sessionId);

  // (16) リソースアクセス
  const session = await mcp.connect(token.access_token);
  try {
    const tools = await mcp.listTools(session);
    flow(sessionId, {
      step: 16,
      title: 'MCP 接続成功 (tools/list)',
      detail: tools.map((t) => t.name).join(', '),
      level: 'ok',
    });
    if (!tools.some((t) => t.name === call.name)) {
      throw new Error(`MCP サーバーに ${call.name} ツールがありません`);
    }

    const text = await mcp.callTool(session, call.name, call.arguments);
    flow(sessionId, {
      step: 16,
      title: 'リソースアクセス (tools/call)',
      detail: text.split('\n')[0],
      level: 'ok',
    });

    // ツール結果を LLM に返して最終回答を作らせる
    messages.push({ role: 'tool', content: text, tool_name: call.name });
    flow(sessionId, { step: 3, title: '推論指示 (ツール結果)', detail: 'LLM に最終回答を作らせます' });
    const final = await infer(messages, TOOL_CATALOG);
    const content = final.type === 'message' ? final.content : JSON.stringify(final);
    send(sessionId, 'message', { role: 'assistant', content });
    flow(sessionId, { title: '完了', detail: 'Chat UI に応答を返しました', level: 'ok' });
  } finally {
    await session.close();
  }
}

app.post('/api/chat', (req, res) => {
  const sessionId = String(req.body?.sessionId ?? '');
  const prompt = String(req.body?.prompt ?? '').trim();
  if (!sessionId || !prompt) {
    res.status(400).json({ error: 'sessionId と prompt が必要です' });
    return;
  }
  res.status(202).json({ accepted: true });

  void runChat(sessionId, prompt).catch((err: Error) => {
    log.error(err.message);
    flow(sessionId, { title: 'エラー', detail: err.message, level: 'error' });
    send(sessionId, 'elicitation-done', {});
    send(sessionId, 'message', {
      role: 'assistant',
      content: `エラーが発生しました: ${err.message}`,
    });
  });
});

/** デモ用: 取得済みトークンを捨てて、次回また認可フローを回せるようにする。 */
app.post('/api/reset', (req, res) => {
  const sessionId = String(req.body?.sessionId ?? '');
  tokens.clear(sessionId, RESOURCE_URI);
  history.delete(sessionId);
  flow(sessionId, { title: 'トークンを破棄しました', detail: '次回は認可フローからやり直します' });
  res.json({ ok: true });
});

app.get('/api/config', (_req, res) => {
  res.json({
    // このプロセス自身の素性
    variant: PROFILE.variant,
    label: PROFILE.label,
    clientName: PROFILE.clientName,
    base: PROFILE.base,
    clientId: PROFILE.clientId,
    // Chat UI の設定に出す選択肢 (信頼できる / できない)
    orchestrators: Object.values(ORCHESTRATORS).map((o) => ({
      variant: o.variant,
      label: o.label,
      description: o.description,
      base: o.base,
      clientId: o.clientId,
      clientName: o.clientName,
    })),
    llm: BASE.llm,
    resource: RESOURCE_URI,
    authorizationServer: AS_ISSUER,
    registry: BASE.registry,
  });
});

app.use(express.static(path.join(import.meta.dirname, 'public')));

app.listen(PROFILE.port, () => {
  log.info(`オーケストレーター (${PROFILE.label}) を起動しました: ${PROFILE.base}`);
  log.info(`CIMD (client_id): ${PROFILE.clientId}`);
  if (PROFILE.variant === 'untrusted') {
    log.warn('このクライアントは Client registry の許可リストに載っていません (認可は失敗します)');
  }
});
