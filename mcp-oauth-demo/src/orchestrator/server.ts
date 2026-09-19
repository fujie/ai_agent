/**
 * オーケストレーター (図の "オーケストレーター (MCP Client / Oauth Client)") と Chat UI。
 *
 * 図の流れを、最新の MCP 仕様に沿う形に整理して実装している:
 *   1. プロンプト指示    : ユーザー → Chat UI
 *   2. 起動              : Chat UI → オーケストレーター
 *   3. 推論指示          : オーケストレーター → LLM
 *   4. MCP Server 呼び出し指示 : LLM → オーケストレーター
 *   5. アクセス試行      : オーケストレーター → MCP Server (トークン無し → 401)
 *   9. PRM 取得          : オーケストレーター → MCP Server
 *  10. 認可リクエスト    : オーケストレーター → AS (PAR)。AS はここで CIMD を取得・検証し、
 *                          信頼ポリシーを確認して、未登録なら登録する (元の図の 6〜8)
 *  11. 認可 URL を指示   : AS → オーケストレーター (request_uri)
 *  12. 認可 URL の提示   : オーケストレーター → ブラウザ (ユーザーの同意を得て開く)
 *  13. 認可              : ユーザー → ブラウザ (同意画面)
 *  14. Callback          : ブラウザ → オーケストレーター (認可コード)
 *  15. 認可コードとトークンを交換 : オーケストレーター → AS
 *  16. リソースアクセス  : オーケストレーター → MCP Server (Bearer 付き)
 *
 * 元の図の 12「Elicitation URL Mode」は、MCP 仕様上はクライアント自身の認可には使えない。
 * そこで 12 は通常の「認可 URL の提示」とし、URL モードの Elicitation は本来の用途
 * (MCP Server が外部サービスの認可を必要とする場面。partner_hello ツール) で扱う。
 *   E1. LLM が partner_hello を指示
 *   E2. MCP Server が input_required (URL モードの Elicitation) を返す
 *   E3. オーケストレーターが URL を示してユーザーに同意を求める
 *   E4. 同意を添えて tools/call を再試行 (MRTR)
 *   E5〜E7. ブラウザでの本人確認と外部サービスの認可、外部 API 呼び出し (MCP Server 側)
 */
import crypto from 'node:crypto';
import path from 'node:path';
import express, { type Response } from 'express';
import cors from 'cors';
import {
  AS_ISSUER,
  BASE,
  BIND_HOST,
  MCP_PROTOCOL_VERSION,
  ORCHESTRATORS,
  RESOURCE_URI,
  SCOPE,
} from '../shared/config.js';
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
  selectScopes,
  validateAuthorizationResponseIssuer,
  type AuthorizationServerMetadata,
  type TokenSet,
} from './oauth-client.js';
import * as mcp from './mcp-client.js';
import { UnauthorizedError } from '@modelcontextprotocol/client';

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

// ------------------------------------------------------------------ URL モード Elicitation (E3 / E4)
type ElicitAction = 'accept' | 'decline' | 'cancel';
interface PendingElicitation {
  sessionId: string;
  resolve: (action: ElicitAction) => void;
  timer: NodeJS.Timeout;
}
const pendingElicitations = new Map<string, PendingElicitation>();

/**
 * MCP サーバーから URL モードの Elicitation が来たときの処理 (E3)。
 *
 * MCP 仕様がクライアントに求めること:
 *  - どのサーバーからの依頼かを明示する (MUST)
 *  - URL 全体を見せ、ユーザーの明示的な同意なしに開かない (MUST / MUST NOT)
 *  - URL を事前に取得 (プリフェッチ) しない (MUST NOT)
 *  - ドメインを強調表示する (SHOULD)。拒否・キャンセルをいつでもできる (SHOULD)
 * このため URL は Chat UI にそのまま示し、ユーザーのボタン操作を待つ。
 */
function urlElicitationHandler(sessionId: string): mcp.UrlElicitationHandler {
  return ({ message, url }) =>
    new Promise<ElicitAction>((resolve) => {
      const id = crypto.randomUUID();
      const timer = setTimeout(() => {
        pendingElicitations.delete(id);
        flow(sessionId, { step: 'E3', title: 'Elicitation が時間切れになりました', level: 'warn' });
        send(sessionId, 'elicitation-done', { id });
        resolve('cancel');
      }, 180_000);
      pendingElicitations.set(id, { sessionId, resolve, timer });

      let host = '(不正な URL)';
      try {
        host = new URL(url).host;
      } catch {
        /* 不正な URL は UI 側でも開けないように、そのまま表示だけする */
      }
      flow(sessionId, {
        step: 'E3',
        title: 'MCP サーバーから URL モードの Elicitation を受け取りました',
        detail: `依頼元=Hello MCP Server / 開く先=${host} — ユーザーの同意を待ちます`,
      });
      send(sessionId, 'elicitation', {
        id,
        server: 'Hello MCP Server',
        message,
        url,
        host,
      });
    });
}

/** Chat UI からの回答 (同意して開いた / 拒否 / キャンセル)。 */
app.post('/api/elicitation/:id', (req, res) => {
  const entry = pendingElicitations.get(req.params.id);
  const action = req.body?.action as ElicitAction | undefined;
  if (!entry || entry.sessionId !== req.body?.sessionId) {
    res.status(404).json({ error: 'この Elicitation は見つかりません' });
    return;
  }
  if (action !== 'accept' && action !== 'decline' && action !== 'cancel') {
    res.status(400).json({ error: 'action は accept / decline / cancel のいずれかです' });
    return;
  }
  pendingElicitations.delete(req.params.id);
  clearTimeout(entry.timer);
  const label = { accept: '同意して URL を開きました', decline: '拒否しました', cancel: 'キャンセルしました' }[action];
  flow(entry.sessionId, {
    step: 'E4',
    title: `ユーザーが${label}`,
    detail: action === 'accept' ? '同意を添えて tools/call を再試行します (MRTR)。サーバーはブラウザでの連携完了を待ちます' : undefined,
    level: action === 'accept' ? 'ok' : 'warn',
  });
  send(entry.sessionId, 'elicitation-done', { id: req.params.id });
  entry.resolve(action);
  res.json({ ok: true });
});

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

  // RFC 9207 / MCP 認可仕様: 認可コードをどこかへ送る前に、どの AS から返ってきたかを検証する。
  // 検証に失敗した場合は error / error_description を表示・利用してはならない (MUST NOT)
  // ので、エラー応答の処理よりも先に行う。
  const iss = typeof req.query.iss === 'string' ? req.query.iss : undefined;
  const issCheck = validateAuthorizationResponseIssuer(entry.as, iss);
  if (!issCheck.ok) {
    flow(entry.sessionId, { step: 14, title: 'Callback', detail: issCheck.reason, level: 'error' });
    entry.reject(new Error(issCheck.reason));
    res.status(400).type('html').send(callbackPage('認可サーバーの検証に失敗しました。', false));
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
    detail: `code=${code.slice(0, 8)}… / state 検証 OK / iss 検証 OK (${iss ?? 'なし'})`,
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
  {
    name: 'partner_hello',
    description: '外部サービス (Partner Greeting Service) から挨拶を取得する (hello-mcp-server)',
  },
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

  // (5) アクセス試行 — トークン無しで MCP (server/discover) を叩いて 401 を受け取る
  const probe = await mcp.probeResource();
  flow(sessionId, {
    step: 5,
    title: `アクセス試行 (server/discover, MCP ${MCP_PROTOCOL_VERSION}, トークン無し)`,
    detail: `HTTP ${probe.status} / WWW-Authenticate: ${probe.wwwAuthenticate ?? 'なし'}`,
    level: probe.status === 401 ? 'ok' : 'warn',
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
  // トークンは AS ごとに分けて保持する。このリソースの AS がどれかを覚えておく
  tokens.rememberIssuer(RESOURCE_URI, issuer);

  // AS メタデータ取得 (RFC 8414 → OIDC Discovery の順に探索し、issuer 一致と PKCE 対応を確認)
  const as = await fetchAuthorizationServerMetadata(issuer);
  flow(sessionId, {
    title: 'AS メタデータ取得 (RFC 8414)',
    detail:
      `issuer=${as.issuer} / PKCE=${as.code_challenge_methods_supported?.join(',')} / ` +
      `PAR=${as.pushed_authorization_request_endpoint ? 'あり' : 'なし'} / ` +
      `iss 応答=${as.authorization_response_iss_parameter_supported ?? false} / ` +
      `CIMD 対応=${as.client_id_metadata_document_supported ?? false}`,
    level: 'ok',
  });
  if (!as.client_id_metadata_document_supported) {
    // 登録手段の優先順位は 事前登録 → CIMD → DCR。このデモは CIMD しか持たない
    throw new Error('AS が Client ID Metadata Document に対応していないため、クライアントを識別できません');
  }

  // スコープの決定 (MCP の Scope Selection Strategy: 401 の scope → PRM の scopes_supported → 省略)
  const scopes = selectScopes(parsed.scope, prm);
  const scopeSource = { challenge: '401 の scope', prm: 'PRM の scopes_supported', none: '指定なし' };

  // (10) 認可リクエスト → (11) 認可 URL
  const request = await createAuthorizationRequest(as, { resource: RESOURCE_URI, scope: scopes.scope });
  flow(sessionId, {
    step: 10,
    title: '認可リクエスト (PAR) — AS が CIMD を取得・検証し、信頼ポリシーと登録状況を確認',
    detail:
      `client_id=${PROFILE.clientId} / PKCE=S256 / resource=${RESOURCE_URI} / ` +
      `scope=${scopes.scope ?? '(なし)'} (${scopeSource[scopes.source]})`,
    level: 'ok',
  });
  flow(sessionId, {
    step: 11,
    title: '認可 URL を取得',
    detail: request.authorizationUrl,
    level: 'ok',
  });

  // (12) 認可 URL をユーザーに示し、同意を得てブラウザで開いてもらう
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
    title: '認可 URL の提示',
    detail: 'ブラウザで認可サーバーを開いてもらいます (MCP の Elicitation ではなく、クライアント自身の認可)',
  });
  // これはこのクライアント自身が MCP サーバーへのアクセス許可を得る手順で、MCP の Elicitation
  // ではない (URL モードの Elicitation をクライアント自身の認可に使うことは仕様で否定されている)。
  // ただし URL を開く前に宛先を示して同意を得る、という安全策は同じように取る。
  send(sessionId, 'authorization-request', {
    message: 'このアプリが MCP サーバー (Hello MCP Server) にアクセスする許可を求めています。',
    url: request.authorizationUrl,
    host: new URL(request.authorizationUrl).host,
  });

  // (13) ユーザーがブラウザで認可 → (14) Callback で code を受け取る
  const code = await codePromise;

  // (15) 認可コードとトークンを交換
  const token = await exchangeAuthorizationCode(as, {
    code,
    verifier: request.pkce.verifier,
    resource: request.resource,
    scope: request.scope,
  });
  tokens.set(sessionId, token);
  flow(sessionId, {
    step: 15,
    title: '認可コードとトークンを交換',
    detail: `issuer=${token.issuer} / scope=${token.scope ?? '(なし)'} / 有効期限=${new Date(token.expires_at * 1000).toLocaleTimeString('ja-JP')}`,
    level: 'ok',
  });
  send(sessionId, 'authorization-done', {});
  return token;
}

/** MCP サーバーがトークンを 401 で拒否したか (期限切れ・AS の鍵が変わった等)。 */
function isUnauthorized(err: unknown): boolean {
  if (UnauthorizedError.isInstance(err)) return true;
  const e = err as { status?: number; code?: number; data?: { status?: number } } | undefined;
  return e?.status === 401 || e?.data?.status === 401;
}

/**
 * アクセストークンを用意して MCP に接続する。
 * 手元のトークンが 401 で拒否された場合は、MCP 認可仕様どおり破棄して認可をやり直す (1 回だけ)。
 */
async function connectWithToken(sessionId: string): Promise<mcp.McpSession> {
  const token = await obtainAccessToken(sessionId);
  try {
    return await mcp.connect(token.access_token, urlElicitationHandler(sessionId));
  } catch (err) {
    if (!isUnauthorized(err)) throw err;
    flow(sessionId, {
      title: 'トークンが拒否されました (401)',
      detail: '手元のトークンを破棄して、認可をやり直します',
      level: 'warn',
    });
    tokens.clear(sessionId, RESOURCE_URI);
    const fresh = await obtainAccessToken(sessionId);
    return mcp.connect(fresh.access_token, urlElicitationHandler(sessionId));
  }
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
  const isPartner = call.name === 'partner_hello';
  flow(sessionId, {
    step: isPartner ? '4 / E1' : 4,
    title: isPartner ? 'MCP Server 呼び出し指示 (外部サービス連携が必要なツール)' : 'MCP Server 呼び出し指示',
    detail: `${call.name}(${JSON.stringify(call.arguments)})`,
    level: 'ok',
  });

  // (5)〜(15) 必要ならアクセストークンを取得し、(16) Bearer 付きで MCP に接続する
  const session = await connectWithToken(sessionId);
  try {
    const tools = await mcp.listTools(session);
    flow(sessionId, {
      step: 16,
      title: `MCP 接続成功 (server/discover → tools/list, MCP ${session.protocolVersion})`,
      detail: tools.map((t) => t.name).join(', '),
      level: 'ok',
    });
    if (!tools.some((t) => t.name === call.name)) {
      throw new Error(`MCP サーバーに ${call.name} ツールがありません`);
    }

    // partner_hello では、この呼び出しの中で input_required (URL モード Elicitation) → ユーザーの同意
    // → 再試行 (MRTR) が起こりうる。SDK がこれを 1 回の callTool の内側で処理する。
    const text = await mcp.callTool(session, call.name, call.arguments);
    flow(sessionId, {
      step: isPartner ? '16 / E7' : 16,
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
    send(sessionId, 'authorization-done', {});
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

app.listen(PROFILE.port, BIND_HOST, () => {
  log.info(`オーケストレーター (${PROFILE.label}) を起動しました: ${PROFILE.base} (bind ${BIND_HOST})`);
  log.info(`CIMD (client_id): ${PROFILE.clientId}`);
  if (PROFILE.variant === 'untrusted') {
    log.warn('このクライアントは Client registry の許可リストに載っていません (認可は失敗します)');
  }
});
