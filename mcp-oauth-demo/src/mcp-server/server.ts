/**
 * MCP Server = OAuth の Resource Server (図の "MCP Server (Resource Server)")
 *
 *  - MCP 2026-07-28 (ステートレス版) の Streamable HTTP でツールを提供する
 *    (initialize ハンドシェイクは無く、各リクエストが `_meta` にプロトコル版を持つ)
 *  - 未認証アクセスには 401 + WWW-Authenticate を返し、
 *    Protected Resource Metadata (RFC 9728) の在り処と必要なスコープを教える (図の 5 → 9)
 *  - アクセストークンは AS の JWKS で検証し、aud が自分自身であることを必ず確認する
 *
 * ツール:
 *  - hello         : 挨拶を返すだけ
 *  - partner_hello : 外部サービス (Partner Greeting Service) の API で挨拶を取ってくる。
 *                    外部サービスの認可が無ければ URL モードの Elicitation で
 *                    ユーザーにブラウザでの連携を依頼する (URL モード Elicitation の本来の用途)
 */
import crypto from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import {
  McpServer,
  createMcpHandler,
  createRequestStateCodec,
  inputRequired,
  inputResponse,
  type AuthInfo,
} from '@modelcontextprotocol/server';
import {
  localhostHostValidation,
  localhostOriginValidation,
  toNodeHandler,
} from '@modelcontextprotocol/node';
import { z } from 'zod';
import {
  AS_ISSUER,
  BASE,
  BIND_HOST,
  MCP_SERVER_CLIENT_ID,
  MCP_SERVER_IDENTITY_REDIRECT_URI,
  PARTNER_API,
  PARTNER_CLIENT_ID,
  PARTNER_ISSUER,
  PARTNER_REDIRECT_URI,
  PARTNER_SCOPE,
  PORTS,
  RESOURCE_URI,
  SCOPE,
} from '../shared/config.js';
import { createLogger } from '../shared/log.js';

const log = createLogger('mcp');
const app = express();

declare global {
  namespace Express {
    interface Request {
      /** 検証済みのアクセストークン情報。toNodeHandler が MCP SDK に引き渡す。 */
      auth?: AuthInfo;
    }
  }
}

const randomId = (bytes = 24) => crypto.randomBytes(bytes).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);

// ------------------------------------------------- DNS リバインディング対策
// MCP の Streamable HTTP 仕様: サーバーはすべての接続で Origin ヘッダを検証しなければならない
// (MUST)。不正な Origin には 403 を返す。ローカルサーバーでは Host の検証が DNS リバインディングを防ぐ。
const validateHost = localhostHostValidation();
const validateOrigin = localhostOriginValidation();

function dnsRebindingGuard(req: Request, res: Response, next: NextFunction): void {
  if (!validateHost(req, res)) {
    log.warn(`不正な Host ヘッダを拒否しました: ${req.headers.host}`);
    return;
  }
  if (!validateOrigin(req, res)) {
    log.warn(`不正な Origin ヘッダを拒否しました: ${req.headers.origin}`);
    return;
  }
  next();
}

app.use(dnsRebindingGuard);
app.use(express.json());

const PRM_URL = `${BASE.resource}/.well-known/oauth-protected-resource`;
const jwks = createRemoteJWKSet(new URL(`${AS_ISSUER}/jwks.json`));

// ------------------------------------------------- Protected Resource Metadata (9)
const protectedResourceMetadata = {
  resource: RESOURCE_URI,
  authorization_servers: [AS_ISSUER],
  scopes_supported: [SCOPE],
  bearer_methods_supported: ['header'],
  resource_name: 'Hello MCP Server',
  resource_documentation: `${BASE.resource}/docs`,
};

// RFC 9728 はリソースのパスを .well-known の後ろに差し込む形も定義している
app.get('/.well-known/oauth-protected-resource', (_req, res) => {
  log.step(9, 'Protected Resource Metadata を返します');
  res.json(protectedResourceMetadata);
});
app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => {
  log.step(9, 'Protected Resource Metadata を返します (path 付き)');
  res.json(protectedResourceMetadata);
});

app.get('/docs', (_req, res) => {
  res
    .type('html')
    .send(
      '<h1>Hello MCP Server</h1><p>ツール: <code>hello</code>, <code>partner_hello</code></p>',
    );
});

// ------------------------------------------------- アクセストークン検証

/** HTTP ヘッダは ASCII しか運べないので、ヘッダ用に安全な文字だけを残す。 */
function toHeaderSafe(value: string): string {
  return value.replace(/[^\x20-\x7e]/g, '').replace(/"/g, "'") || 'authentication required';
}

/**
 * 401 チャレンジ (RFC 6750 §3 / RFC 9728 §5.1 / MCP の Scope Selection Strategy)。
 *
 *  - resource_metadata: Protected Resource Metadata の場所
 *  - scope: このリソースに必要なスコープ (MCP は含めることを推奨 = SHOULD)
 *  - error: トークンが「無い」場合は付けない。RFC 6750 §3.1 は、認証情報を全く含まない
 *    リクエストにはエラーコードを含めるべきでない (SHOULD NOT) としている。
 *    トークンが「あるが無効」な場合だけ invalid_token を付ける。
 *
 * ヘッダには ASCII のみを入れ、日本語の説明は JSON ボディ側に置く。
 */
function challenge(
  res: Response,
  opts: { error?: 'invalid_token'; description: string; headerHint?: string },
): void {
  const params = ['realm="mcp"'];
  if (opts.error) {
    params.push(`error="${opts.error}"`);
    if (opts.headerHint) params.push(`error_description="${toHeaderSafe(opts.headerHint)}"`);
  }
  params.push(`scope="${SCOPE}"`, `resource_metadata="${PRM_URL}"`);
  res.setHeader('WWW-Authenticate', `Bearer ${params.join(', ')}`);
  res.status(401).json({
    jsonrpc: '2.0',
    error: { code: -32001, message: opts.description },
    id: null,
  });
}

async function requireAccessToken(req: Request, res: Response, next: NextFunction): Promise<void> {
  const header = req.header('authorization');

  if (!header?.toLowerCase().startsWith('bearer ')) {
    log.step(5, '未認証のアクセス試行です。401 を返します (PRM の場所と必要なスコープを添える)');
    challenge(res, { description: 'アクセストークンがありません' });
    return;
  }

  const token = header.slice(7).trim();
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: AS_ISSUER,
      // 最重要: このトークンが「自分向け」に発行されたものかを必ず確認する
      // (トークンの使い回し / confused deputy を防ぐ)
      audience: RESOURCE_URI,
      typ: 'at+jwt', // RFC 9068: JWT アクセストークン以外 (ID トークン等) を受け付けない
    });
    const scopes = String(payload.scope ?? '')
      .split(' ')
      .filter(Boolean);
    if (!scopes.includes(SCOPE)) {
      // MCP の Runtime Insufficient Scope Errors: 403 + insufficient_scope + 必要なスコープ
      res.setHeader(
        'WWW-Authenticate',
        `Bearer realm="mcp", error="insufficient_scope", scope="${SCOPE}", resource_metadata="${PRM_URL}"`,
      );
      res
        .status(403)
        .json({ jsonrpc: '2.0', error: { code: -32002, message: 'scope が不足しています' }, id: null });
      return;
    }
    req.auth = {
      token,
      clientId: String(payload.client_id ?? ''),
      scopes,
      expiresAt: payload.exp,
      resource: new URL(RESOURCE_URI),
      extra: { sub: String(payload.sub), name: payload.name, email: payload.email },
    };
    log.info(`トークン検証 OK (sub=${payload.sub}, aud=${RESOURCE_URI})`);
    next();
  } catch (err) {
    log.warn(`トークン検証に失敗: ${(err as Error).message}`);
    challenge(res, {
      error: 'invalid_token',
      description: (err as Error).message,
      headerHint: (err as Error).message,
    });
  }
}

// ================================================= 外部サービス連携 (URL モード Elicitation)
//
// 流れ (E は Elicitation シナリオのステップ):
//  E2  partner_hello が呼ばれたが外部サービスのトークンが無い
//      → input_required (elicitation/create, mode=url) を返す。requestState は HMAC で保護し、
//        MCP のユーザー (sub) に束縛する
//  E4  クライアントがユーザーの同意 (accept) を添えて再試行 → ブラウザでの連携完了を待つ
//  E5  ブラウザで連携 URL が開かれる → まず MCP の AS で「誰が開いたか」を確認 (フィッシング対策)
//  E6  本人と確認できたら外部サービスの認可へ → 取得したトークンを sub に紐付けて保存
//  E7  待っていた再試行の中で外部 API を呼び、結果を返す
//
// 外部サービスのトークンは MCP Server だけが持ち、MCP クライアントには決して渡さない (MUST NOT)。

interface Elicitation {
  sub: string;
  clientId: string;
  status: 'pending' | 'done' | 'denied';
  expires_at: number;
}
/** 発行した連携要求。URL には推測不能な ID だけを載せ、ユーザー情報は載せない。 */
const elicitations = new Map<string, Elicitation>();
/** 外部サービスのトークン。MCP のユーザー (sub) ごとに保持する。 */
const partnerTokens = new Map<string, { access_token: string; expires_at: number }>();
/** ブラウザ側の連携フローの一時状態 (state → 内容)。 */
const connectStates = new Map<
  string,
  { kind: 'identity' | 'partner'; eid: string; verifier: string; nonce?: string; expires_at: number }
>();

/**
 * requestState はクライアントを経由して戻ってくる「攻撃者が改ざんできる入力」なので、
 * 認可に影響する以上、完全性を保護しなければならない (MUST)。SDK の HMAC コーデックを使い、
 * さらに MCP のユーザー (sub) に束縛して、別ユーザーの状態を使い回せないようにする。
 */
const stateCodec = createRequestStateCodec<{ eid: string }>({
  key: crypto.randomBytes(32), // 1 プロセスで全ラウンドを処理するので、起動ごとの鍵でよい
  ttlSeconds: 600,
  bind: (ctx) => String(ctx.http?.authInfo?.extra?.sub ?? ''),
});

function pkcePair() {
  const verifier = randomId(32);
  return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') };
}

function validPartnerToken(sub: string) {
  const t = partnerTokens.get(sub);
  return t && t.expires_at - 30 > now() ? t : undefined;
}

async function callPartnerApi(sub: string, name: string) {
  const token = validPartnerToken(sub)!;
  log.step('E7', `外部サービスの API を呼びます (sub=${sub})`);
  const res = await fetch(`${PARTNER_API}?${new URLSearchParams({ name })}`, {
    headers: { authorization: `Bearer ${token.access_token}` },
  });
  if (!res.ok) {
    partnerTokens.delete(sub);
    return {
      isError: true,
      content: [
        { type: 'text' as const, text: `外部サービスの API 呼び出しに失敗しました (HTTP ${res.status})` },
      ],
    };
  }
  const body = (await res.json()) as { greeting: string };
  return {
    content: [
      { type: 'text' as const, text: body.greeting },
      {
        type: 'text' as const,
        text: '(外部サービスのトークンは MCP Server が保持しており、MCP クライアントには渡していません)',
      },
    ],
  };
}

/** ブラウザでの連携が終わるまで待つ (再試行されたリクエストの中で待つ)。 */
async function waitForConnection(
  sub: string,
  eid: string,
  signal: AbortSignal,
  timeoutMs = 180_000,
): Promise<'done' | 'denied' | 'timeout' | 'aborted'> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (signal.aborted) return 'aborted';
    if (validPartnerToken(sub)) return 'done';
    if (elicitations.get(eid)?.status === 'denied') return 'denied';
    await new Promise((r) => setTimeout(r, 500));
  }
  return 'timeout';
}

// ------------------------------------------------- MCP 本体
/**
 * リクエストごとに呼ばれるサーバーファクトリ。
 * createMcpHandler が server/discover・resultType・キャッシュヒント (ttlMs / cacheScope)・
 * Mcp-Method / MCP-Protocol-Version ヘッダの検証など、2026-07-28 の要件を処理する。
 */
function buildServer(auth: AuthInfo | undefined): McpServer {
  const server = new McpServer(
    { name: 'hello-mcp-server', version: '1.0.0' },
    {
      capabilities: { tools: {} },
      // 認証付きの応答なので共有キャッシュには載せない (private)
      cacheHints: { 'tools/list': { ttlMs: 60_000, cacheScope: 'private' } },
      // 戻ってきた requestState は、ハンドラに入る前に SDK がこの verify で検証する
      requestState: { verify: stateCodec.verify },
    },
  );

  server.registerTool(
    'hello',
    {
      title: 'Hello',
      description: '挨拶を返します。name を渡すとその名前で挨拶します。',
      inputSchema: z.object({ name: z.string().optional().describe('挨拶する相手の名前') }),
    },
    async ({ name }) => {
      const who = name?.trim() || (auth?.extra?.name as string | undefined) || 'World';
      log.step(16, `hello ツールを実行しました (name=${who})`);
      return {
        content: [
          { type: 'text' as const, text: `Hello, ${who}!` },
          {
            type: 'text' as const,
            text: `(MCP Server が認証済みリクエストとして処理しました: sub=${auth?.extra?.sub}, client_id=${auth?.clientId})`,
          },
        ],
      };
    },
  );

  server.registerTool(
    'partner_hello',
    {
      title: 'Partner Hello',
      description:
        '外部サービス (Partner Greeting Service) から挨拶を取得します。初回は外部サービスとの連携 (ブラウザでの許可) が必要です。',
      inputSchema: z.object({ name: z.string().optional().describe('挨拶する相手の名前') }),
    },
    async ({ name }, ctx) => {
      const sub = auth?.extra?.sub as string | undefined;
      if (!sub) {
        return { isError: true, content: [{ type: 'text' as const, text: 'ユーザーを特定できません' }] };
      }
      const who = name?.trim() || (auth?.extra?.name as string | undefined) || 'ゲスト';

      // 1. 既に外部サービスと連携済みなら、そのまま API を呼ぶ
      if (validPartnerToken(sub)) return callPartnerApi(sub, who);

      // 2. Elicitation への応答を添えた再試行 (E4)
      const state = ctx.mcpReq.requestState<{ eid: string }>(); // SDK が HMAC とユーザー束縛を検証済み
      const answer = inputResponse(ctx.mcpReq.inputResponses, 'partner_auth');
      if (state && answer.kind === 'elicit') {
        const rec = elicitations.get(state.eid);
        if (!rec || rec.sub !== sub) {
          return { isError: true, content: [{ type: 'text' as const, text: '連携要求が見つかりません' }] };
        }
        if (answer.action !== 'accept') {
          rec.status = 'denied';
          log.step('E4', `ユーザーが連携を${answer.action === 'decline' ? '拒否' : 'キャンセル'}しました`);
          return {
            content: [
              { type: 'text' as const, text: 'ユーザーが外部サービスとの連携を行いませんでした。' },
            ],
          };
        }
        // accept は「URL を開くことに同意した」という意味で、連携の完了ではない。
        // ブラウザでの連携が終わるまで、このリクエストの中で待つ。
        log.step('E4', 'ユーザーが URL を開くことに同意しました。ブラウザでの連携完了を待ちます');
        const outcome = await waitForConnection(sub, state.eid, ctx.mcpReq.signal);
        if (outcome === 'done') return callPartnerApi(sub, who);
        const reason = {
          denied: '外部サービスで拒否されました',
          timeout: '時間内に完了しませんでした',
          aborted: '中断されました',
        }[outcome];
        return {
          isError: true,
          content: [{ type: 'text' as const, text: `外部サービスとの連携が完了しませんでした (${reason})` }],
        };
      }

      // 3. 初回: URL モードの Elicitation で、ブラウザでの連携をユーザーに依頼する (E2)
      //    クライアントが URL モードに対応していなければ送ってはならない (MUST NOT)
      if (!server.server.getClientCapabilities()?.elicitation?.url) {
        return {
          isError: true,
          content: [
            { type: 'text' as const, text: 'このクライアントは URL モードの Elicitation に対応していません' },
          ],
        };
      }
      const eid = randomId();
      elicitations.set(eid, {
        sub,
        clientId: auth!.clientId,
        status: 'pending',
        expires_at: now() + 600,
      });
      // URL には推測不能な ID だけを入れる。ユーザーの情報や、開くだけでアクセスできる
      // 認証情報 (pre-authenticated URL) を含めてはならない (MUST NOT)
      const url = `${BASE.resource}/connect/partner?${new URLSearchParams({ eid })}`;
      log.step('E2', `外部サービスのトークンが無いため、URL モードの Elicitation を返します: ${url}`);
      return inputRequired({
        inputRequests: {
          partner_auth: inputRequired.elicitUrl({
            message:
              'Hello MCP Server が外部サービス「Partner Greeting Service」を利用するための連携が必要です。ブラウザで開いて許可してください。',
            url,
          }),
        },
        requestState: await stateCodec.mint({ eid }, ctx),
      });
    },
  );

  return server;
}

const mcpHandler = createMcpHandler(({ authInfo }) => buildServer(authInfo), {
  onerror: (err) => log.error(`MCP リクエストの処理に失敗: ${err.message}`),
});
const nodeHandler = toNodeHandler(mcpHandler, {
  onerror: (err) => log.error(`MCP アダプタでエラー: ${err.message}`),
});

// 認証を通ったリクエストだけを MCP に渡す。req.auth は toNodeHandler が authInfo として引き渡す。
// GET / DELETE (2025 版のセッション操作) には SDK が 405 を返す。
app.all('/mcp', requireAccessToken, (req, res) => {
  void nodeHandler(req, res, req.body);
});

// ================================================= ブラウザ側の連携フロー
// MCP Server が OAuth クライアントになるのは次の 2 つ:
//  - MCP の AS  : 連携 URL を開いた人が誰かを確認する (本人確認。scope=openid)
//  - 外部サービス: 挨拶 API を呼ぶためのトークンを得る

/** 本人確認で AS に名乗る Client ID Metadata Document。 */
app.get('/oauth/client-metadata.json', (_req, res) => {
  res.json({
    client_id: MCP_SERVER_CLIENT_ID,
    client_name: 'Hello MCP Server (本人確認)',
    client_uri: BASE.resource,
    redirect_uris: [MCP_SERVER_IDENTITY_REDIRECT_URI],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    scope: 'openid',
  });
});

const escHtml = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );

function page(title: string, message: string, ok: boolean): string {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>${escHtml(title)}</title>
<style>:root{color-scheme:light dark}body{font-family:system-ui,"Hiragino Sans",sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f4f5f7}
.box{background:#fff;padding:30px 36px;border-radius:14px;box-shadow:0 8px 30px rgba(0,0,0,.08);max-width:460px;text-align:center}
.icon{font-size:38px}h1{font-size:17px}p{color:#444;line-height:1.7;font-size:14px}
@media (prefers-color-scheme:dark){body{background:#15171b}.box{background:#1e2127}p{color:#ccd}}</style></head>
<body><div class="box"><div class="icon">${ok ? '✅' : '⛔'}</div><h1>${escHtml(title)}</h1><p>${escHtml(message)}</p></div></body></html>`;
}

async function fetchAsMetadata(issuer: string) {
  const res = await fetch(`${issuer}/.well-known/oauth-authorization-server`);
  const meta = (await res.json()) as {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    pushed_authorization_request_endpoint?: string;
    code_challenge_methods_supported?: string[];
  };
  if (meta.issuer !== issuer) throw new Error(`issuer が一致しません: ${meta.issuer}`);
  if (!meta.code_challenge_methods_supported?.includes('S256')) {
    throw new Error('PKCE S256 に未対応です');
  }
  return meta;
}

/** E5: 連携 URL が開かれた。まず MCP の AS で「開いた人が誰か」を確認する。 */
app.get('/connect/partner', async (req, res) => {
  const eid = String(req.query.eid ?? '');
  const rec = elicitations.get(eid);
  if (!rec || rec.status !== 'pending' || rec.expires_at < now()) {
    res
      .status(400)
      .type('html')
      .send(page('連携できません', 'この連携リンクは無効か、期限切れです。', false));
    return;
  }
  try {
    const as = await fetchAsMetadata(AS_ISSUER);
    const { verifier, challenge: codeChallenge } = pkcePair();
    const state = randomId();
    const nonce = randomId();
    connectStates.set(state, { kind: 'identity', eid, verifier, nonce, expires_at: now() + 300 });

    const par = await fetch(as.pushed_authorization_request_endpoint!, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        response_type: 'code',
        client_id: MCP_SERVER_CLIENT_ID,
        redirect_uri: MCP_SERVER_IDENTITY_REDIRECT_URI,
        scope: 'openid',
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      }),
    });
    const body = (await par.json()) as { request_uri?: string; error_description?: string };
    if (!par.ok || !body.request_uri) {
      throw new Error(body.error_description ?? `PAR 失敗 (HTTP ${par.status})`);
    }

    const url = new URL(as.authorization_endpoint);
    url.searchParams.set('client_id', MCP_SERVER_CLIENT_ID);
    url.searchParams.set('request_uri', body.request_uri);
    log.step('E5', '連携 URL が開かれました。本人確認のため MCP の AS へ移動します');
    res.redirect(302, url.toString());
  } catch (err) {
    log.error(`本人確認を開始できません: ${(err as Error).message}`);
    res.status(500).type('html').send(page('連携できません', (err as Error).message, false));
  }
});

/** E5 → E6: 本人確認の結果を受け取り、一致すれば外部サービスの認可へ進む。 */
app.get('/connect/identity/callback', async (req, res) => {
  const state = String(req.query.state ?? '');
  const st = connectStates.get(state);
  connectStates.delete(state);
  if (!st || st.kind !== 'identity' || st.expires_at < now()) {
    res.status(400).type('html').send(page('連携できません', '状態が無効です。', false));
    return;
  }
  // RFC 9207: AS は iss を返すと宣言しているので、必ず一致を確認する
  if (req.query.iss !== AS_ISSUER) {
    res
      .status(400)
      .type('html')
      .send(page('連携できません', '認可サーバーの検証に失敗しました。', false));
    return;
  }
  const rec = elicitations.get(st.eid);
  if (!rec || rec.status !== 'pending') {
    res.status(400).type('html').send(page('連携できません', 'この連携リンクは無効です。', false));
    return;
  }
  try {
    if (req.query.error) throw new Error(`本人確認が完了しませんでした (${String(req.query.error)})`);
    const as = await fetchAsMetadata(AS_ISSUER);
    const tokenRes = await fetch(as.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: String(req.query.code ?? ''),
        redirect_uri: MCP_SERVER_IDENTITY_REDIRECT_URI,
        client_id: MCP_SERVER_CLIENT_ID,
        code_verifier: st.verifier,
      }),
    });
    const tokens = (await tokenRes.json()) as { id_token?: string; error_description?: string };
    if (!tokenRes.ok || !tokens.id_token) {
      throw new Error(tokens.error_description ?? 'ID トークンを取得できません');
    }

    const { payload } = await jwtVerify(tokens.id_token, jwks, {
      issuer: AS_ISSUER,
      audience: MCP_SERVER_CLIENT_ID,
    });
    if (payload.nonce !== st.nonce) throw new Error('nonce が一致しません');

    // フィッシング対策 (MUST): 連携を始めたユーザーと、いまブラウザで操作しているユーザーが同じか
    if (payload.sub !== rec.sub) {
      log.warn(
        `(E5) 連携 URL を開いたユーザー (${payload.sub}) が、連携を始めたユーザー (${rec.sub}) と異なります。中止します`,
      );
      res
        .status(403)
        .type('html')
        .send(
          page(
            '連携を中止しました',
            'このリンクは別のユーザーのために発行されたものです。心当たりが無い場合は、リンクを送ってきた相手に注意してください。',
            false,
          ),
        );
      return;
    }
    log.step('E5', `本人確認 OK (sub=${payload.sub})。外部サービスの認可へ進みます`);

    // E6: 外部サービス (事前登録済みクライアント) の認可へ
    const partner = await fetchAsMetadata(PARTNER_ISSUER);
    const { verifier, challenge: codeChallenge } = pkcePair();
    const partnerState = randomId();
    connectStates.set(partnerState, {
      kind: 'partner',
      eid: st.eid,
      verifier,
      expires_at: now() + 300,
    });
    const url = new URL(partner.authorization_endpoint);
    for (const [k, v] of Object.entries({
      response_type: 'code',
      client_id: PARTNER_CLIENT_ID,
      redirect_uri: PARTNER_REDIRECT_URI,
      scope: PARTNER_SCOPE,
      state: partnerState,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      resource: PARTNER_API,
    })) {
      url.searchParams.set(k, v);
    }
    res.redirect(302, url.toString());
  } catch (err) {
    log.error(`本人確認に失敗: ${(err as Error).message}`);
    res.status(400).type('html').send(page('連携できません', (err as Error).message, false));
  }
});

/** E6: 外部サービスからの戻り。トークンを MCP のユーザー (sub) に紐付けて保存する。 */
app.get('/connect/partner/callback', async (req, res) => {
  const state = String(req.query.state ?? '');
  const st = connectStates.get(state);
  connectStates.delete(state);
  if (!st || st.kind !== 'partner' || st.expires_at < now()) {
    res.status(400).type('html').send(page('連携できません', '状態が無効です。', false));
    return;
  }
  if (req.query.iss !== PARTNER_ISSUER) {
    res
      .status(400)
      .type('html')
      .send(page('連携できません', '外部サービスの検証に失敗しました。', false));
    return;
  }
  const rec = elicitations.get(st.eid);
  if (!rec || rec.status !== 'pending') {
    res.status(400).type('html').send(page('連携できません', 'この連携リンクは無効です。', false));
    return;
  }
  if (req.query.error) {
    rec.status = 'denied';
    log.step('E6', '外部サービスでユーザーが連携を拒否しました');
    res
      .type('html')
      .send(page('連携を取りやめました', '外部サービスとの連携は行われませんでした。', false));
    return;
  }
  try {
    const partner = await fetchAsMetadata(PARTNER_ISSUER);
    const tokenRes = await fetch(partner.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: String(req.query.code ?? ''),
        redirect_uri: PARTNER_REDIRECT_URI,
        client_id: PARTNER_CLIENT_ID,
        code_verifier: st.verifier,
      }),
    });
    const body = (await tokenRes.json()) as { access_token?: string; expires_in?: number };
    if (!tokenRes.ok || !body.access_token) throw new Error('外部サービスのトークンを取得できません');

    partnerTokens.set(rec.sub, {
      access_token: body.access_token,
      expires_at: now() + (body.expires_in ?? 3600),
    });
    rec.status = 'done';
    log.step('E6', `外部サービスのトークンを取得し、ユーザー (${rec.sub}) に紐付けて保存しました`);
    res
      .type('html')
      .send(
        page(
          '連携が完了しました',
          'Partner Greeting Service と連携しました。チャット画面に戻ってください。',
          true,
        ),
      );
  } catch (err) {
    log.error(`外部サービス連携に失敗: ${(err as Error).message}`);
    res.status(400).type('html').send(page('連携できません', (err as Error).message, false));
  }
});

app.listen(PORTS.resource, BIND_HOST, () => {
  log.info(`MCP Server (Resource Server) を起動しました: ${RESOURCE_URI} (bind ${BIND_HOST})`);
  log.info(`Protected Resource Metadata: ${PRM_URL}`);
});
