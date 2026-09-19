/**
 * Authorization Server (図の "Authorization Server")
 *
 * OAuth 2.1 準拠の最小実装:
 *  - authorization code + PKCE (S256) 必須 / implicit・password グラントなし
 *  - Pushed Authorization Request (RFC 9126) — 図の 10 と 11 に対応
 *  - Client ID Metadata Document によるクライアント識別 (DCR 不要)
 *    CIMD の取得・検証と信頼ポリシー (許可リスト) の判定は、PAR の時点でこの AS が行う
 *  - Resource Indicators (RFC 8707) — トークンの aud を MCP エンドポイントに限定
 *  - リフレッシュトークンはワンタイム (パブリッククライアント向けのローテーション)
 *  - `openid` スコープによる本人確認 (ID トークン)。MCP Server が URL モード Elicitation の
 *    フィッシング対策として「ブラウザの利用者が誰か」を確かめるために使う
 */
import crypto from 'node:crypto';
import express from 'express';
import { SignJWT, exportJWK, generateKeyPair, calculateJwkThumbprint, type JWK } from 'jose';
import {
  AS_ISSUER,
  AUTH_CODE_TTL_SEC,
  BASE,
  BIND_HOST,
  DEMO_USERS,
  PAR_TTL_SEC,
  PORTS,
  SCOPE,
  TOKEN_TTL_SEC,
} from '../shared/config.js';
import { createLogger } from '../shared/log.js';

const log = createLogger('auth');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ---------------------------------------------------------------- 署名鍵
const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
const publicJwk: JWK = await exportJWK(publicKey);
publicJwk.kid = await calculateJwkThumbprint(publicJwk);
publicJwk.alg = 'RS256';
publicJwk.use = 'sig';

// ---------------------------------------------------------------- ストア
interface PushedRequest {
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  nonce?: string;
  code_challenge: string;
  code_challenge_method: 'S256';
  /** 本人確認 (openid のみ) の要求では省略される。 */
  resource?: string;
  expires_at: number;
}
interface AuthCode {
  client_id: string;
  redirect_uri: string;
  scope: string;
  nonce?: string;
  resource?: string;
  code_challenge: string;
  sub: string;
  auth_time: number;
  expires_at: number;
  used: boolean;
}
interface RefreshToken {
  client_id: string;
  scope: string;
  resource?: string;
  sub: string;
  expires_at: number;
}

const pushedRequests = new Map<string, PushedRequest>();
const authCodes = new Map<string, AuthCode>();
const refreshTokens = new Map<string, RefreshToken>();

const now = () => Math.floor(Date.now() / 1000);
const randomId = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const hasScope = (scope: string, s: string) => scope.split(' ').includes(s);

// ---------------------------------------------------------------- ログインセッション
// デモなのでパスワード認証は省略し、「どのデモユーザーとしてログインするか」を選ぶだけにする。
// URL モード Elicitation のフィッシング対策 (別のユーザーが連携 URL を開いたら拒否する) を
// 試せるように、ユーザーを切り替えられるようにしている。
type DemoUser = (typeof DEMO_USERS)[number];
const SESSION_COOKIE = 'demo_as_sid';
const sessions = new Map<string, { sub: string; auth_time: number }>();

function userBySub(sub: string): DemoUser | undefined {
  return DEMO_USERS.find((u) => u.sub === sub);
}

function readSession(req: express.Request): { user: DemoUser; auth_time: number } | undefined {
  const cookie = req.headers.cookie ?? '';
  const sid = cookie
    .split(';')
    .map((c) => c.trim().split('='))
    .find(([k]) => k === SESSION_COOKIE)?.[1];
  const session = sid ? sessions.get(sid) : undefined;
  const user = session ? userBySub(session.sub) : undefined;
  return user && session ? { user, auth_time: session.auth_time } : undefined;
}

function startSession(res: express.Response, user: DemoUser): number {
  const sid = randomId(24);
  const authTime = now();
  sessions.set(sid, { sub: user.sub, auth_time: authTime });
  res.cookie(SESSION_COOKIE, sid, { httpOnly: true, sameSite: 'lax', path: '/' });
  return authTime;
}

// ---------------------------------------------------------------- CIMD 解決と信頼ポリシー
interface ClientMetadata {
  client_id: string;
  client_name: string;
  client_uri?: string;
  logo_uri?: string;
  redirect_uris: string[];
  scope?: string;
}

class OAuthError extends Error {
  constructor(
    public code: string,
    message: string,
    public status = 400,
  ) {
    super(message);
  }
}

interface ResolvedClient {
  metadata: ClientMetadata;
  registered: boolean;
  trusted: boolean;
}

/**
 * client_id (= CIMD の URL) からクライアントメタデータを得る。
 * 取得と検証は Client registry (この AS の台帳) に委譲する。
 */
async function resolveClient(clientId: string): Promise<ResolvedClient> {
  const res = await fetch(`${BASE.registry}/clients/resolve`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_id: clientId }),
  });
  const body = (await res.json()) as {
    metadata?: ClientMetadata;
    registered?: boolean;
    trusted?: boolean;
    error_description?: string;
  };
  if (!res.ok || !body.metadata) {
    throw new OAuthError('invalid_client', body.error_description ?? 'CIMD を解決できません');
  }
  return {
    metadata: body.metadata,
    registered: body.registered ?? false,
    trusted: body.trusted ?? false,
  };
}

/**
 * 認可リクエスト (PAR) を受けた時点で、クライアントを識別して受け入れてよいかを決める。
 * (以前の図の 6〜8 を、標準どおり AS の中で行う形)
 *
 *  a. CIMD を取得・検証する (client_id の URL = クライアントがホストするメタデータ)
 *  b. 信頼ポリシー (許可リスト) を確認する。CIMD は「誰を名乗っているか」しか示さないので、
 *     受け入れるかどうかは AS 側の方針で決める
 *  c. まだ台帳に登録されていなければ登録する
 */
async function admitClient(clientId: string): Promise<ResolvedClient> {
  const client = await resolveClient(clientId);
  log.step('10a', `CIMD を確認しました: ${client.metadata.client_name} (${clientId})`);

  if (!client.trusted) {
    log.warn(`(10b) 信頼ポリシーに無いクライアントを拒否します: ${clientId}`);
    throw new OAuthError(
      'invalid_client',
      'このクライアントは Client registry に登録されていないため、認可できません',
      403,
    );
  }
  log.step('10b', '信頼ポリシー (許可リスト) を満たしています');

  if (!client.registered) {
    const created = await fetch(`${BASE.registry}/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_id: clientId }),
    });
    if (!created.ok) {
      const err = (await created.json()) as { error_description?: string };
      throw new OAuthError('invalid_client', err.error_description ?? '登録に失敗しました', 403);
    }
    log.step('10c', `クライアントを台帳に登録しました: ${client.metadata.client_name}`);
    return { ...client, registered: true };
  }
  log.step('10c', '既に登録済みのクライアントです');
  return client;
}

/** 認可・トークン発行の時点で、登録済みであることを再確認する。 */
async function requireRegisteredClient(clientId: string): Promise<ResolvedClient> {
  const client = await resolveClient(clientId);
  if (!client.registered || !client.trusted) {
    log.warn(`未登録のクライアントからの要求を拒否します: ${clientId}`);
    throw new OAuthError(
      'invalid_client',
      'このクライアントは Client registry に登録されていないため、認可できません',
      403,
    );
  }
  return client;
}

// ---------------------------------------------------------------- メタデータ
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: AS_ISSUER,
    authorization_endpoint: `${AS_ISSUER}/authorize`,
    token_endpoint: `${AS_ISSUER}/token`,
    pushed_authorization_request_endpoint: `${AS_ISSUER}/par`,
    require_pushed_authorization_requests: true,
    jwks_uri: `${AS_ISSUER}/jwks.json`,
    scopes_supported: [SCOPE, 'openid'],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    authorization_response_iss_parameter_supported: true,
    // CIMD 対応であることの表明 (client_id に URL を使ってよい)
    client_id_metadata_document_supported: true,
    // 本人確認 (ID トークン) 用
    id_token_signing_alg_values_supported: ['RS256'],
    subject_types_supported: ['public'],
  });
});

app.get('/jwks.json', (_req, res) => {
  res.json({ keys: [publicJwk] });
});

/**
 * トークンや request_uri を含む応答は、中継者やブラウザにキャッシュさせてはならない
 * (OAuth 2.1 §3.2.3: トークン応答には Cache-Control: no-store が MUST)。
 */
function noStore(res: express.Response): void {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
}

// ---------------------------------------------------------------- PAR (10 → 11)
app.post('/par', async (req, res) => {
  noStore(res);
  try {
    // RFC 9126 §2.1: PAR のリクエストボディは application/x-www-form-urlencoded (MUST)
    if (!req.is('application/x-www-form-urlencoded')) {
      throw new OAuthError(
        'invalid_request',
        'PAR のリクエストは application/x-www-form-urlencoded で送ってください',
      );
    }
    const {
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: responseType,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      scope = SCOPE,
      state,
      nonce,
      resource,
    } = req.body ?? {};

    if (responseType !== 'code') {
      throw new OAuthError('unsupported_response_type', 'response_type は code のみ');
    }
    if (typeof clientId !== 'string') throw new OAuthError('invalid_request', 'client_id が必要です');
    if (typeof state !== 'string' || !state) throw new OAuthError('invalid_request', 'state が必要です');
    if (codeChallengeMethod !== 'S256') throw new OAuthError('invalid_request', 'PKCE は S256 のみ');
    if (typeof codeChallenge !== 'string' || codeChallenge.length < 43) {
      throw new OAuthError('invalid_request', 'code_challenge が不正です');
    }
    // 本人確認 (openid だけ) の要求はリソースへのアクセスを伴わないので resource は不要。
    // それ以外 (MCP サーバーへのアクセス) は RFC 8707 の resource を必須にする。
    const identityOnly = String(scope) === 'openid';
    if (!identityOnly && typeof resource !== 'string') {
      throw new OAuthError('invalid_target', 'resource (RFC 8707) が必要です');
    }

    log.step(10, `認可リクエスト (PAR) を受け取りました: client_id=${clientId} scope=${scope}`);

    // CIMD の取得・検証 → 信頼ポリシー → 未登録なら登録
    const { metadata } = await admitClient(clientId);

    // redirect_uri は CIMD の redirect_uris と完全一致であること
    if (!metadata.redirect_uris.includes(redirectUri)) {
      throw new OAuthError('invalid_request', `redirect_uri が CIMD に登録されていません: ${redirectUri}`);
    }

    const requestUri = `urn:ietf:params:oauth:request_uri:${randomId(24)}`;
    pushedRequests.set(requestUri, {
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: String(scope),
      state,
      nonce: typeof nonce === 'string' ? nonce : undefined,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      resource: typeof resource === 'string' ? resource : undefined,
      expires_at: now() + PAR_TTL_SEC,
    });

    log.step(11, `認可 URL の元になる request_uri を返します: ${requestUri}`);
    res.status(201).json({ request_uri: requestUri, expires_in: PAR_TTL_SEC });
  } catch (err) {
    const e = err as OAuthError;
    log.error(`PAR 失敗: ${e.message}`);
    res
      .status(e.status ?? 400)
      .json({ error: e.code ?? 'invalid_request', error_description: e.message });
  }
});

// ---------------------------------------------------------------- 画面
const esc = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );

const PAGE_STYLE = `
 :root{color-scheme:light dark}
 body{font-family:system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;background:#f4f5f7;margin:0;padding:40px 16px;display:flex;justify-content:center}
 .card{background:#fff;max-width:520px;width:100%;border-radius:14px;box-shadow:0 8px 30px rgba(0,0,0,.09);padding:28px 30px}
 h1{font-size:18px;margin:0 0 4px}
 .sub{color:#666;font-size:13px;margin:0 0 20px}
 .sub a{color:#4b6bfb;text-decoration:none;margin-left:6px}
 .client{display:flex;gap:12px;align-items:center;border:1px solid #e6e8eb;border-radius:10px;padding:14px;margin-bottom:18px}
 .client img{width:40px;height:40px;border-radius:8px}
 .client b{display:block;font-size:15px}
 .client a{font-size:12px;color:#4b6bfb;text-decoration:none}
 dl{margin:0;font-size:13px}
 dt{color:#666;margin-top:10px}
 dd{margin:2px 0 0;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
 .scope{display:inline-block;background:#eef2ff;color:#3a49b5;border-radius:6px;padding:3px 8px;font-size:12px;margin-right:6px}
 .note{font-size:11.5px;color:#888;margin-top:18px;line-height:1.6;border-top:1px solid #eee;padding-top:12px}
 .host{font-weight:700;font-size:13px;font-family:system-ui,sans-serif}
 .warn{font-size:12px;line-height:1.6;background:#fff7e6;color:#8a5300;border:1px solid #f5d38a;border-radius:8px;padding:9px 11px;margin:14px 0 0}
 .actions{display:flex;gap:10px;margin-top:22px}
 button{flex:1;padding:11px;border-radius:9px;border:0;font-size:14px;cursor:pointer}
 .ok{background:#2f6df6;color:#fff}
 .ng{background:#eceef1;color:#333}
 label.user{display:flex;gap:10px;align-items:center;border:1px solid #e6e8eb;border-radius:10px;padding:12px 14px;margin-top:10px;cursor:pointer;font-size:14px}
 label.user small{color:#888;display:block;font-size:12px}
 @media (prefers-color-scheme:dark){body{background:#15171b}.card{background:#1e2127;box-shadow:none}.client,label.user{border-color:#31353d}.note{border-color:#2a2e35}.ng{background:#2a2e35;color:#ddd}.scope{background:#26304d;color:#aab8ff}.warn{background:#3a2c10;color:#f3c97a;border-color:#6b5020}}`;

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function consentPage(opts: {
  requestUri: string;
  metadata: ClientMetadata;
  pushed: PushedRequest;
  user: DemoUser;
  switchUrl: string;
}): string {
  const { metadata, pushed, requestUri, user, switchUrl } = opts;
  // MCP: AS は認可時に戻り先 (redirect URI) のホスト名をはっきり表示しなければならない (MUST)。
  // 戻り先が localhost だけのクライアントには追加の警告を出すべき (SHOULD)。
  const redirectHost = new URL(pushed.redirect_uri).host;
  const localhostOnly = metadata.redirect_uris.every((u) =>
    LOOPBACK_HOSTS.has(new URL(u).hostname),
  );
  return `<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>アクセスの許可 — Demo Authorization Server</title>
<style>${PAGE_STYLE}</style></head><body>
<div class="card">
  <h1>アクセスを許可しますか？</h1>
  <p class="sub">${esc(user.name)} (${esc(user.email)}) としてログイン中
    <a href="${esc(switchUrl)}">ユーザーを切り替える</a></p>

  <div class="client">
    ${metadata.logo_uri ? `<img src="${esc(metadata.logo_uri)}" alt="">` : ''}
    <div>
      <b>${esc(metadata.client_name)}</b>
      ${metadata.client_uri ? `<a href="${esc(metadata.client_uri)}" target="_blank" rel="noopener">${esc(metadata.client_uri)}</a>` : ''}
    </div>
  </div>

  <dl>
    <dt>要求されているスコープ</dt>
    <dd>${pushed.scope
      .split(' ')
      .map((s) => `<span class="scope">${esc(s)}</span>`)
      .join('')}</dd>
    <dt>アクセス先リソース (RFC 8707)</dt>
    <dd>${esc(pushed.resource ?? '(なし)')}</dd>
    <dt>client_id (Client ID Metadata Document)</dt>
    <dd>${esc(pushed.client_id)}</dd>
    <dt>許可後の戻り先</dt>
    <dd><span class="host">${esc(redirectHost)}</span> — ${esc(pushed.redirect_uri)}</dd>
  </dl>
  ${
    localhostOnly
      ? `<p class="warn">⚠ 戻り先がこのコンピューター (${esc(redirectHost)}) です。
         CIMD だけでは localhost の戻り先を名乗る別アプリと区別できません。
         自分で起動したアプリからの要求であることを確認してください。</p>`
      : ''
  }

  <form method="post" action="/authorize/decision">
    <input type="hidden" name="request_uri" value="${esc(requestUri)}">
    <input type="hidden" name="sub" value="${esc(user.sub)}">
    <div class="actions">
      <button class="ng" name="decision" value="deny" type="submit">拒否</button>
      <button class="ok" name="decision" value="allow" type="submit">許可する</button>
    </div>
  </form>

  <p class="note">このクライアント情報は、client_id の URL から取得した
  Client ID Metadata Document に基づいて表示しています。事前のクライアント登録 (DCR) は行っていません。</p>
</div></body></html>`;
}

/** ログイン (デモユーザーの選択) 画面。 */
function sessionPage(opts: { current?: DemoUser; returnTo: string }): string {
  const users = DEMO_USERS.map(
    (u, i) => `<label class="user"><input type="radio" name="sub" value="${esc(u.sub)}"
      ${opts.current ? (opts.current.sub === u.sub ? 'checked' : '') : i === 0 ? 'checked' : ''}>
      <span>${esc(u.name)}<small>${esc(u.email)} / sub=${esc(u.sub)}</small></span></label>`,
  ).join('');
  return `<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>ログイン — Demo Authorization Server</title>
<style>${PAGE_STYLE}</style></head><body>
<div class="card">
  <h1>ログイン</h1>
  <p class="sub">${
    opts.current ? `現在 ${esc(opts.current.name)} としてログイン中です。` : 'ログインしていません。'
  } デモのため、ユーザーを選ぶだけでログインできます。</p>
  <form method="post" action="/session">
    <input type="hidden" name="return_to" value="${esc(opts.returnTo)}">
    ${users}
    <div class="actions"><button class="ok" type="submit">このユーザーでログイン</button></div>
  </form>
</div></body></html>`;
}

/** オープンリダイレクトを避けるため、戻り先は自分の画面 (相対パス) に限る。 */
function safeReturnTo(value: unknown): string {
  const s = typeof value === 'string' ? value : '';
  return s.startsWith('/') && !s.startsWith('//') ? s : '/session';
}

app.get('/session', (req, res) => {
  res
    .type('html')
    .send(sessionPage({ current: readSession(req)?.user, returnTo: safeReturnTo(req.query.return_to) }));
});

app.post('/session', (req, res) => {
  const user = userBySub(String(req.body?.sub ?? ''));
  if (!user) {
    res.status(400).send('<p>ユーザーが見つかりません。</p>');
    return;
  }
  startSession(res, user);
  log.info(`ログイン: ${user.name} (${user.sub})`);
  res.redirect(302, safeReturnTo(req.body?.return_to));
});

// ---------------------------------------------------------------- 認可エンドポイント (13)
/** 認可コードを発行してクライアントへリダイレクトする。 */
function issueCodeAndRedirect(
  res: express.Response,
  pushed: PushedRequest,
  user: DemoUser,
  authTime: number,
): void {
  const code = randomId(24);
  authCodes.set(code, {
    client_id: pushed.client_id,
    redirect_uri: pushed.redirect_uri,
    scope: pushed.scope,
    nonce: pushed.nonce,
    resource: pushed.resource,
    code_challenge: pushed.code_challenge,
    sub: user.sub,
    auth_time: authTime,
    expires_at: now() + AUTH_CODE_TTL_SEC,
    used: false,
  });
  const redirect = new URL(pushed.redirect_uri);
  redirect.searchParams.set('code', code);
  redirect.searchParams.set('state', pushed.state);
  redirect.searchParams.set('iss', AS_ISSUER); // RFC 9207
  log.step(14, `認可コードを発行し、リダイレクトします (user=${user.sub}): ${pushed.redirect_uri}`);
  res.redirect(302, redirect.toString());
}

app.get('/authorize', async (req, res) => {
  const requestUri = String(req.query.request_uri ?? '');
  const clientId = String(req.query.client_id ?? '');
  const pushed = pushedRequests.get(requestUri);

  // OAuth 2.1 / PAR: 事前に push された認可リクエスト以外は受け付けない
  if (!pushed || pushed.expires_at < now()) {
    pushedRequests.delete(requestUri);
    res.status(400).send('<p>request_uri が無効または期限切れです。</p>');
    return;
  }
  if (pushed.client_id !== clientId) {
    res.status(400).send('<p>client_id が request_uri と一致しません。</p>');
    return;
  }

  const here = `/authorize?${new URLSearchParams({ client_id: clientId, request_uri: requestUri })}`;
  const session = readSession(req);

  try {
    const { metadata } = await requireRegisteredClient(clientId);

    // 本人確認だけの要求 (scope=openid): ユーザーが誰かを返すだけで、リソースへのアクセスは
    // 与えない。許可リストに載ったクライアントに限り、ログイン済みなら同意画面を省く。
    if (pushed.scope === 'openid') {
      if (!session) {
        log.info('本人確認の要求ですが、未ログインなのでログイン画面を出します');
        res.type('html').send(sessionPage({ returnTo: here }));
        return;
      }
      pushedRequests.delete(requestUri);
      log.step('13', `本人確認: ログイン中のユーザー (${session.user.sub}) を返します`);
      issueCodeAndRedirect(res, pushed, session.user, session.auth_time);
      return;
    }

    const user = session?.user ?? DEMO_USERS[0];
    log.step(13, `同意画面を表示します (user=${user.email})`);
    res.type('html').send(
      consentPage({
        requestUri,
        metadata,
        pushed,
        user,
        switchUrl: `/session?${new URLSearchParams({ return_to: here })}`,
      }),
    );
  } catch (err) {
    res.status(400).send(`<p>クライアントを受け付けられません: ${esc((err as Error).message)}</p>`);
  }
});

app.post('/authorize/decision', (req, res) => {
  const requestUri = String(req.body?.request_uri ?? '');
  const pushed = pushedRequests.get(requestUri);
  if (!pushed || pushed.expires_at < now()) {
    res.status(400).send('<p>request_uri が無効または期限切れです。</p>');
    return;
  }
  pushedRequests.delete(requestUri); // request_uri はワンタイム

  if (req.body?.decision !== 'allow') {
    log.step(13, 'ユーザーが拒否しました');
    const redirect = new URL(pushed.redirect_uri);
    redirect.searchParams.set('error', 'access_denied');
    redirect.searchParams.set('state', pushed.state);
    redirect.searchParams.set('iss', AS_ISSUER); // RFC 9207 (エラー応答にも付ける)
    res.redirect(302, redirect.toString());
    return;
  }

  // 同意したユーザーでログインセッションを張る (以後の本人確認はこのセッションを使う)
  const user = userBySub(String(req.body?.sub ?? '')) ?? readSession(req)?.user ?? DEMO_USERS[0];
  const existing = readSession(req);
  const authTime =
    existing && existing.user.sub === user.sub ? existing.auth_time : startSession(res, user);
  issueCodeAndRedirect(res, pushed, user, authTime);
});

// ---------------------------------------------------------------- トークン (15)
async function issueAccessToken(params: {
  sub: string;
  clientId: string;
  scope: string;
  resource?: string;
}): Promise<string> {
  const user = userBySub(params.sub);
  return (
    new SignJWT({
      scope: params.scope,
      client_id: params.clientId,
      email: user?.email,
      name: user?.name,
    })
      .setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid!, typ: 'at+jwt' })
      .setIssuer(AS_ISSUER)
      .setSubject(params.sub)
      // RFC 8707: アクセストークンの受け手を MCP エンドポイントに限定する
      // (本人確認だけの場合はリソースが無いので、受け手は AS 自身にする)
      .setAudience(params.resource ?? AS_ISSUER)
      .setIssuedAt()
      .setExpirationTime(`${TOKEN_TTL_SEC}s`)
      .setJti(randomId(16))
      .sign(privateKey)
  );
}

/** 本人確認用の ID トークン。受け手 (aud) は要求したクライアントの client_id。 */
async function issueIdToken(params: {
  sub: string;
  clientId: string;
  nonce?: string;
  authTime: number;
}): Promise<string> {
  const user = userBySub(params.sub);
  return new SignJWT({
    name: user?.name,
    email: user?.email,
    auth_time: params.authTime,
    // リプレイ防止のため、要求時の nonce をそのまま返す
    ...(params.nonce && { nonce: params.nonce }),
  })
    .setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid!, typ: 'JWT' })
    .setIssuer(AS_ISSUER)
    .setSubject(params.sub)
    .setAudience(params.clientId)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
}

function verifyPkce(verifier: string, challenge: string): boolean {
  const computed = crypto.createHash('sha256').update(verifier).digest('base64url');
  const a = Buffer.from(computed);
  const b = Buffer.from(challenge);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.post('/token', async (req, res) => {
  noStore(res);
  try {
    const grantType = req.body?.grant_type;

    if (grantType === 'authorization_code') {
      const {
        code,
        code_verifier: verifier,
        client_id: clientId,
        redirect_uri: redirectUri,
        resource,
      } = req.body ?? {};
      const entry = typeof code === 'string' ? authCodes.get(code) : undefined;

      if (!entry || entry.expires_at < now()) throw new OAuthError('invalid_grant', '認可コードが無効です');
      if (entry.used) {
        // 認可コードの再利用 -> 同じクライアント/ユーザーのトークンも無効化する (OAuth 2.1)
        authCodes.delete(code);
        for (const [token, rt] of refreshTokens) {
          if (rt.sub === entry.sub && rt.client_id === entry.client_id) refreshTokens.delete(token);
        }
        throw new OAuthError('invalid_grant', '認可コードが再利用されました');
      }
      if (entry.client_id !== clientId) throw new OAuthError('invalid_grant', 'client_id が一致しません');
      if (entry.redirect_uri !== redirectUri) {
        throw new OAuthError('invalid_grant', 'redirect_uri が一致しません');
      }
      if (typeof resource === 'string' && resource !== entry.resource) {
        throw new OAuthError('invalid_target', 'resource が認可時と一致しません');
      }
      if (typeof verifier !== 'string' || !verifyPkce(verifier, entry.code_challenge)) {
        throw new OAuthError('invalid_grant', 'PKCE の検証に失敗しました');
      }

      // CIMD と登録状態を再確認 (認可時から変わっている可能性があるため)
      await requireRegisteredClient(entry.client_id);

      entry.used = true;
      authCodes.delete(code);

      const accessToken = await issueAccessToken({
        sub: entry.sub,
        clientId: entry.client_id,
        scope: entry.scope,
        resource: entry.resource,
      });
      const body: Record<string, unknown> = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: TOKEN_TTL_SEC,
        scope: entry.scope,
      };

      if (hasScope(entry.scope, 'openid')) {
        body.id_token = await issueIdToken({
          sub: entry.sub,
          clientId: entry.client_id,
          nonce: entry.nonce,
          authTime: entry.auth_time,
        });
        log.info(`本人確認用の ID トークンを発行しました (sub=${entry.sub}, aud=${entry.client_id})`);
      } else {
        const refreshToken = randomId(32);
        refreshTokens.set(refreshToken, {
          client_id: entry.client_id,
          scope: entry.scope,
          resource: entry.resource,
          sub: entry.sub,
          expires_at: now() + 3600,
        });
        body.refresh_token = refreshToken;
        log.step(15, `認可コードをアクセストークンに交換しました (aud=${entry.resource})`);
      }
      res.json(body);
      return;
    }

    if (grantType === 'refresh_token') {
      const { refresh_token: token, client_id: clientId, resource } = req.body ?? {};
      const entry = typeof token === 'string' ? refreshTokens.get(token) : undefined;
      if (!entry || entry.expires_at < now()) throw new OAuthError('invalid_grant', 'refresh_token が無効です');
      if (entry.client_id !== clientId) throw new OAuthError('invalid_grant', 'client_id が一致しません');
      refreshTokens.delete(token); // ワンタイム: 使ったら必ずローテーション

      const target = typeof resource === 'string' ? resource : entry.resource;
      if (target !== entry.resource) throw new OAuthError('invalid_target', 'resource が一致しません');

      const accessToken = await issueAccessToken({
        sub: entry.sub,
        clientId: entry.client_id,
        scope: entry.scope,
        resource: entry.resource,
      });
      const next = randomId(32);
      refreshTokens.set(next, { ...entry, expires_at: now() + 3600 });
      log.info('リフレッシュトークンをローテーションしました');
      res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: TOKEN_TTL_SEC,
        scope: entry.scope,
        refresh_token: next,
      });
      return;
    }

    throw new OAuthError('unsupported_grant_type', `未対応の grant_type: ${grantType}`);
  } catch (err) {
    const e = err as OAuthError;
    log.error(`トークン発行失敗: ${e.message}`);
    res
      .status(e.status ?? 400)
      .json({ error: e.code ?? 'invalid_request', error_description: e.message });
  }
});

app.listen(PORTS.auth, BIND_HOST, () => {
  log.info(`Authorization Server を起動しました: ${AS_ISSUER} (bind ${BIND_HOST})`);
});
