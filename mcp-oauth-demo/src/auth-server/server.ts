/**
 * Authorization Server (図の "Authorization Server")
 *
 * OAuth 2.1 準拠の最小実装:
 *  - authorization code + PKCE (S256) 必須 / implicit・password グラントなし
 *  - Pushed Authorization Request (RFC 9126) — 図の 10 と 11 に対応
 *  - Client ID Metadata Document によるクライアント識別 (DCR 不要)
 *  - Resource Indicators (RFC 8707) — トークンの aud を MCP エンドポイントに限定
 *  - リフレッシュトークンはワンタイム (パブリッククライアント向けのローテーション)
 */
import crypto from 'node:crypto';
import express from 'express';
import { SignJWT, exportJWK, generateKeyPair, calculateJwkThumbprint, type JWK } from 'jose';
import {
  AS_ISSUER,
  AUTH_CODE_TTL_SEC,
  BASE,
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
  code_challenge: string;
  code_challenge_method: 'S256';
  resource: string;
  expires_at: number;
}
interface AuthCode {
  client_id: string;
  redirect_uri: string;
  scope: string;
  resource: string;
  code_challenge: string;
  sub: string;
  expires_at: number;
  used: boolean;
}
interface RefreshToken {
  client_id: string;
  scope: string;
  resource: string;
  sub: string;
  expires_at: number;
}

const pushedRequests = new Map<string, PushedRequest>();
const authCodes = new Map<string, AuthCode>();
const refreshTokens = new Map<string, RefreshToken>();

/** このデモではログイン済みのユーザーが 1 人いる前提にする。 */
const DEMO_USER = { sub: 'user-0001', name: '山田 太郎', email: 'taro@example.com' };

const now = () => Math.floor(Date.now() / 1000);
const randomId = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

// ---------------------------------------------------------------- CIMD 解決
interface ClientMetadata {
  client_id: string;
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  redirect_uris: string[];
  grant_types?: string[];
  response_types?: string[];
  scope?: string;
  policy_uri?: string;
  tos_uri?: string;
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
  /** Client registry に登録済みか。 */
  registered: boolean;
  /** 許可リストに載っているか。 */
  trusted: boolean;
}

/**
 * client_id (= CIMD の URL) からクライアントメタデータを得る。
 * 取得と検証は Client registry に委譲する。
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
 * CIMD が正しく取得できても、Client registry に登録されていないクライアントには
 * 認可を与えない。CIMD は「誰を名乗っているか」を示すだけで、
 * 「信頼してよいか」は registry の許可リストが決める。
 */
async function requireRegisteredClient(clientId: string): Promise<ResolvedClient> {
  const client = await resolveClient(clientId);
  if (!client.registered) {
    log.warn(`未登録のクライアントからの要求を拒否します: ${clientId}`);
    throw new OAuthError(
      'invalid_client',
      'このクライアントは Client registry に登録されていないため、認可できません',
      403,
    );
  }
  return client;
}

/** 図の 8: MCP Server からの「クライアント登録（なければ）」。 */
app.post('/clients/register', async (req, res) => {
  const clientId: unknown = req.body?.client_id;
  if (typeof clientId !== 'string') {
    res.status(400).json({ error: 'invalid_request' });
    return;
  }
  try {
    const lookup = (await fetch(
      `${BASE.registry}/clients/lookup?client_id=${encodeURIComponent(clientId)}`,
    ).then((r) => r.json())) as { registered: boolean };

    if (lookup.registered) {
      log.step(8, `既に登録済みのクライアントです: ${clientId}`);
      res.json({ client_id: clientId, registered: true, created: false });
      return;
    }
    const created = await fetch(`${BASE.registry}/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_id: clientId }),
    });
    if (!created.ok) {
      const err = (await created.json()) as { error?: string; error_description?: string };
      // 許可リストに無いクライアントはここで弾かれる。未登録のままなので、
      // このあと認可リクエスト (PAR) が来ても拒否されることになる。
      throw new OAuthError(
        err.error ?? 'invalid_client',
        err.error_description ?? '登録に失敗しました',
        created.status === 403 ? 403 : 400,
      );
    }
    log.step(8, `クライアントを登録しました: ${clientId}`);
    res.status(201).json({ client_id: clientId, registered: true, created: true });
  } catch (err) {
    const e = err as OAuthError;
    res
      .status(e.status ?? 400)
      .json({ error: e.code ?? 'invalid_client', error_description: e.message });
  }
});

// ---------------------------------------------------------------- メタデータ
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: AS_ISSUER,
    authorization_endpoint: `${AS_ISSUER}/authorize`,
    token_endpoint: `${AS_ISSUER}/token`,
    pushed_authorization_request_endpoint: `${AS_ISSUER}/par`,
    require_pushed_authorization_requests: true,
    jwks_uri: `${AS_ISSUER}/jwks.json`,
    scopes_supported: [SCOPE],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    authorization_response_iss_parameter_supported: true,
    // CIMD 対応であることの表明 (client_id に URL を使ってよい)
    client_id_metadata_document_supported: true,
  });
});

app.get('/jwks.json', (_req, res) => {
  res.json({ keys: [publicJwk] });
});

// ---------------------------------------------------------------- PAR (10 → 11)
app.post('/par', async (req, res) => {
  try {
    const {
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: responseType,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      scope = SCOPE,
      state,
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
    if (typeof resource !== 'string') {
      throw new OAuthError('invalid_target', 'resource (RFC 8707) が必要です');
    }

    log.step(10, `認可リクエスト (PAR) を受け取りました: client_id=${clientId}`);

    // CIMD を解決してクライアントを識別し (DCR なし)、登録済みであることを確認する
    const { metadata } = await requireRegisteredClient(clientId);

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
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      resource,
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

// ---------------------------------------------------------------- 認可エンドポイント (13)
const esc = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );

function consentPage(opts: { requestUri: string; metadata: ClientMetadata; pushed: PushedRequest }): string {
  const { metadata, pushed, requestUri } = opts;
  return `<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>アクセスの許可 — Demo Authorization Server</title>
<style>
 :root{color-scheme:light dark}
 body{font-family:system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;background:#f4f5f7;margin:0;padding:40px 16px;display:flex;justify-content:center}
 .card{background:#fff;max-width:520px;width:100%;border-radius:14px;box-shadow:0 8px 30px rgba(0,0,0,.09);padding:28px 30px}
 h1{font-size:18px;margin:0 0 4px}
 .sub{color:#666;font-size:13px;margin:0 0 20px}
 .client{display:flex;gap:12px;align-items:center;border:1px solid #e6e8eb;border-radius:10px;padding:14px;margin-bottom:18px}
 .client img{width:40px;height:40px;border-radius:8px}
 .client b{display:block;font-size:15px}
 .client a{font-size:12px;color:#4b6bfb;text-decoration:none}
 dl{margin:0;font-size:13px}
 dt{color:#666;margin-top:10px}
 dd{margin:2px 0 0;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
 .scope{display:inline-block;background:#eef2ff;color:#3a49b5;border-radius:6px;padding:3px 8px;font-size:12px;margin-right:6px}
 .note{font-size:11.5px;color:#888;margin-top:18px;line-height:1.6;border-top:1px solid #eee;padding-top:12px}
 .actions{display:flex;gap:10px;margin-top:22px}
 button{flex:1;padding:11px;border-radius:9px;border:0;font-size:14px;cursor:pointer}
 .ok{background:#2f6df6;color:#fff}
 .ng{background:#eceef1;color:#333}
 @media (prefers-color-scheme:dark){body{background:#15171b}.card{background:#1e2127;box-shadow:none}.client{border-color:#31353d}.note{border-color:#2a2e35}.ng{background:#2a2e35;color:#ddd}.scope{background:#26304d;color:#aab8ff}}
</style></head><body>
<div class="card">
  <h1>アクセスを許可しますか？</h1>
  <p class="sub">${esc(DEMO_USER.name)} (${esc(DEMO_USER.email)}) としてログイン中</p>

  <div class="client">
    ${metadata.logo_uri ? `<img src="${esc(metadata.logo_uri)}" alt="">` : ''}
    <div>
      <b>${esc(metadata.client_name ?? metadata.client_id)}</b>
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
    <dd>${esc(pushed.resource)}</dd>
    <dt>client_id (Client ID Metadata Document)</dt>
    <dd>${esc(pushed.client_id)}</dd>
    <dt>リダイレクト先</dt>
    <dd>${esc(pushed.redirect_uri)}</dd>
  </dl>

  <form method="post" action="/authorize/decision">
    <input type="hidden" name="request_uri" value="${esc(requestUri)}">
    <div class="actions">
      <button class="ng" name="decision" value="deny" type="submit">拒否</button>
      <button class="ok" name="decision" value="allow" type="submit">許可する</button>
    </div>
  </form>

  <p class="note">このクライアント情報は、client_id の URL から取得した
  Client ID Metadata Document に基づいて表示しています。事前のクライアント登録 (DCR) は行っていません。</p>
</div></body></html>`;
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
  try {
    const { metadata } = await requireRegisteredClient(clientId);
    log.step(13, `同意画面を表示します (user=${DEMO_USER.email})`);
    res.type('html').send(consentPage({ requestUri, metadata, pushed }));
  } catch (err) {
    res.status(400).send(`<p>クライアントを解決できません: ${esc((err as Error).message)}</p>`);
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

  const redirect = new URL(pushed.redirect_uri);
  redirect.searchParams.set('state', pushed.state);
  redirect.searchParams.set('iss', AS_ISSUER); // RFC 9207

  if (req.body?.decision !== 'allow') {
    log.step(13, 'ユーザーが拒否しました');
    redirect.searchParams.set('error', 'access_denied');
    res.redirect(302, redirect.toString());
    return;
  }

  const code = randomId(24);
  authCodes.set(code, {
    client_id: pushed.client_id,
    redirect_uri: pushed.redirect_uri,
    scope: pushed.scope,
    resource: pushed.resource,
    code_challenge: pushed.code_challenge,
    sub: DEMO_USER.sub,
    expires_at: now() + AUTH_CODE_TTL_SEC,
    used: false,
  });
  redirect.searchParams.set('code', code);
  log.step(14, `認可コードを発行し、リダイレクトします: ${pushed.redirect_uri}`);
  res.redirect(302, redirect.toString());
});

// ---------------------------------------------------------------- トークン (15)
async function issueAccessToken(params: {
  sub: string;
  clientId: string;
  scope: string;
  resource: string;
}): Promise<string> {
  return new SignJWT({
    scope: params.scope,
    client_id: params.clientId,
    email: DEMO_USER.email,
    name: DEMO_USER.name,
  })
    .setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid!, typ: 'at+jwt' })
    .setIssuer(AS_ISSUER)
    .setSubject(params.sub)
    // RFC 8707: アクセストークンの受け手を MCP エンドポイントに限定する
    .setAudience(params.resource)
    .setIssuedAt()
    .setExpirationTime(`${TOKEN_TTL_SEC}s`)
    .setJti(randomId(16))
    .sign(privateKey);
}

function verifyPkce(verifier: string, challenge: string): boolean {
  const computed = crypto.createHash('sha256').update(verifier).digest('base64url');
  const a = Buffer.from(computed);
  const b = Buffer.from(challenge);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.post('/token', async (req, res) => {
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
      const refreshToken = randomId(32);
      refreshTokens.set(refreshToken, {
        client_id: entry.client_id,
        scope: entry.scope,
        resource: entry.resource,
        sub: entry.sub,
        expires_at: now() + 3600,
      });

      log.step(15, `認可コードをアクセストークンに交換しました (aud=${entry.resource})`);
      res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: TOKEN_TTL_SEC,
        scope: entry.scope,
        refresh_token: refreshToken,
      });
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

app.listen(PORTS.auth, () => {
  log.info(`Authorization Server を起動しました: ${AS_ISSUER}`);
});
