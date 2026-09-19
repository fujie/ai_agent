/**
 * オーケストレーターの OAuth 2.1 クライアント部分。
 *
 * 図の 9〜15 に対応する (MCP 認可仕様 2026-07-28 に準拠):
 *  - 401 の WWW-Authenticate から Protected Resource Metadata を辿る (9)
 *  - PRM の authorization_servers から AS メタデータを取得し、PKCE 対応を確認する
 *  - PAR で認可リクエストを送り、認可 URL を組み立てる (10, 11)
 *  - 認可レスポンスの iss を検証する (RFC 9207)
 *  - 認可コードをアクセストークンに交換する (15)
 *
 * client_id には自分がホストしている Client ID Metadata Document の URL を使うので、
 * 動的クライアント登録 (DCR。2026-07-28 で非推奨) は行わない。
 */
import crypto from 'node:crypto';
import { PROFILE } from './profile.js';

export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers?: string[];
  scopes_supported?: string[];
  bearer_methods_supported?: string[];
  resource_name?: string;
  resource_documentation?: string;
}

export interface AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  pushed_authorization_request_endpoint?: string;
  require_pushed_authorization_requests?: boolean;
  code_challenge_methods_supported?: string[];
  scopes_supported?: string[];
  authorization_response_iss_parameter_supported?: boolean;
  client_id_metadata_document_supported?: boolean;
}

export interface TokenSet {
  access_token: string;
  refresh_token?: string;
  /** AS が付与したスコープ (省略された場合は要求したスコープ)。 */
  scope?: string;
  resource: string;
  /** このトークンを発行した AS。トークンは AS ごとに分けて保持しなければならない。 */
  issuer: string;
  expires_at: number; // epoch 秒
}

export class OAuthFlowError extends Error {}

/** `WWW-Authenticate: Bearer realm="mcp", resource_metadata="https://..."` を分解する。 */
export function parseWwwAuthenticate(value: string | null): Record<string, string> {
  if (!value) return {};
  const out: Record<string, string> = {};
  const scheme = value.match(/^\s*(\w+)\s+/);
  if (scheme) out.scheme = scheme[1];
  for (const m of value.matchAll(/(\w+)\s*=\s*"([^"]*)"/g)) out[m[1]] = m[2];
  return out;
}

/** (9) Protected Resource Metadata (RFC 9728) の取得。 */
export async function fetchProtectedResourceMetadata(
  resourceMetadataUrl: string,
): Promise<ProtectedResourceMetadata> {
  const res = await fetch(resourceMetadataUrl, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new OAuthFlowError(`PRM の取得に失敗しました (HTTP ${res.status})`);
  const prm = (await res.json()) as ProtectedResourceMetadata;
  if (!prm.resource) throw new OAuthFlowError('PRM に resource がありません');
  return prm;
}

/**
 * 401 に resource_metadata が無い場合のフォールバック。
 * MCP 認可仕様の順序どおり、パス差し込み形 → ルート形の順に試す。
 */
export function guessResourceMetadataUrls(resourceUri: string): string[] {
  const url = new URL(resourceUri);
  const path = url.pathname.replace(/\/$/, '');
  const urls = [`${url.origin}/.well-known/oauth-protected-resource`];
  if (path) urls.unshift(`${url.origin}/.well-known/oauth-protected-resource${path}`);
  return urls;
}

/**
 * AS メタデータの探索 URL を、MCP 認可仕様 (2026-07-28) が定める優先順で返す。
 *
 *  issuer にパスがある場合 (例: https://auth.example.com/tenant1):
 *    1. /.well-known/oauth-authorization-server/tenant1   (RFC 8414 パス差し込み)
 *    2. /.well-known/openid-configuration/tenant1         (OIDC パス差し込み)
 *    3. /tenant1/.well-known/openid-configuration         (OIDC パス付加)
 *  issuer にパスが無い場合:
 *    1. /.well-known/oauth-authorization-server
 *    2. /.well-known/openid-configuration
 */
export function authorizationServerMetadataUrls(issuer: string): string[] {
  const url = new URL(issuer);
  const path = url.pathname.replace(/\/$/, '');
  if (!path) {
    return [
      `${url.origin}/.well-known/oauth-authorization-server`,
      `${url.origin}/.well-known/openid-configuration`,
    ];
  }
  return [
    `${url.origin}/.well-known/oauth-authorization-server${path}`,
    `${url.origin}/.well-known/openid-configuration${path}`,
    `${url.origin}${path}/.well-known/openid-configuration`,
  ];
}

/**
 * AS メタデータ (RFC 8414 / OIDC Discovery) を取得し、仕様どおりに検証する。
 *
 *  - issuer は探索に使った issuer と完全一致しなければならない (MUST)。一致しなければ使わない。
 *  - code_challenge_methods_supported が無い AS は PKCE 非対応とみなし、先に進んではならない (MUST)。
 *    PKCE の方式は S256 を使わなければならない (MUST) ので、S256 が含まれていることも確認する。
 */
export async function fetchAuthorizationServerMetadata(
  issuer: string,
): Promise<AuthorizationServerMetadata> {
  for (const candidate of authorizationServerMetadataUrls(issuer)) {
    const res = await fetch(candidate, { headers: { accept: 'application/json' } });
    if (!res.ok) continue;
    const meta = (await res.json()) as AuthorizationServerMetadata;

    if (meta.issuer !== issuer) {
      throw new OAuthFlowError(`AS メタデータの issuer が一致しません: ${meta.issuer} != ${issuer}`);
    }
    const methods = meta.code_challenge_methods_supported;
    if (!methods) {
      throw new OAuthFlowError(
        'AS メタデータに code_challenge_methods_supported がありません (PKCE 非対応のため中止します)',
      );
    }
    if (!methods.includes('S256')) {
      throw new OAuthFlowError('AS が PKCE の S256 に対応していないため中止します');
    }
    return meta;
  }
  throw new OAuthFlowError(`AS メタデータを取得できません: ${issuer}`);
}

/**
 * 要求するスコープを決める (MCP の Scope Selection Strategy)。
 *
 *  1. 401 の WWW-Authenticate に scope があれば、それを正とする (MUST: 今回の操作に必要なスコープ)
 *  2. 無ければ PRM の scopes_supported をすべて使う
 *  3. どちらも無ければ scope パラメータ自体を省略する
 */
export function selectScopes(
  challengeScope: string | undefined,
  prm: ProtectedResourceMetadata,
): { scope?: string; source: 'challenge' | 'prm' | 'none' } {
  if (challengeScope?.trim()) return { scope: challengeScope.trim(), source: 'challenge' };
  if (prm.scopes_supported?.length) return { scope: prm.scopes_supported.join(' '), source: 'prm' };
  return { source: 'none' };
}

export interface PkcePair {
  verifier: string;
  challenge: string;
}

export function createPkcePair(): PkcePair {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export interface AuthorizationRequest {
  authorizationUrl: string;
  state: string;
  pkce: PkcePair;
  resource: string;
  scope?: string;
}

/**
 * (10) 認可リクエストを AS に push し、(11) 返ってきた request_uri から認可 URL を作る。
 *
 * PAR (RFC 9126 §2.1) のリクエストボディは application/x-www-form-urlencoded でなければならない。
 * PAR に対応していない AS の場合は、通常のクエリパラメータ形式で認可 URL を組み立てる。
 */
export async function createAuthorizationRequest(
  as: AuthorizationServerMetadata,
  opts: { resource: string; scope?: string },
): Promise<AuthorizationRequest> {
  const pkce = createPkcePair();
  const state = crypto.randomBytes(16).toString('base64url');

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: PROFILE.clientId, // = Client ID Metadata Document の URL
    redirect_uri: PROFILE.redirectUri,
    state,
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256',
    resource: opts.resource, // RFC 8707 (MCP では MUST)
  });
  if (opts.scope) params.set('scope', opts.scope);

  if (as.pushed_authorization_request_endpoint) {
    const res = await fetch(as.pushed_authorization_request_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: params,
    });
    const body = (await res.json()) as { request_uri?: string; error_description?: string };
    if (!res.ok || !body.request_uri) {
      throw new OAuthFlowError(`PAR に失敗しました: ${body.error_description ?? res.status}`);
    }
    const url = new URL(as.authorization_endpoint);
    url.searchParams.set('client_id', PROFILE.clientId);
    url.searchParams.set('request_uri', body.request_uri);
    return { authorizationUrl: url.toString(), state, pkce, resource: opts.resource, scope: opts.scope };
  }

  if (as.require_pushed_authorization_requests) {
    throw new OAuthFlowError('AS が PAR を必須としていますが、PAR エンドポイントがありません');
  }
  const url = new URL(as.authorization_endpoint);
  for (const [k, v] of params) url.searchParams.set(k, v);
  return { authorizationUrl: url.toString(), state, pkce, resource: opts.resource, scope: opts.scope };
}

/**
 * 認可レスポンスの iss 検証 (RFC 9207 §2.4 / MCP 認可仕様の判定表)。
 *
 * | AS メタデータの iss 対応 | レスポンスの iss | 動作                     |
 * | true                     | あり             | 記録した issuer と比較   |
 * | true                     | なし             | 拒否                     |
 * | false / 無し             | あり             | 記録した issuer と比較   |
 * | false / 無し             | なし             | そのまま進む             |
 *
 * 比較は単純な文字列比較で、大文字小文字・既定ポート・末尾スラッシュ等の正規化はしない (MUST NOT)。
 */
export function validateAuthorizationResponseIssuer(
  as: AuthorizationServerMetadata,
  iss: string | undefined,
): { ok: true } | { ok: false; reason: string } {
  if (iss !== undefined) {
    return iss === as.issuer
      ? { ok: true }
      : { ok: false, reason: `予期しない issuer からの応答です: ${iss}` };
  }
  if (as.authorization_response_iss_parameter_supported === true) {
    return { ok: false, reason: 'AS は iss を返すと宣言しているのに、応答に iss がありません' };
  }
  return { ok: true };
}

/** (15) 認可コードとトークンの交換。 */
export async function exchangeAuthorizationCode(
  as: AuthorizationServerMetadata,
  opts: { code: string; verifier: string; resource: string; scope?: string },
): Promise<TokenSet> {
  const res = await fetch(as.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: opts.code,
      redirect_uri: PROFILE.redirectUri,
      client_id: PROFILE.clientId, // パブリッククライアントなのでクライアント認証はしない
      code_verifier: opts.verifier,
      resource: opts.resource, // MCP: トークンリクエストにも resource を含めなければならない
    }),
  });
  const body = (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
    scope?: string;
    error_description?: string;
    error?: string;
  };
  if (!res.ok || !body.access_token) {
    throw new OAuthFlowError(
      `トークン交換に失敗しました: ${body.error_description ?? body.error ?? res.status}`,
    );
  }
  return {
    access_token: body.access_token,
    refresh_token: body.refresh_token,
    scope: body.scope ?? opts.scope,
    resource: opts.resource,
    issuer: as.issuer,
    expires_at: Math.floor(Date.now() / 1000) + (body.expires_in ?? 300),
  };
}

/**
 * トークン置き場 (プロセス内メモリのみ)。
 *
 * MCP 認可仕様: クライアントは認可サーバーごとに登録情報・トークンを分けて保持しなければならず、
 * 別の AS のものを流用してはならない (MUST)。そのためキーに AS の issuer を含める。
 * リソースに対応する AS は PRM で決まるので、最後に確認した対応関係も覚えておく。
 */
export class TokenStore {
  private tokens = new Map<string, TokenSet>();
  private issuerByResource = new Map<string, string>();

  private key(sessionId: string, issuer: string, resource: string): string {
    return `${sessionId}::${issuer}::${resource}`;
  }

  /** PRM で確認した「このリソースの AS はこれ」という対応を記録する。 */
  rememberIssuer(resource: string, issuer: string): void {
    this.issuerByResource.set(resource, issuer);
  }

  get(sessionId: string, resource: string): TokenSet | undefined {
    const issuer = this.issuerByResource.get(resource);
    if (!issuer) return undefined;
    const token = this.tokens.get(this.key(sessionId, issuer, resource));
    if (!token) return undefined;
    // 期限切れ間近 (30 秒前) なら無いものとして扱う
    if (token.expires_at - 30 <= Math.floor(Date.now() / 1000)) return undefined;
    return token;
  }

  set(sessionId: string, token: TokenSet): void {
    this.rememberIssuer(token.resource, token.issuer);
    this.tokens.set(this.key(sessionId, token.issuer, token.resource), token);
  }

  clear(sessionId: string, resource: string): void {
    for (const key of this.tokens.keys()) {
      if (key.startsWith(`${sessionId}::`) && key.endsWith(`::${resource}`)) this.tokens.delete(key);
    }
  }
}
