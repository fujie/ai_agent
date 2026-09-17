/**
 * オーケストレーターの OAuth 2.1 クライアント部分。
 *
 * 図の 9〜15 に対応する:
 *  - 401 の WWW-Authenticate から Protected Resource Metadata を辿る (9)
 *  - PRM の authorization_servers から AS メタデータを取得 (RFC 8414)
 *  - PAR で認可リクエストを送り、認可 URL を組み立てる (10, 11)
 *  - 認可コードをアクセストークンに交換する (15)
 *
 * client_id には自分がホストしている Client ID Metadata Document の URL を使うので、
 * 動的クライアント登録 (DCR) は行わない。
 */
import crypto from 'node:crypto';
import { SCOPE } from '../shared/config.js';
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
  client_id_metadata_document_supported?: boolean;
}

export interface TokenSet {
  access_token: string;
  refresh_token?: string;
  scope: string;
  resource: string;
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
 * 401 に WWW-Authenticate が無い場合のフォールバック。
 * RFC 9728 の well-known パス (パス差し込み形 / ルート形) を順に試す。
 */
export function guessResourceMetadataUrls(resourceUri: string): string[] {
  const url = new URL(resourceUri);
  const path = url.pathname.replace(/\/$/, '');
  return [
    `${url.origin}/.well-known/oauth-protected-resource${path}`,
    `${url.origin}/.well-known/oauth-protected-resource`,
  ];
}

/** AS メタデータ (RFC 8414) の取得。 */
export async function fetchAuthorizationServerMetadata(
  issuer: string,
): Promise<AuthorizationServerMetadata> {
  const url = new URL(issuer);
  const path = url.pathname.replace(/\/$/, '');
  const candidates = [
    `${url.origin}/.well-known/oauth-authorization-server${path}`,
    `${url.origin}${path}/.well-known/openid-configuration`,
  ];
  for (const candidate of candidates) {
    const res = await fetch(candidate, { headers: { accept: 'application/json' } });
    if (!res.ok) continue;
    const meta = (await res.json()) as AuthorizationServerMetadata;
    if (meta.issuer !== issuer) {
      throw new OAuthFlowError(`AS メタデータの issuer が一致しません: ${meta.issuer} != ${issuer}`);
    }
    return meta;
  }
  throw new OAuthFlowError(`AS メタデータを取得できません: ${issuer}`);
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
}

/**
 * (10) 認可リクエストを AS に push し、(11) 返ってきた request_uri から認可 URL を作る。
 *
 * PAR に対応していない AS の場合は、通常のクエリパラメータ形式で認可 URL を組み立てる。
 */
export async function createAuthorizationRequest(
  as: AuthorizationServerMetadata,
  opts: { resource: string; scope?: string },
): Promise<AuthorizationRequest> {
  const pkce = createPkcePair();
  const state = crypto.randomBytes(16).toString('base64url');
  const scope = opts.scope ?? SCOPE;

  const params: Record<string, string> = {
    response_type: 'code',
    client_id: PROFILE.clientId, // = Client ID Metadata Document の URL
    redirect_uri: PROFILE.redirectUri,
    scope,
    state,
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256',
    resource: opts.resource, // RFC 8707
  };

  if (as.pushed_authorization_request_endpoint) {
    const res = await fetch(as.pushed_authorization_request_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(params),
    });
    const body = (await res.json()) as { request_uri?: string; error_description?: string };
    if (!res.ok || !body.request_uri) {
      throw new OAuthFlowError(`PAR に失敗しました: ${body.error_description ?? res.status}`);
    }
    const url = new URL(as.authorization_endpoint);
    url.searchParams.set('client_id', PROFILE.clientId);
    url.searchParams.set('request_uri', body.request_uri);
    return { authorizationUrl: url.toString(), state, pkce, resource: opts.resource };
  }

  const url = new URL(as.authorization_endpoint);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return { authorizationUrl: url.toString(), state, pkce, resource: opts.resource };
}

/** (15) 認可コードとトークンの交換。 */
export async function exchangeAuthorizationCode(
  as: AuthorizationServerMetadata,
  opts: { code: string; verifier: string; resource: string },
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
      resource: opts.resource,
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
    scope: body.scope ?? SCOPE,
    resource: opts.resource,
    expires_at: Math.floor(Date.now() / 1000) + (body.expires_in ?? 300),
  };
}

export async function refreshAccessToken(
  as: AuthorizationServerMetadata,
  token: TokenSet,
): Promise<TokenSet> {
  if (!token.refresh_token) throw new OAuthFlowError('refresh_token がありません');
  const res = await fetch(as.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: token.refresh_token,
      client_id: PROFILE.clientId,
      resource: token.resource,
    }),
  });
  const body = (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
    scope?: string;
    error_description?: string;
  };
  if (!res.ok || !body.access_token) {
    throw new OAuthFlowError(`トークン更新に失敗しました: ${body.error_description ?? res.status}`);
  }
  return {
    access_token: body.access_token,
    refresh_token: body.refresh_token ?? token.refresh_token,
    scope: body.scope ?? token.scope,
    resource: token.resource,
    expires_at: Math.floor(Date.now() / 1000) + (body.expires_in ?? 300),
  };
}

/** セッション × リソースごとのトークン置き場 (プロセス内メモリのみ)。 */
export class TokenStore {
  private tokens = new Map<string, TokenSet>();

  private key(sessionId: string, resource: string): string {
    return `${sessionId}::${resource}`;
  }

  get(sessionId: string, resource: string): TokenSet | undefined {
    const token = this.tokens.get(this.key(sessionId, resource));
    if (!token) return undefined;
    // 期限切れ間近 (30 秒前) なら無いものとして扱う
    if (token.expires_at - 30 <= Math.floor(Date.now() / 1000)) return undefined;
    return token;
  }

  getIncludingExpired(sessionId: string, resource: string): TokenSet | undefined {
    return this.tokens.get(this.key(sessionId, resource));
  }

  set(sessionId: string, token: TokenSet): void {
    this.tokens.set(this.key(sessionId, token.resource), token);
  }

  clear(sessionId: string, resource: string): void {
    this.tokens.delete(this.key(sessionId, resource));
  }
}
