/**
 * Client registry (図の "Client registry")
 *
 * client_id (= Client ID Metadata Document の URL) を受け取り、
 *  - その URL からメタデータを取得 (図の破線: オーケストレーターがホストしている)
 *  - CIMD としての妥当性を検証 (draft-ietf-oauth-client-id-metadata-document-02 / MCP 2026-07-28)
 *  - 取得結果と「登録済みかどうか」を保持
 * する小さなサービス。Authorization Server だけが参照する (AS の内部台帳に相当)。
 *
 * 以前は MCP Server がトークン無しのアクセス試行時にここへ問い合わせていた (図の 6〜8) が、
 * 標準の流れに合わせ、CIMD の解決と信頼ポリシーの判定は AS が認可リクエスト (図の 10) の
 * 時点で行う形に改めた。
 */
import dns from 'node:dns/promises';
import net from 'node:net';
import express from 'express';
import {
  BIND_HOST,
  DEV_ALLOW_LOOPBACK_CIMD,
  PORTS,
  TRUSTED_CLIENT_IDS,
} from '../shared/config.js';
import { createLogger } from '../shared/log.js';

const log = createLogger('registry');
const app = express();
app.use(express.json());

export interface ClientMetadata {
  client_id: string;
  client_name: string;
  client_uri?: string;
  logo_uri?: string;
  redirect_uris: string[];
  grant_types?: string[];
  response_types?: string[];
  token_endpoint_auth_method?: string;
  scope?: string;
  policy_uri?: string;
  tos_uri?: string;
  software_id?: string;
  software_version?: string;
}

interface Entry {
  client_id: string;
  metadata: ClientMetadata;
  /** AS 側に「登録済み」として認識されているか (図の 8)。 */
  registered: boolean;
  /** 許可リストに載っているか。載っていなければ登録を拒否する。 */
  trusted: boolean;
  first_seen_at: string;
  last_resolved_at: string;
  /** メタデータのキャッシュ期限 (epoch ms)。登録状態はキャッシュ期限と無関係に保持する。 */
  cache_expires_at: number;
}

const entries = new Map<string, Entry>();

/** CIMD の読み込み上限 (draft-02 の推奨値は 5KB)。 */
const MAX_CIMD_BYTES = 5 * 1024;
/** HTTP キャッシュヘッダを尊重しつつ、AS 側で上下限を設ける (draft-02 で MAY)。 */
const CACHE_DEFAULT_MS = 5 * 60_000;
const CACHE_MAX_MS = 24 * 60 * 60_000;

/**
 * CIMD が取得・検証できることと、そのクライアントを信頼してよいことは別の話。
 * CIMD は「誰を名乗っているか」しか保証しないので、登録の可否はこの許可リストで決める。
 */
function isTrusted(clientId: string): boolean {
  return TRUSTED_CLIENT_IDS.includes(clientId);
}

class CimdError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

const LOOPBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
const isLoopbackBind = LOOPBACK_HOSTNAMES.has(BIND_HOST);

/**
 * Client Identifier URL の検証 (draft-02 §3)。
 *
 *  - https でなければならない (MUST)。ただしループバック上の開発環境に限り http を許容する
 *  - path を含まなければならない (MUST)
 *  - "." や ".." のパスセグメントを含んではならない (MUST NOT)
 *  - fragment / userinfo を含んではならない (MUST NOT)
 *  - query を含むべきでない (SHOULD NOT)。このサーバーは受け付けない
 *
 * `new URL()` は ".." を解決してしまうので、セグメントの検査は元の文字列で行う。
 */
function assertValidClientIdUrl(clientId: string): URL {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    throw new CimdError('invalid_client_id', 'client_id が絶対 URL ではありません');
  }

  const devLoopback =
    DEV_ALLOW_LOOPBACK_CIMD && isLoopbackBind && LOOPBACK_HOSTNAMES.has(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && devLoopback)) {
    throw new CimdError('invalid_client_id', 'client_id は https URL でなければなりません');
  }
  if (url.username || url.password) {
    throw new CimdError('invalid_client_id', 'client_id に userinfo を含めてはいけません');
  }
  if (clientId.includes('#')) {
    throw new CimdError('invalid_client_id', 'client_id に fragment を含めてはいけません');
  }
  if (url.search || clientId.includes('?')) {
    throw new CimdError('invalid_client_id', 'client_id に query を含めないでください');
  }

  const rawPath = clientId.slice(clientId.indexOf('//') + 2).replace(/^[^/]*/, '');
  if (!rawPath || rawPath === '/') {
    throw new CimdError('invalid_client_id', 'client_id には path が必要です');
  }
  const segments = rawPath.split('/').map((s) => s.toLowerCase());
  if (segments.some((s) => s === '.' || s === '..' || s === '%2e' || s === '%2e%2e')) {
    throw new CimdError('invalid_client_id', 'client_id に "." や ".." のパスを含めてはいけません');
  }
  return url;
}

/** RFC 6890 の特殊用途アドレスか (SSRF 対策)。 */
function isSpecialUseAddress(address: string): { special: boolean; loopback: boolean } {
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number);
    const loopback = a === 127;
    const special =
      loopback ||
      a === 0 ||
      a === 10 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224;
    return { special, loopback };
  }
  const lower = address.toLowerCase();
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isSpecialUseAddress(mapped[1]);
  const loopback = lower === '::1';
  const special =
    loopback ||
    lower === '::' ||
    lower.startsWith('fc') ||
    lower.startsWith('fd') ||
    /^fe[89ab]/.test(lower) ||
    lower.startsWith('ff');
  return { special, loopback };
}

/**
 * 取得先が特殊用途アドレスでないことを確認する (draft-02: MUST NOT fetch)。
 * AS 自身がループバック上で動く開発環境に限り、ループバックだけは許可する (MAY)。
 *
 * 注: 名前解決と実際の接続の間で結果が変わる (DNS rebinding) 攻撃までは防げない。
 * 本番では解決済みアドレスに対して接続するなど、より厳密な対策が必要。
 */
async function assertFetchableHost(url: URL): Promise<void> {
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const addresses = net.isIP(host)
    ? [host]
    : (await dns.lookup(host, { all: true })).map((a) => a.address);
  for (const address of addresses) {
    const { special, loopback } = isSpecialUseAddress(address);
    if (!special) continue;
    if (loopback && DEV_ALLOW_LOOPBACK_CIMD && isLoopbackBind) continue;
    throw new CimdError(
      'invalid_client_id',
      `client_id のホストが特殊用途アドレス (${address}) に解決されるため取得しません`,
    );
  }
}

/** 本文を上限付きで読む (draft-02: 読み込む量を制限すべき。推奨 5KB)。 */
async function readLimited(res: Response, limit: number): Promise<string> {
  const declared = Number(res.headers.get('content-length') ?? 0);
  if (declared > limit) {
    throw new CimdError('invalid_client_metadata', `CIMD が大きすぎます (${declared} bytes)`);
  }
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      throw new CimdError('invalid_client_metadata', `CIMD が大きすぎます (${limit} bytes 超)`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Cache-Control からメタデータのキャッシュ期間を決める (上下限つき)。 */
function cacheDurationMs(res: Response): number {
  const cc = res.headers.get('cache-control') ?? '';
  if (/no-store|no-cache/i.test(cc)) return 0;
  const maxAge = cc.match(/max-age=(\d+)/i);
  if (!maxAge) return CACHE_DEFAULT_MS;
  return Math.min(Number(maxAge[1]) * 1000, CACHE_MAX_MS);
}

/** redirect_uri は localhost か https でなければならない (MCP 認可仕様: MUST)。 */
function assertAllowedRedirectUri(uri: string): void {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw new CimdError('invalid_client_metadata', `redirect_uri が URL ではありません: ${uri}`);
  }
  const loopback = LOOPBACK_HOSTNAMES.has(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new CimdError(
      'invalid_client_metadata',
      `redirect_uri は localhost か https である必要があります: ${uri}`,
    );
  }
  if (url.hash) {
    throw new CimdError('invalid_client_metadata', `redirect_uri に fragment は使えません: ${uri}`);
  }
}

/** 共有鍵に基づくクライアント認証方式 (CIMD では使用禁止)。 */
const SHARED_SECRET_METHODS = new Set([
  'client_secret_post',
  'client_secret_basic',
  'client_secret_jwt',
]);
/** JWK の秘密鍵メンバー。CIMD に秘密鍵を含めてはならない。 */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'];

/** CIMD の中身を検証する (draft-02 §4 / MCP 2026-07-28)。 */
function validateMetadata(clientId: string, doc: unknown): ClientMetadata {
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    throw new CimdError('invalid_client_metadata', 'CIMD が JSON オブジェクトではありません');
  }
  const meta = doc as Record<string, unknown>;

  // 最重要: ドキュメント内の client_id は、取得元 URL と完全一致 (単純な文字列比較) しなければならない。
  if (meta.client_id !== clientId) {
    throw new CimdError(
      'invalid_client_metadata',
      `CIMD 内の client_id (${String(meta.client_id)}) が取得元 URL (${clientId}) と一致しません`,
    );
  }
  // MCP は client_id / client_name / redirect_uris を必須としている
  if (typeof meta.client_name !== 'string' || !meta.client_name.trim()) {
    throw new CimdError('invalid_client_metadata', 'client_name がありません');
  }
  if (!Array.isArray(meta.redirect_uris) || meta.redirect_uris.length === 0) {
    throw new CimdError('invalid_client_metadata', 'redirect_uris がありません');
  }
  for (const uri of meta.redirect_uris) assertAllowedRedirectUri(String(uri));

  // 共有シークレットは CIMD では使えない
  if ('client_secret' in meta || 'client_secret_expires_at' in meta) {
    throw new CimdError('invalid_client_metadata', 'CIMD に client_secret を含めてはいけません');
  }
  const authMethod = String(meta.token_endpoint_auth_method ?? 'none');
  if (SHARED_SECRET_METHODS.has(authMethod)) {
    throw new CimdError(
      'invalid_client_metadata',
      `共有シークレット方式のクライアント認証 (${authMethod}) は CIMD では使えません`,
    );
  }
  if (authMethod !== 'none') {
    // private_key_jwt は仕様上許されるが、この AS はパブリッククライアント (none) のみ対応
    throw new CimdError(
      'invalid_client_metadata',
      `この認可サーバーは token_endpoint_auth_method="${authMethod}" に対応していません (none のみ)`,
    );
  }
  const jwks = meta.jwks as { keys?: Record<string, unknown>[] } | undefined;
  if (jwks?.keys?.some((k) => PRIVATE_JWK_MEMBERS.some((m) => m in k))) {
    throw new CimdError('invalid_client_metadata', 'CIMD に秘密鍵を含めてはいけません');
  }

  return { ...(meta as unknown as ClientMetadata), token_endpoint_auth_method: 'none' };
}

async function resolveCimd(clientId: string): Promise<Entry> {
  const url = assertValidClientIdUrl(clientId);
  await assertFetchableHost(url);
  log.info(`CIMD を取得します: ${clientId}`);

  let res: Response;
  try {
    res = await fetch(clientId, {
      headers: { accept: 'application/json' },
      redirect: 'manual', // CIMD の取得ではリダイレクトを自動で追ってはならない (MUST NOT)
      signal: AbortSignal.timeout(5000),
    });
  } catch (err) {
    throw new CimdError('cimd_fetch_failed', `CIMD を取得できません: ${(err as Error).message}`);
  }
  // CIMD は 200 OK で返されなければならない (リダイレクトやその他の成功系も不可)
  if (res.status !== 200) {
    throw new CimdError('cimd_fetch_failed', `CIMD の取得に失敗しました (HTTP ${res.status})`);
  }

  const text = await readLimited(res, MAX_CIMD_BYTES);
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new CimdError(
      'invalid_client_metadata',
      `CIMD が JSON として解釈できません (content-type: ${res.headers.get('content-type') ?? '不明'})`,
    );
  }

  // 不正なドキュメントやエラー応答はキャッシュしない (MUST NOT)。ここまで来たものだけを保存する
  const metadata = validateMetadata(clientId, doc);
  const now = new Date();
  const existing = entries.get(clientId);
  const entry: Entry = {
    client_id: clientId,
    metadata,
    registered: existing?.registered ?? false,
    trusted: isTrusted(clientId),
    first_seen_at: existing?.first_seen_at ?? now.toISOString(),
    last_resolved_at: now.toISOString(),
    cache_expires_at: now.getTime() + cacheDurationMs(res),
  };
  entries.set(clientId, entry);
  log.info(
    `CIMD 検証 OK: ${metadata.client_name}` +
      (entry.trusted ? '' : ' ⚠ 許可リストにありません (未登録のまま)'),
  );
  return entry;
}

function publicView(entry: Entry, cached: boolean) {
  const { cache_expires_at: _expires, ...rest } = entry;
  return { ...rest, cached };
}

/** (6)(7) CIMD 確認 / CIMD 返却。期限内のキャッシュがあればそれを返す。 */
app.post('/clients/resolve', async (req, res) => {
  const clientId: unknown = req.body?.client_id;
  const force = req.body?.force === true;
  if (typeof clientId !== 'string') {
    res.status(400).json({ error: 'invalid_request', error_description: 'client_id が必要です' });
    return;
  }
  const cached = entries.get(clientId);
  if (cached && !force && cached.cache_expires_at > Date.now()) {
    log.step(7, `CIMD 返却 (cache): ${clientId}`);
    res.json(publicView(cached, true));
    return;
  }
  try {
    const entry = await resolveCimd(clientId);
    log.step(7, `CIMD 返却: ${clientId}`);
    res.json(publicView(entry, false));
  } catch (err) {
    const e = err as CimdError;
    log.error(`CIMD 解決に失敗: ${e.message}`);
    res.status(400).json({ error: e.code ?? 'invalid_client', error_description: e.message });
  }
});

/** 登録済みかどうかの確認のみ (フェッチしない)。 */
app.get('/clients/lookup', (req, res) => {
  const clientId = String(req.query.client_id ?? '');
  const entry = entries.get(clientId);
  res.json({
    client_id: clientId,
    known: Boolean(entry),
    registered: entry?.registered ?? false,
    trusted: entry?.trusted ?? isTrusted(clientId),
    metadata: entry?.metadata ?? null,
  });
});

/**
 * (8) クライアント登録。Authorization Server から呼ばれる。
 * 許可リストに無いクライアントはここで拒否され、登録されないままになる。
 */
app.post('/clients', async (req, res) => {
  const clientId: unknown = req.body?.client_id;
  if (typeof clientId !== 'string') {
    res.status(400).json({ error: 'invalid_request', error_description: 'client_id が必要です' });
    return;
  }
  if (!isTrusted(clientId)) {
    log.warn(`登録を拒否しました (許可リストにありません): ${clientId}`);
    res.status(403).json({
      error: 'client_not_trusted',
      error_description: 'このクライアントは登録を許可されていません',
      client_id: clientId,
      registered: false,
      trusted: false,
    });
    return;
  }
  try {
    const existing = entries.get(clientId);
    const entry =
      existing && existing.cache_expires_at > Date.now() ? existing : await resolveCimd(clientId);
    entry.registered = true;
    entries.set(clientId, entry);
    log.step('10c', `クライアント登録: ${entry.metadata.client_name}`);
    res.status(201).json(publicView(entry, false));
  } catch (err) {
    const e = err as CimdError;
    res.status(400).json({ error: e.code ?? 'invalid_client', error_description: e.message });
  }
});

app.get('/clients', (_req, res) => {
  res.json({
    clients: [...entries.values()].map((e) => publicView(e, false)),
    trusted_client_ids: TRUSTED_CLIENT_IDS,
  });
});

app.listen(PORTS.registry, BIND_HOST, () => {
  log.info(`Client registry を起動しました: http://localhost:${PORTS.registry} (bind ${BIND_HOST})`);
  log.info('(CIMD の取得・検証と信頼ポリシーの判定を Authorization Server に提供します)');
  if (DEV_ALLOW_LOOPBACK_CIMD) {
    log.warn('開発用: ループバック上の CIMD 取得を許可しています (本番では無効にすること)');
  }
});
