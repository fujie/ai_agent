/**
 * Client registry (図の "Client registry")
 *
 * client_id (= Client ID Metadata Document の URL) を受け取り、
 *  - その URL からメタデータを取得 (図の破線: オーケストレーターがホストしている)
 *  - CIMD としての妥当性を検証
 *  - 取得結果と「登録済みかどうか」を保持
 * する小さなサービス。Authorization Server と MCP Server の双方から参照される。
 */
import express from 'express';
import { PORTS, CLIENT_ID_HEADER, TRUSTED_CLIENT_IDS } from '../shared/config.js';
import { createLogger } from '../shared/log.js';

const log = createLogger('registry');
const app = express();
app.use(express.json());

export interface ClientMetadata {
  client_id: string;
  client_name?: string;
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
}

const entries = new Map<string, Entry>();

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

/**
 * client_id として許容できる URL かを検証する。
 * CIMD では client_id は絶対 URL で、https であること (ローカル開発の localhost のみ例外)、
 * fragment / userinfo を含まないことが求められる。
 */
function assertValidClientIdUrl(clientId: string): URL {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    throw new CimdError('invalid_client_id', 'client_id が絶対 URL ではありません');
  }
  const isLocal = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLocal)) {
    throw new CimdError('invalid_client_id', 'client_id は https URL である必要があります');
  }
  if (url.hash) throw new CimdError('invalid_client_id', 'client_id に fragment を含められません');
  if (url.username || url.password) {
    throw new CimdError('invalid_client_id', 'client_id に userinfo を含められません');
  }
  return url;
}

/** CIMD の中身を検証する。 */
function validateMetadata(clientId: string, doc: unknown): ClientMetadata {
  if (typeof doc !== 'object' || doc === null) {
    throw new CimdError('invalid_client_metadata', 'CIMD が JSON オブジェクトではありません');
  }
  const meta = doc as Partial<ClientMetadata>;

  // 最重要: ドキュメント内の client_id は、取得元 URL と完全一致しなければならない。
  if (meta.client_id !== clientId) {
    throw new CimdError(
      'invalid_client_metadata',
      `CIMD 内の client_id (${meta.client_id}) が取得元 URL (${clientId}) と一致しません`,
    );
  }
  if (!Array.isArray(meta.redirect_uris) || meta.redirect_uris.length === 0) {
    throw new CimdError('invalid_client_metadata', 'redirect_uris がありません');
  }
  for (const uri of meta.redirect_uris) {
    try {
      new URL(uri);
    } catch {
      throw new CimdError('invalid_client_metadata', `redirect_uri が URL ではありません: ${uri}`);
    }
  }
  // CIMD で識別されるクライアントはクライアント認証を持たないパブリッククライアント。
  const authMethod = meta.token_endpoint_auth_method ?? 'none';
  if (authMethod !== 'none') {
    throw new CimdError(
      'invalid_client_metadata',
      `token_endpoint_auth_method は "none" である必要があります (${authMethod})`,
    );
  }
  return { ...(meta as ClientMetadata), token_endpoint_auth_method: 'none' };
}

async function resolveCimd(clientId: string): Promise<Entry> {
  assertValidClientIdUrl(clientId);
  log.info(`CIMD を取得します: ${clientId}`);

  let res: Response;
  try {
    res = await fetch(clientId, {
      headers: { accept: 'application/json' },
      redirect: 'error', // CIMD の取得ではリダイレクトを追わない
      signal: AbortSignal.timeout(5000),
    });
  } catch (err) {
    throw new CimdError('cimd_fetch_failed', `CIMD を取得できません: ${(err as Error).message}`);
  }
  if (!res.ok) {
    throw new CimdError('cimd_fetch_failed', `CIMD の取得に失敗しました (HTTP ${res.status})`);
  }

  let doc: unknown;
  try {
    doc = await res.json();
  } catch {
    throw new CimdError(
      'invalid_client_metadata',
      `CIMD が JSON として解釈できません (content-type: ${res.headers.get('content-type') ?? '不明'})`,
    );
  }

  const metadata = validateMetadata(clientId, doc);
  const now = new Date().toISOString();
  const existing = entries.get(clientId);
  const entry: Entry = {
    client_id: clientId,
    metadata,
    registered: existing?.registered ?? false,
    trusted: isTrusted(clientId),
    first_seen_at: existing?.first_seen_at ?? now,
    last_resolved_at: now,
  };
  entries.set(clientId, entry);
  log.info(
    `CIMD 検証 OK: ${metadata.client_name ?? clientId}` +
      (entry.trusted ? '' : ' ⚠ 許可リストにありません (未登録のまま)'),
  );
  return entry;
}

/** (6)(7) CIMD 確認 / CIMD 返却。キャッシュがあればそれを返す。 */
app.post('/clients/resolve', async (req, res) => {
  const clientId: unknown = req.body?.client_id;
  const force = req.body?.force === true;
  if (typeof clientId !== 'string') {
    res.status(400).json({ error: 'invalid_request', error_description: 'client_id が必要です' });
    return;
  }
  const cached = entries.get(clientId);
  if (cached && !force) {
    log.step(7, `CIMD 返却 (cache): ${clientId}`);
    res.json({ ...cached, cached: true });
    return;
  }
  try {
    const entry = await resolveCimd(clientId);
    log.step(7, `CIMD 返却: ${clientId}`);
    res.json({ ...entry, cached: false });
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
    const entry = entries.get(clientId) ?? (await resolveCimd(clientId));
    entry.registered = true;
    entries.set(clientId, entry);
    log.step(8, `クライアント登録: ${entry.metadata.client_name ?? clientId}`);
    res.status(201).json(entry);
  } catch (err) {
    const e = err as CimdError;
    res.status(400).json({ error: e.code ?? 'invalid_client', error_description: e.message });
  }
});

app.get('/clients', (_req, res) => {
  res.json({ clients: [...entries.values()], trusted_client_ids: TRUSTED_CLIENT_IDS });
});

app.listen(PORTS.registry, () => {
  log.info(`Client registry を起動しました: http://localhost:${PORTS.registry}`);
  log.info(`(MCP Server は "${CLIENT_ID_HEADER}" ヘッダの値をここに問い合わせます)`);
});
