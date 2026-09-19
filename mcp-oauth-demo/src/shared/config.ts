/**
 * 図中の各コンポーネントの配置。すべて localhost 上の別プロセスとして動かし、
 * コンポーネント間は実際の HTTP で通信する。
 *
 * オーケストレーターは 2 つ起動する:
 *  - trusted   : Client registry に登録が許可されている、正規のクライアント
 *  - untrusted : CIMD は公開しているが、registry が登録を許可していないクライアント
 * Chat UI からどちらを使うか切り替えられる。
 */
export const PORTS = {
  orchestrator: 4000, // オーケストレーター (信頼できる) + Chat UI
  orchestratorUntrusted: 4001, // オーケストレーター (信頼できない / 未登録)
  llm: 4100, // LLM (ダミー)
  resource: 4200, // MCP Server (Resource Server)
  auth: 4300, // Authorization Server
  registry: 4400, // Client registry (AS が参照するクライアント台帳)
  partner: 4500, // 外部サービス (Partner Greeting Service: 独自の AS + API)
} as const;

const origin = (port: number) => `http://localhost:${port}`;

export const BASE = {
  orchestrator: origin(PORTS.orchestrator),
  orchestratorUntrusted: origin(PORTS.orchestratorUntrusted),
  llm: origin(PORTS.llm),
  resource: origin(PORTS.resource),
  auth: origin(PORTS.auth),
  registry: origin(PORTS.registry),
  partner: origin(PORTS.partner),
} as const;

/**
 * すべてのサービスが待ち受けるアドレス。
 * MCP の Streamable HTTP 仕様は、ローカルで動かすサーバーは全インターフェース (0.0.0.0) ではなく
 * ループバックだけに bind することを推奨している (SHOULD)。
 */
export const BIND_HOST = '127.0.0.1';

/** 準拠する MCP のプロトコル版 (2026-07-28: initialize を廃止したステートレス版)。 */
export const MCP_PROTOCOL_VERSION = '2026-07-28';

/**
 * CIMD (draft-ietf-oauth-client-id-metadata-document-02) は、AS が特殊用途アドレス
 * (RFC 6890) から CIMD を取得することを禁じている (MUST NOT)。ただし AS 自身が
 * ループバック上で動く開発環境に限り、ループバックからの取得を許してよい (MAY)。
 * このデモは localhost 上で完結するので、その例外を明示的に有効にしている。
 * 本番では必ず false にすること。
 */
export const DEV_ALLOW_LOOPBACK_CIMD = true;

/** MCP のエンドポイント。RFC 8707 の `resource` パラメータ / トークンの `aud` にもこの値を使う。 */
export const RESOURCE_URI = `${BASE.resource}/mcp`;

/** Authorization Server の issuer (RFC 8414 のメタデータ探索に使う)。 */
export const AS_ISSUER = BASE.auth;

/** このデモで扱うスコープ。 */
export const SCOPE = 'mcp:tools';

export type OrchestratorVariant = 'trusted' | 'untrusted';

export interface OrchestratorProfile {
  variant: OrchestratorVariant;
  /** Chat UI の設定に表示する名前。 */
  label: string;
  description: string;
  port: number;
  base: string;
  /**
   * Client ID Metadata Document の URL。これがそのまま client_id になる。
   * 事前登録 (DCR) なしで AS がクライアントを識別できる。
   */
  clientId: string;
  redirectUri: string;
  /** CIMD の client_name。AS の同意画面に表示される。 */
  clientName: string;
}

function profile(
  variant: OrchestratorVariant,
  port: number,
  clientName: string,
  label: string,
  description: string,
): OrchestratorProfile {
  const base = origin(port);
  return {
    variant,
    label,
    description,
    port,
    base,
    clientId: `${base}/oauth/client-metadata.json`,
    redirectUri: `${base}/oauth/callback`,
    clientName,
  };
}

export const ORCHESTRATORS: Record<OrchestratorVariant, OrchestratorProfile> = {
  trusted: profile(
    'trusted',
    PORTS.orchestrator,
    'Demo Orchestrator (MCP Client)',
    '信頼できるオーケストレーター',
    'Client registry に登録が許可されているクライアント',
  ),
  untrusted: profile(
    'untrusted',
    PORTS.orchestratorUntrusted,
    'Unknown Orchestrator (未登録)',
    '信頼できないオーケストレーター',
    'CIMD は公開しているが、Client registry に登録されていないクライアント',
  ),
};

/**
 * Client registry が登録を許可するクライアントの許可リスト。
 *
 * CIMD は「クライアントが何者を名乗っているか」を検証できるだけで、
 * 「そのクライアントを信頼してよいか」までは決められない。
 * 信頼の判断はこの許可リスト (= registry への登録可否) が担う。
 * CIMD 仕様の「ドメイン等に基づく信頼ポリシー」(§6.4 / §6.8, MAY) に当たる。
 */
export const TRUSTED_CLIENT_IDS: readonly string[] = [
  ORCHESTRATORS.trusted.clientId,
  // MCP Server 自身も、外部サービス連携の本人確認のために AS のクライアントになる
  `${BASE.resource}/oauth/client-metadata.json`,
];

// ------------------------------------------------------------------ 外部サービス連携
// URL モードの Elicitation を「本来の用途」で使う場面:
// MCP Server が外部サービス (Partner Greeting Service) の OAuth クライアントとなり、
// ユーザーの代わりに外部 API を呼ぶ。外部サービスの認可はクライアントを経由させず、
// ユーザーがブラウザで直接行う。

/** MCP Server が MCP の AS に対して名乗る client_id (CIMD の URL)。本人確認にだけ使う。 */
export const MCP_SERVER_CLIENT_ID = `${BASE.resource}/oauth/client-metadata.json`;
export const MCP_SERVER_IDENTITY_REDIRECT_URI = `${BASE.resource}/connect/identity/callback`;

/** 外部サービス側に事前登録された MCP Server のクライアント (登録手段の優先順位 1 位の「事前登録」)。 */
export const PARTNER_CLIENT_ID = 'hello-mcp-server';
export const PARTNER_REDIRECT_URI = `${BASE.resource}/connect/partner/callback`;
export const PARTNER_ISSUER = BASE.partner;
export const PARTNER_API = `${BASE.partner}/api/greeting`;
export const PARTNER_SCOPE = 'greeting:read';

/** MCP の AS のデモ用ユーザー。フィッシング対策の確認用に 2 人用意する。 */
export const DEMO_USERS = [
  { sub: 'user-0001', name: '山田 太郎', email: 'taro@example.com' },
  { sub: 'user-0002', name: '佐藤 花子', email: 'hanako@example.com' },
] as const;

export const TOKEN_TTL_SEC = 600;
export const AUTH_CODE_TTL_SEC = 60;
export const PAR_TTL_SEC = 90;
