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
  registry: 4400, // Client registry
} as const;

const origin = (port: number) => `http://localhost:${port}`;

export const BASE = {
  orchestrator: origin(PORTS.orchestrator),
  orchestratorUntrusted: origin(PORTS.orchestratorUntrusted),
  llm: origin(PORTS.llm),
  resource: origin(PORTS.resource),
  auth: origin(PORTS.auth),
  registry: origin(PORTS.registry),
} as const;

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
 */
export const TRUSTED_CLIENT_IDS: readonly string[] = [ORCHESTRATORS.trusted.clientId];

/**
 * デモ専用のヘッダ。標準仕様ではないが、図の 6〜8
 * (MCP Server が client registry に CIMD を問い合わせ、未登録なら AS に登録する)
 * を成立させるために、オーケストレーターが自分の client_id (= CIMD の URL) を
 * 最初のアクセス試行に添えて送る。
 */
export const CLIENT_ID_HEADER = 'mcp-client-id';

export const TOKEN_TTL_SEC = 600;
export const AUTH_CODE_TTL_SEC = 60;
export const PAR_TTL_SEC = 90;
