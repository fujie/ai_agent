/**
 * オーケストレーターの MCP クライアント部分 (MCP 2026-07-28)。
 *
 *  - (5) アクセス試行: まずトークン無しで `server/discover` を投げ、401 と
 *    WWW-Authenticate を実際に受け取る
 *  - (16) リソースアクセス: アクセストークンを付けて MCP SDK で接続し、ツールを呼ぶ
 *
 * 2026-07-28 では initialize ハンドシェイクが廃止され、すべてのリクエストが
 * `_meta` にプロトコル版・クライアント情報・クライアント能力を持つ (ステートレス)。
 */
import {
  Client,
  StreamableHTTPClientTransport,
  type ElicitRequestURLParams,
  type ElicitResult,
} from '@modelcontextprotocol/client';
import { MCP_PROTOCOL_VERSION, RESOURCE_URI } from '../shared/config.js';

const CLIENT_INFO = { name: 'orchestrator', version: '1.0.0' };

/**
 * MCP サーバーから URL モードの Elicitation (MRTR の inputRequests 経由) が来たときに呼ばれる。
 * ユーザーに URL を示して同意を取り、その結果 (accept / decline / cancel) を返す。
 */
export type UrlElicitationHandler = (
  params: Pick<ElicitRequestURLParams, 'message' | 'url'>,
) => Promise<ElicitResult['action']>;

export interface ProbeResult {
  status: number;
  wwwAuthenticate: string | null;
  body?: unknown;
}

/**
 * (5) トークン無しでのアクセス試行。
 *
 * 2026-07-28 形式の `server/discover` をそのまま POST する。
 * Streamable HTTP では、ボディの `_meta` と同じ値を HTTP ヘッダにも載せる必要がある
 * (MCP-Protocol-Version / Mcp-Method)。値が食い違うとサーバーは HeaderMismatch で拒否する。
 */
export async function probeResource(): Promise<ProbeResult> {
  const method = 'server/discover';
  const res = await fetch(RESOURCE_URI, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'mcp-method': method,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'probe-1',
      method,
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': MCP_PROTOCOL_VERSION,
          'io.modelcontextprotocol/clientInfo': CLIENT_INFO,
          'io.modelcontextprotocol/clientCapabilities': {},
        },
      },
    }),
  });

  let body: unknown;
  try {
    body = await res.json();
  } catch {
    body = undefined;
  }
  return { status: res.status, wwwAuthenticate: res.headers.get('www-authenticate'), body };
}

export interface McpSession {
  client: Client;
  /** サーバーと合意したプロトコル版。 */
  protocolVersion: string | undefined;
  close: () => Promise<void>;
}

/**
 * (16) アクセストークンを付けて MCP サーバーに接続する。
 *
 * `versionNegotiation` で 2026-07-28 に固定している。connect() は `server/discover` で
 * サーバーが同じ版に対応しているかを確かめ、以後のリクエストには SDK が
 * `_meta` と Mcp-Method / Mcp-Name / MCP-Protocol-Version ヘッダを自動で付ける。
 * (旧版へのフォールバックはせず、非対応なら明示的に失敗させる)
 */
export async function connect(
  accessToken: string,
  onUrlElicitation: UrlElicitationHandler,
): Promise<McpSession> {
  const transport = new StreamableHTTPClientTransport(new URL(RESOURCE_URI), {
    requestInit: {
      headers: {
        // MCP 認可仕様: すべての HTTP リクエストに Authorization を付けなければならない (MUST)
        authorization: `Bearer ${accessToken}`,
      },
    },
  });
  const client = new Client(CLIENT_INFO, {
    // URL モードの Elicitation に対応することを宣言する。宣言していないクライアントには、
    // サーバーは URL モードの Elicitation を送ってはならない (MUST NOT)。
    capabilities: { elicitation: { url: {} } },
    versionNegotiation: { mode: { pin: MCP_PROTOCOL_VERSION } },
  });

  // 2026-07-28 の MRTR: サーバーが tools/call に input_required を返すと、SDK がこのハンドラを
  // 呼び、返した結果を inputResponses に入れて元のリクエストを再試行する。
  client.setRequestHandler('elicitation/create', async (request) => {
    const params = request.params;
    if (params.mode !== 'url') {
      // このクライアントはフォームモードに対応していない (capabilities でも宣言していない)
      return { action: 'decline' as const };
    }
    const action = await onUrlElicitation({ message: params.message, url: params.url });
    return { action };
  });

  await client.connect(transport);
  return {
    client,
    protocolVersion: client.getNegotiatedProtocolVersion(),
    close: async () => {
      await client.close().catch(() => undefined);
    },
  };
}

export interface ToolSummary {
  name: string;
  description?: string;
}

export async function listTools(session: McpSession): Promise<ToolSummary[]> {
  const { tools } = await session.client.listTools();
  return tools.map((t) => ({ name: t.name, description: t.description }));
}

export async function callTool(
  session: McpSession,
  name: string,
  args: Record<string, unknown>,
): Promise<string> {
  // URL モードの Elicitation では、同意後の再試行中にサーバーがブラウザでの
  // 外部認可の完了を待つことがあるので、タイムアウトを長めにとる
  const result = await session.client.callTool({ name, arguments: args }, { timeout: 240_000 });
  const content = (result.content ?? []) as Array<{ type: string; text?: string }>;
  return content
    .filter((c) => c.type === 'text')
    .map((c) => c.text ?? '')
    .join('\n');
}
