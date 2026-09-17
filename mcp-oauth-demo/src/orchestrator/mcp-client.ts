/**
 * オーケストレーターの MCP クライアント部分。
 *
 *  - (5) アクセス試行: まずトークン無しで MCP の initialize を投げ、401 と
 *    WWW-Authenticate を実際に受け取る
 *  - (16) リソースアクセス: アクセストークンを付けて MCP SDK で接続し、ツールを呼ぶ
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { LATEST_PROTOCOL_VERSION } from '@modelcontextprotocol/sdk/types.js';
import { CLIENT_ID_HEADER, RESOURCE_URI } from '../shared/config.js';
import { PROFILE } from './profile.js';

export interface ProbeResult {
  status: number;
  wwwAuthenticate: string | null;
  /** WWW-Authenticate に含まれていた resource_metadata の URL。 */
  resourceMetadataUrl?: string;
  body?: unknown;
}

function parseParams(value: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of value.matchAll(/(\w+)\s*=\s*"([^"]*)"/g)) out[m[1]] = m[2];
  return out;
}

/**
 * (5) トークン無しでのアクセス試行。
 * MCP の initialize をそのまま POST するので、実際のプロトコル上のやり取りになる。
 */
export async function probeResource(): Promise<ProbeResult> {
  const res = await fetch(RESOURCE_URI, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      // 自分の client_id (CIMD の URL) を名乗る。MCP Server 側はこれを使って
      // Client registry への CIMD 確認 (6〜8) を行う。
      [CLIENT_ID_HEADER]: PROFILE.clientId,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: LATEST_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'orchestrator', version: '1.0.0' },
      },
    }),
  });

  const wwwAuthenticate = res.headers.get('www-authenticate');
  const params = wwwAuthenticate ? parseParams(wwwAuthenticate) : {};
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    body = undefined;
  }
  return {
    status: res.status,
    wwwAuthenticate,
    resourceMetadataUrl: params.resource_metadata,
    body,
  };
}

export interface McpSession {
  client: Client;
  close: () => Promise<void>;
}

/** (16) アクセストークンを付けて MCP サーバーに接続する。 */
export async function connect(accessToken: string): Promise<McpSession> {
  const transport = new StreamableHTTPClientTransport(new URL(RESOURCE_URI), {
    requestInit: {
      headers: {
        authorization: `Bearer ${accessToken}`,
        [CLIENT_ID_HEADER]: PROFILE.clientId,
      },
    },
  });
  const client = new Client({ name: 'orchestrator', version: '1.0.0' }, { capabilities: {} });
  await client.connect(transport);
  return {
    client,
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
  const result = await session.client.callTool({ name, arguments: args });
  const content = (result.content ?? []) as Array<{ type: string; text?: string }>;
  return content
    .filter((c) => c.type === 'text')
    .map((c) => c.text ?? '')
    .join('\n');
}
