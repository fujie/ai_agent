/**
 * MCP Server = OAuth の Resource Server (図の "MCP Server (Resource Server)")
 *
 *  - Streamable HTTP で MCP を提供し、`hello` ツールだけを持つ
 *  - 未認証アクセスには 401 + WWW-Authenticate を返し、
 *    Protected Resource Metadata (RFC 9728) の在り処を教える (図の 5 → 9)
 *  - アクセス試行時に client_id が添えられていれば、Client registry に CIMD を問い合わせ、
 *    未登録なら Authorization Server に登録を依頼する (図の 6 → 7 → 8)
 *  - アクセストークンは AS の JWKS で検証し、aud が自分自身であることを必ず確認する
 */
import express, { type NextFunction, type Request, type Response } from 'express';
import cors from 'cors';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
// このインポートで SDK の `Request.auth` 型拡張を読み込む (実行時の副作用はない)
import type {} from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { z } from 'zod';
import { AS_ISSUER, BASE, CLIENT_ID_HEADER, PORTS, RESOURCE_URI, SCOPE } from '../shared/config.js';
import { createLogger } from '../shared/log.js';

const log = createLogger('mcp');
const app = express();

app.use(
  cors({
    origin: true,
    // ブラウザから直接叩く場合に、401 のヒントを読めるようにしておく
    exposedHeaders: ['WWW-Authenticate', 'Mcp-Session-Id'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'Mcp-Session-Id',
      'MCP-Protocol-Version',
      'MCP-Client-Id',
    ],
  }),
);
app.use(express.json());

const PRM_URL = `${BASE.resource}/.well-known/oauth-protected-resource`;
const jwks = createRemoteJWKSet(new URL(`${AS_ISSUER}/jwks.json`));

// ------------------------------------------------- Protected Resource Metadata (9)
const protectedResourceMetadata = {
  resource: RESOURCE_URI,
  authorization_servers: [AS_ISSUER],
  scopes_supported: [SCOPE],
  bearer_methods_supported: ['header'],
  resource_name: 'Hello MCP Server',
  resource_documentation: `${BASE.resource}/docs`,
};

// RFC 9728 はリソースのパスを .well-known の後ろに差し込む形も定義している
app.get('/.well-known/oauth-protected-resource', (_req, res) => {
  log.step(9, 'Protected Resource Metadata を返します');
  res.json(protectedResourceMetadata);
});
app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => {
  log.step(9, 'Protected Resource Metadata を返します (path 付き)');
  res.json(protectedResourceMetadata);
});

app.get('/docs', (_req, res) => {
  res
    .type('html')
    .send('<h1>Hello MCP Server</h1><p>ツール: <code>hello</code> — 挨拶を返します。</p>');
});

// ------------------------------------------------- 6 → 7 → 8: CIMD 確認とクライアント登録
const announced = new Set<string>();

async function ensureClientKnown(clientId: string): Promise<void> {
  if (announced.has(clientId)) return;
  try {
    // (6) CIMD 確認 / (7) CIMD 返却
    log.step(6, `Client registry に CIMD を確認します: ${clientId}`);
    const resolved = await fetch(`${BASE.registry}/clients/resolve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_id: clientId }),
    });
    const body = (await resolved.json()) as {
      registered?: boolean;
      metadata?: { client_name?: string };
      error_description?: string;
    };
    if (!resolved.ok || !body.metadata) {
      log.warn(`CIMD を解決できませんでした: ${body.error_description ?? resolved.status}`);
      return;
    }
    log.step(7, `CIMD を受け取りました: ${body.metadata.client_name ?? clientId}`);

    // (8) 未登録なら AS にクライアント登録を依頼する
    if (!body.registered) {
      log.step(8, 'Authorization Server にクライアント登録を依頼します');
      const reg = await fetch(`${AS_ISSUER}/clients/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_id: clientId }),
      });
      if (!reg.ok) {
        log.warn(`クライアント登録に失敗しました (HTTP ${reg.status})`);
        return;
      }
    } else {
      log.step(8, '既に登録済みのため、登録はスキップします');
    }
    announced.add(clientId);
  } catch (err) {
    log.warn(`クライアント確認中にエラー: ${(err as Error).message}`);
  }
}

// ------------------------------------------------- アクセストークン検証
// 検証結果は SDK の AuthInfo として req.auth に載せる。
// こうしておくと、ツールハンドラ側でも extra.authInfo から同じ情報を参照できる。

/** HTTP ヘッダは ASCII しか運べないので、ヘッダ用に安全な文字だけを残す。 */
function toHeaderSafe(value: string): string {
  return value.replace(/[^\x20-\x7e]/g, '').replace(/"/g, "'") || 'authentication required';
}

/**
 * 401 チャレンジ。RFC 9728 に従い、WWW-Authenticate に
 * Protected Resource Metadata の場所 (resource_metadata) を載せる。
 * ヘッダには ASCII のみを入れ、日本語の説明は JSON ボディ側に置く。
 */
function challenge(
  res: Response,
  error: string,
  description: string,
  headerHint: string,
  status = 401,
): void {
  res.setHeader(
    'WWW-Authenticate',
    `Bearer realm="mcp", error="${error}", error_description="${toHeaderSafe(headerHint)}", resource_metadata="${PRM_URL}"`,
  );
  res.status(status).json({
    jsonrpc: '2.0',
    error: { code: -32001, message: description },
    id: null,
  });
}

async function requireAccessToken(req: Request, res: Response, next: NextFunction): Promise<void> {
  const clientId = req.header(CLIENT_ID_HEADER);
  const header = req.header('authorization');

  if (!header?.toLowerCase().startsWith('bearer ')) {
    log.step(5, `未認証のアクセス試行 (client_id=${clientId ?? 'なし'})`);
    // 図の 6〜8。トークンが無い段階でもクライアントの素性を CIMD で確認しておく
    if (clientId) await ensureClientKnown(clientId);
    log.info('401 を返します (WWW-Authenticate に PRM の場所を含む)');
    challenge(res, 'invalid_token', 'アクセストークンがありません', 'access token required');
    return;
  }

  const token = header.slice(7).trim();
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: AS_ISSUER,
      // 最重要: このトークンが「自分向け」に発行されたものかを必ず確認する
      // (トークンの使い回し / confused deputy を防ぐ)
      audience: RESOURCE_URI,
    });
    const scopes = String(payload.scope ?? '')
      .split(' ')
      .filter(Boolean);
    if (!scopes.includes(SCOPE)) {
      res.setHeader(
        'WWW-Authenticate',
        `Bearer realm="mcp", error="insufficient_scope", scope="${SCOPE}", resource_metadata="${PRM_URL}"`,
      );
      res
        .status(403)
        .json({ jsonrpc: '2.0', error: { code: -32002, message: 'scope が不足しています' }, id: null });
      return;
    }
    req.auth = {
      token,
      clientId: String(payload.client_id ?? ''),
      scopes,
      expiresAt: payload.exp,
      resource: new URL(RESOURCE_URI),
      extra: { sub: String(payload.sub), name: payload.name, email: payload.email },
    };
    log.info(`トークン検証 OK (sub=${payload.sub}, aud=${RESOURCE_URI})`);
    next();
  } catch (err) {
    log.warn(`トークン検証に失敗: ${(err as Error).message}`);
    challenge(res, 'invalid_token', (err as Error).message, (err as Error).message);
  }
}

// ------------------------------------------------- MCP 本体
function buildServer(auth: AuthInfo): McpServer {
  const server = new McpServer(
    { name: 'hello-mcp-server', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  server.registerTool(
    'hello',
    {
      title: 'Hello',
      description: '挨拶を返します。name を渡すとその名前で挨拶します。',
      inputSchema: { name: z.string().optional().describe('挨拶する相手の名前') },
    },
    async ({ name }) => {
      const who = name?.trim() || (auth.extra?.name as string | undefined) || 'World';
      log.step(16, `hello ツールを実行しました (name=${who})`);
      return {
        content: [
          { type: 'text' as const, text: `Hello, ${who}!` },
          {
            type: 'text' as const,
            text: `(MCP Server が認証済みリクエストとして処理しました: sub=${auth.extra?.sub}, client_id=${auth.clientId})`,
          },
        ],
      };
    },
  );

  return server;
}

// ステートレス運用: リクエストごとに server と transport を作って捨てる
app.post('/mcp', requireAccessToken, async (req, res) => {
  const server = buildServer(req.auth!);
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  res.on('close', () => {
    void transport.close();
    void server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    log.error(`MCP リクエストの処理に失敗: ${(err as Error).message}`);
    if (!res.headersSent) {
      res
        .status(500)
        .json({ jsonrpc: '2.0', error: { code: -32603, message: 'internal error' }, id: null });
    }
  }
});

for (const method of ['get', 'delete'] as const) {
  app[method]('/mcp', (_req, res) => {
    res.status(405).json({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'このデモはステートレスな POST のみ対応しています' },
      id: null,
    });
  });
}

app.listen(PORTS.resource, () => {
  log.info(`MCP Server (Resource Server) を起動しました: ${RESOURCE_URI}`);
  log.info(`Protected Resource Metadata: ${PRM_URL}`);
});
