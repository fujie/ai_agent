/**
 * 外部サービス: Partner Greeting Service
 *
 * URL モード Elicitation を「本来の用途」で使う場面を作るための、MCP とは無関係な第三者サービス。
 * 独自の認可サーバー (OAuth 2.1 / PKCE) と API を 1 プロセスに同居させている。
 *
 *  - MCP Server はこのサービスの OAuth クライアント (事前登録済み) として振る舞う
 *  - ユーザーはブラウザで直接このサービスの同意画面を操作する
 *    (外部サービスの認可情報は MCP クライアントを通らない: MCP 仕様の MUST)
 *  - 発行したトークンは MCP Server が保持し、ユーザーに紐付けて管理する
 */
import crypto from 'node:crypto';
import express from 'express';
import {
  BIND_HOST,
  PARTNER_API,
  PARTNER_CLIENT_ID,
  PARTNER_ISSUER,
  PARTNER_REDIRECT_URI,
  PARTNER_SCOPE,
  PORTS,
} from '../shared/config.js';
import { createLogger } from '../shared/log.js';

const log = createLogger('partner');
const app = express();
app.use(express.urlencoded({ extended: false }));

/** このサービスに事前登録されたクライアント (MCP の登録手段でいう「事前登録」に当たる)。 */
const CLIENTS: Record<string, { name: string; redirect_uris: string[] }> = {
  [PARTNER_CLIENT_ID]: { name: 'Hello MCP Server', redirect_uris: [PARTNER_REDIRECT_URI] },
};

/** このサービス側のアカウント (MCP 側のユーザーとは別の ID 体系)。 */
const PARTNER_ACCOUNT = { id: 'yamada-taro', display: '山田 太郎 (Partner Greeting アカウント)' };

interface Code {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scope: string;
  resource?: string;
  expires_at: number;
}
const codes = new Map<string, Code>();
const tokens = new Map<string, { scope: string; account: string; expires_at: number }>();

const now = () => Math.floor(Date.now() / 1000);
const randomId = (n = 24) => crypto.randomBytes(n).toString('base64url');
const esc = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );

app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: PARTNER_ISSUER,
    authorization_endpoint: `${PARTNER_ISSUER}/authorize`,
    token_endpoint: `${PARTNER_ISSUER}/token`,
    scopes_supported: [PARTNER_SCOPE],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    authorization_response_iss_parameter_supported: true,
  });
});

app.get('/authorize', (req, res) => {
  const q = req.query as Record<string, string | undefined>;
  const client = q.client_id ? CLIENTS[q.client_id] : undefined;
  // redirect_uri が検証できるまでは、エラーをリダイレクトで返してはいけない (オープンリダイレクト対策)
  if (!client || !q.redirect_uri || !client.redirect_uris.includes(q.redirect_uri)) {
    res.status(400).send('<p>client_id または redirect_uri が不正です。</p>');
    return;
  }
  if (
    q.response_type !== 'code' ||
    q.code_challenge_method !== 'S256' ||
    !q.code_challenge ||
    !q.state
  ) {
    res.status(400).send('<p>認可リクエストが不正です (code / PKCE S256 / state が必要)。</p>');
    return;
  }
  log.info(`同意画面を表示します: client=${client.name}`);
  const hidden = Object.entries(q)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(String(v ?? ''))}">`)
    .join('');
  res.type('html').send(`<!doctype html><html lang="ja"><head><meta charset="utf-8">
<title>Partner Greeting Service — 連携の許可</title>
<style>
 :root{color-scheme:light dark}
 body{font-family:system-ui,"Hiragino Sans",sans-serif;background:#f3f7f2;margin:0;padding:40px 16px;display:flex;justify-content:center}
 .card{background:#fff;max-width:480px;width:100%;border-radius:14px;box-shadow:0 8px 30px rgba(0,0,0,.08);padding:26px 28px;border-top:5px solid #1f9d55}
 h1{font-size:17px;margin:0 0 6px}.sub{color:#666;font-size:13px;margin:0 0 16px;line-height:1.6}
 .scope{display:inline-block;background:#e6f6ec;color:#17693a;border-radius:6px;padding:3px 8px;font-size:12px}
 .actions{display:flex;gap:10px;margin-top:20px}button{flex:1;padding:11px;border-radius:9px;border:0;font-size:14px;cursor:pointer}
 .ok{background:#1f9d55;color:#fff}.ng{background:#eceef1;color:#333}
 @media (prefers-color-scheme:dark){body{background:#131815}.card{background:#1d221f;box-shadow:none}.ng{background:#2a2e35;color:#ddd}}
</style></head><body><div class="card">
<h1>🌿 Partner Greeting Service</h1>
<p class="sub">${esc(PARTNER_ACCOUNT.display)} としてログイン中</p>
<p class="sub"><b>${esc(client.name)}</b> が、あなたの Partner Greeting アカウントで
挨拶 API を使う許可を求めています。</p>
<p><span class="scope">${esc(q.scope ?? PARTNER_SCOPE)}</span></p>
<form method="post" action="/authorize/decision">${hidden}
<div class="actions"><button class="ng" name="decision" value="deny">拒否</button>
<button class="ok" name="decision" value="allow">許可する</button></div></form>
</div></body></html>`);
});

app.post('/authorize/decision', (req, res) => {
  const b = req.body as Record<string, string | undefined>;
  const client = b.client_id ? CLIENTS[b.client_id] : undefined;
  if (!client || !b.redirect_uri || !client.redirect_uris.includes(b.redirect_uri) || !b.state) {
    res.status(400).send('<p>不正なリクエストです。</p>');
    return;
  }
  const redirect = new URL(b.redirect_uri);
  redirect.searchParams.set('state', b.state);
  redirect.searchParams.set('iss', PARTNER_ISSUER);
  if (b.decision !== 'allow') {
    log.info('ユーザーが連携を拒否しました');
    redirect.searchParams.set('error', 'access_denied');
    res.redirect(302, redirect.toString());
    return;
  }
  const code = randomId();
  codes.set(code, {
    client_id: b.client_id!,
    redirect_uri: b.redirect_uri,
    code_challenge: b.code_challenge!,
    scope: b.scope ?? PARTNER_SCOPE,
    resource: b.resource,
    expires_at: now() + 60,
  });
  redirect.searchParams.set('code', code);
  log.info(`認可コードを発行しました → ${b.redirect_uri}`);
  res.redirect(302, redirect.toString());
});

app.post('/token', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const b = req.body as Record<string, string | undefined>;
  const entry = b.code ? codes.get(b.code) : undefined;
  if (b.code) codes.delete(b.code); // 認可コードはワンタイム
  const verifierOk =
    entry &&
    b.code_verifier &&
    crypto.createHash('sha256').update(b.code_verifier).digest('base64url') === entry.code_challenge;
  if (
    b.grant_type !== 'authorization_code' ||
    !entry ||
    entry.expires_at < now() ||
    entry.client_id !== b.client_id ||
    entry.redirect_uri !== b.redirect_uri ||
    !verifierOk
  ) {
    res.status(400).json({ error: 'invalid_grant' });
    return;
  }
  const accessToken = randomId(32);
  tokens.set(accessToken, {
    scope: entry.scope,
    account: PARTNER_ACCOUNT.id,
    expires_at: now() + 3600,
  });
  log.info(`アクセストークンを発行しました (client=${entry.client_id})`);
  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: entry.scope,
  });
});

app.get('/api/greeting', (req, res) => {
  const header = req.header('authorization') ?? '';
  const token = header.toLowerCase().startsWith('bearer ')
    ? tokens.get(header.slice(7).trim())
    : undefined;
  if (!token || token.expires_at < now() || !token.scope.split(' ').includes(PARTNER_SCOPE)) {
    res.setHeader('WWW-Authenticate', `Bearer realm="partner", scope="${PARTNER_SCOPE}"`);
    res.status(401).json({ error: 'invalid_token' });
    return;
  }
  const name = String(req.query.name ?? '').trim() || 'ゲスト';
  log.info(`挨拶 API が呼ばれました (account=${token.account}, name=${name})`);
  res.json({
    greeting: `こんにちは、${name}さん！ Partner Greeting Service からのご挨拶です 🌿`,
    account: token.account,
  });
});

app.listen(PORTS.partner, BIND_HOST, () => {
  log.info(`Partner Greeting Service を起動しました: ${PARTNER_ISSUER} (API: ${PARTNER_API})`);
});
