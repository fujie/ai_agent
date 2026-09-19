/**
 * ブラウザを使わずにフローを一通り流すスモークテスト。
 *
 * 人間の代わりに
 *   - Chat UI の代わりにプロンプトを送り
 *   - (12) 提示された認可 URL を開いて、同意画面で「許可する」を押し
 *   - (E3) MCP サーバーからの URL モード Elicitation に同意して URL を開き、
 *     本人確認と外部サービスの同意画面を通す
 * ところまで自動でやる。ブラウザの代わりに Cookie を保持してリダイレクトを辿る。
 *
 *   npm run smoke                 # hello (図の 1〜16)
 *   npm run smoke:untrusted       # 未登録のオーケストレーター → 拒否されれば成功
 *   npm run smoke:partner         # partner_hello (URL モード Elicitation)
 *   npm run smoke -- --phishing   # 別ユーザーが連携 URL を開くと拒否されることも確認する
 */
import { DEMO_USERS, ORCHESTRATORS, BASE } from '../src/shared/config.js';

const args = process.argv.slice(2);
/** --untrusted: registry に登録されていないオーケストレーターで試す。 */
const untrusted = args.includes('--untrusted');
/** --phishing: 連携 URL を別のユーザーが開いた場合に拒否されることも確かめる (--partner を含む)。 */
const phishing = args.includes('--phishing');
/** --partner: 外部サービス連携 (URL モード Elicitation) のツールを使う。 */
const partner = phishing || args.includes('--partner');
const orchestrator = untrusted ? ORCHESTRATORS.untrusted : ORCHESTRATORS.trusted;

const sessionId = `smoke-${Date.now()}`;
const prompt =
  args.find((a) => !a.startsWith('--')) ??
  (partner ? 'パートナー経由で太郎さんに挨拶して' : '太郎さんに挨拶して');

let reachedResource = false;
let finished = false;
let failed = false;
let finalMessage = '';
let phishingBlocked: boolean | undefined;
/** URL モードの Elicitation が実際に発生したか。 */
let elicited = false;

// ------------------------------------------------------------------ 簡易ブラウザ
/** オリジンごとの Cookie (ブラウザの代わり)。 */
const jar = new Map<string, Map<string, string>>();

function cookieHeader(url: URL): string | undefined {
  const cookies = jar.get(url.origin);
  return cookies?.size ? [...cookies].map(([k, v]) => `${k}=${v}`).join('; ') : undefined;
}

function storeCookies(url: URL, res: Response): void {
  for (const raw of res.headers.getSetCookie()) {
    const [pair] = raw.split(';');
    const i = pair.indexOf('=');
    const cookies = jar.get(url.origin) ?? new Map<string, string>();
    cookies.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
    jar.set(url.origin, cookies);
  }
}

/** リダイレクトを手で辿りながらページを開く (Cookie を保持)。 */
async function browse(
  start: string,
  init?: { method?: string; form?: Record<string, string> },
): Promise<{ status: number; url: string; html: string }> {
  let url = new URL(start);
  let method = init?.method ?? 'GET';
  let body: URLSearchParams | undefined = init?.form ? new URLSearchParams(init.form) : undefined;
  for (let hop = 0; hop < 10; hop++) {
    const headers: Record<string, string> = {};
    const cookie = cookieHeader(url);
    if (cookie) headers.cookie = cookie;
    if (body) headers['content-type'] = 'application/x-www-form-urlencoded';
    const res = await fetch(url, { method, headers, body, redirect: 'manual' });
    storeCookies(url, res);
    const location = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && location) {
      url = new URL(location, url);
      method = 'GET';
      body = undefined;
      continue;
    }
    return { status: res.status, url: url.toString(), html: await res.text() };
  }
  throw new Error('リダイレクトが多すぎます');
}

/** HTML のフォームの hidden 値を取り出す。 */
function hiddenInputs(html: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) {
    out[m[1]] = m[2].replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
  }
  return out;
}

/** (12)〜(14) このアプリ自身の認可: MCP の AS の同意画面で許可する。 */
async function approveAuthorization(authorizationUrl: string): Promise<void> {
  const page = await browse(authorizationUrl);
  if (page.status !== 200) throw new Error(`同意画面を取得できません (HTTP ${page.status})`);
  const form = hiddenInputs(page.html);
  if (!form.request_uri) throw new Error('同意画面から request_uri を取得できません');
  const done = await browse(`${new URL(authorizationUrl).origin}/authorize/decision`, {
    method: 'POST',
    form: { ...form, decision: 'allow' },
  });
  if (done.status !== 200) throw new Error(`Callback が失敗しました (HTTP ${done.status})`);
}

/** MCP の AS のログインユーザーを切り替える。 */
async function loginAs(sub: string): Promise<void> {
  await browse(`${BASE.auth}/session`, { method: 'POST', form: { sub, return_to: '/session' } });
}

/** (E5)(E6) 連携 URL を開き、本人確認と外部サービスの同意を通す。 */
async function completeConnection(url: string): Promise<{ status: number; html: string }> {
  const page = await browse(url);
  // 外部サービスの同意画面まで来たら「許可する」
  if (page.status === 200 && page.url.startsWith(BASE.partner)) {
    return browse(`${BASE.partner}/authorize/decision`, {
      method: 'POST',
      form: { ...hiddenInputs(page.html), decision: 'allow' },
    });
  }
  return page;
}

async function answerElicitation(id: string, action: 'accept' | 'decline' | 'cancel') {
  const res = await fetch(`${orchestrator.base}/api/elicitation/${id}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId, action }),
  });
  if (!res.ok) throw new Error(`Elicitation に回答できません (HTTP ${res.status})`);
}

// ------------------------------------------------------------------ イベント処理
interface FlowEvent {
  step?: number | string;
  title: string;
  detail?: string;
  level?: string;
}

async function handle(event: string, data: any): Promise<void> {
  if (event === 'flow') {
    const e = data as FlowEvent;
    const mark = e.level === 'error' ? '✖' : e.level === 'ok' ? '✔' : '·';
    console.log(`  ${mark} (${e.step ?? '-'}) ${e.title}${e.detail ? ` — ${e.detail}` : ''}`);
    if (e.level === 'error') failed = true;
    if (String(e.step).startsWith('16')) reachedResource = true;
    return;
  }
  if (event === 'authorization-request') {
    console.log(`\n  → (12) 認可 URL が提示されました (開く先: ${data.host})。自動で認可します。\n`);
    await approveAuthorization(data.url);
    return;
  }
  if (event === 'elicitation') {
    elicited = true;
    console.log(
      `\n  → (E3) ${data.server} から URL モードの Elicitation (開く先: ${data.host})。同意して開きます。\n`,
    );
    await answerElicitation(data.id, 'accept');

    if (phishing) {
      // 攻撃者が連携 URL を別のユーザー (佐藤 花子) に開かせた場合
      await loginAs(DEMO_USERS[1].sub);
      const attack = await completeConnection(data.url);
      phishingBlocked = attack.status === 403 && attack.html.includes('連携を中止しました');
      console.log(
        `  ${phishingBlocked ? '✔' : '✖'} [フィッシング対策] 別ユーザー (${DEMO_USERS[1].sub}) が開くと: HTTP ${attack.status}` +
          (phishingBlocked ? ' (連携を中止)' : ' (中止されなかった!)'),
      );
      await loginAs(DEMO_USERS[0].sub); // 本来のユーザーに戻す
    }

    const result = await completeConnection(data.url);
    const ok = result.status === 200 && result.html.includes('連携が完了しました');
    console.log(`  ${ok ? '✔' : '✖'} (E5-E6) 本人確認と外部サービスの認可: HTTP ${result.status}\n`);
    return;
  }
  if (event === 'message') {
    if (data.role === 'user') return; // サーバーはユーザーの発言も echo してくる
    finalMessage = data.content;
    console.log(`\n=== 最終応答 ===\n${data.content}\n`);
    finished = true;
  }
}

async function consumeEvents(): Promise<void> {
  const res = await fetch(`${orchestrator.base}/api/events?session=${sessionId}`, {
    headers: { accept: 'text/event-stream' },
  });
  if (!res.body) throw new Error('SSE に接続できません');

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (!finished) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let sep: number;
    while ((sep = buffer.indexOf('\n\n')) !== -1) {
      const raw = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      const event = raw.match(/^event: (.+)$/m)?.[1];
      const data = raw.match(/^data: (.+)$/m)?.[1];
      if (!event || !data) continue;
      // 認可や連携の処理 (ブラウザ操作) を待っている間も SSE を読み続けられるよう、await しない
      void handle(event, JSON.parse(data)).catch((err: Error) => {
        console.error(`  ✖ ${err.message}`);
        failed = true;
      });
    }
  }
  await reader.cancel().catch(() => undefined);
}

async function main(): Promise<void> {
  console.log(`オーケストレーター: ${orchestrator.label} (${orchestrator.base})`);
  console.log(`client_id: ${orchestrator.clientId}`);
  if (untrusted) console.log('期待する結果: Client registry に未登録のため認可が拒否されること');
  if (partner) console.log('シナリオ: 外部サービス連携 (URL モード Elicitation)');
  console.log(`プロンプト: 「${prompt}」\n`);

  const events = consumeEvents();
  await new Promise((r) => setTimeout(r, 300));
  const res = await fetch(`${orchestrator.base}/api/chat`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId, prompt }),
  });
  if (!res.ok) throw new Error(`/api/chat が失敗しました (HTTP ${res.status})`);

  const timeout = setTimeout(() => {
    console.error('✖ タイムアウトしました');
    process.exit(1);
  }, 60_000);

  await events;
  clearTimeout(timeout);

  if (untrusted) {
    const rejected = failed && !reachedResource;
    console.log(
      rejected
        ? '✔ 期待どおり拒否されました (未登録のクライアントはリソースにアクセスできない)'
        : '✖ 拒否されるはずが、リソースにアクセスできてしまいました',
    );
    process.exit(rejected ? 0 : 1);
  }
  if (partner) {
    if (!elicited) {
      console.log(
        '・このユーザーは既に外部サービスと連携済みのため、Elicitation は発生しませんでした' +
          ' (もう一度確かめるには MCP Server を再起動してください)',
      );
    }
    // --phishing では、別ユーザーでの拒否を実際に確かめられたことを合格の条件にする
    const phishingOk = phishing ? phishingBlocked === true : true;
    const ok = !failed && finalMessage.includes('Partner Greeting Service') && phishingOk;
    console.log(
      ok
        ? '✔ 外部サービス連携 (URL モード Elicitation) が完了しました'
        : phishing && phishingBlocked === undefined
          ? '✖ フィッシング対策を確かめられませんでした (Elicitation が発生していません)'
          : '✖ 外部サービス連携に失敗しました',
    );
    process.exit(ok ? 0 : 1);
  }
  process.exit(failed ? 1 : 0);
}

main().catch((err: Error) => {
  console.error(`✖ ${err.message}`);
  process.exit(1);
});
