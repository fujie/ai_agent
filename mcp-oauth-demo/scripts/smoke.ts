/**
 * ブラウザを使わずに図の 1〜16 を一通り流すスモークテスト。
 *
 * 人間の代わりに
 *   - Chat UI の代わりにプロンプトを送り
 *   - Elicitation (URL Mode) で提示された認可 URL を開き
 *   - 同意画面で「許可する」を押し
 *   - リダイレクト先 (Callback) を叩く
 * ところまで自動でやる。
 */
import { ORCHESTRATORS } from '../src/shared/config.js';

const args = process.argv.slice(2);
/** --untrusted を付けると、registry に登録されていないオーケストレーターで試す。 */
const untrusted = args.includes('--untrusted');
const orchestrator = untrusted ? ORCHESTRATORS.untrusted : ORCHESTRATORS.trusted;

const sessionId = `smoke-${Date.now()}`;
const prompt = args.find((a) => !a.startsWith('--')) ?? '太郎さんに挨拶して';

/** 図の 16 (リソースアクセス) まで到達したか。 */
let reachedResource = false;

interface FlowEvent {
  step?: number | string;
  title: string;
  detail?: string;
  level?: string;
}

let finished = false;
let failed = false;

/** 同意画面を開いて「許可する」を押し、リダイレクト先まで辿る。 */
async function approve(authorizationUrl: string): Promise<void> {
  const page = await fetch(authorizationUrl, { headers: { accept: 'text/html' } });
  const html = await page.text();
  if (!page.ok) throw new Error(`同意画面を取得できません (HTTP ${page.status}): ${html}`);

  const requestUri = html.match(/name="request_uri" value="([^"]+)"/)?.[1];
  if (!requestUri) throw new Error('同意画面から request_uri を取得できません');

  const decision = await fetch(`${new URL(authorizationUrl).origin}/authorize/decision`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ request_uri: requestUri, decision: 'allow' }),
    redirect: 'manual',
  });
  const location = decision.headers.get('location');
  if (!location) throw new Error(`リダイレクト先がありません (HTTP ${decision.status})`);

  const callback = await fetch(location);
  if (!callback.ok) throw new Error(`Callback が失敗しました (HTTP ${callback.status})`);
}

async function handle(event: string, data: any): Promise<void> {
  if (event === 'flow') {
    const e = data as FlowEvent;
    const mark = e.level === 'error' ? '✖' : e.level === 'ok' ? '✔' : '·';
    console.log(`  ${mark} (${e.step ?? '-'}) ${e.title}${e.detail ? ` — ${e.detail}` : ''}`);
    if (e.level === 'error') failed = true;
    if (e.step === 16) reachedResource = true;
    return;
  }
  if (event === 'elicitation') {
    const url: string = data.params.url;
    console.log(`\n  → Elicitation (${data.params.mode}) を受け取りました。自動で認可します。\n`);
    await approve(url);
    return;
  }
  if (event === 'message') {
    // サーバーはユーザーの発言も echo してくるので、assistant の応答だけを待つ
    if (data.role === 'user') return;
    console.log(`\n=== 最終応答 ===\n${data.content}\n`);
    finished = true;
  }
}

/** SSE を購読して、認可 URL が来たら自動で認可を済ませる。 */
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
      await handle(event, JSON.parse(data));
    }
  }
  await reader.cancel().catch(() => undefined);
}

async function main(): Promise<void> {
  console.log(`オーケストレーター: ${orchestrator.label} (${orchestrator.base})`);
  console.log(`client_id: ${orchestrator.clientId}`);
  if (untrusted) console.log('期待する結果: Client registry に未登録のため認可が拒否されること');
  console.log(`プロンプト: 「${prompt}」\n`);

  const events = consumeEvents();

  // SSE が繋がるのを少し待ってから送信する
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
  }, 30_000);

  await events;
  clearTimeout(timeout);

  if (untrusted) {
    // 未登録のクライアントは、リソースに到達せずエラーで終わるのが正しい
    const rejected = failed && !reachedResource;
    console.log(
      rejected
        ? '✔ 期待どおり拒否されました (未登録のクライアントはリソースにアクセスできない)'
        : '✖ 拒否されるはずが、リソースにアクセスできてしまいました',
    );
    process.exit(rejected ? 0 : 1);
  }

  process.exit(failed ? 1 : 0);
}

main().catch((err: Error) => {
  console.error(`✖ ${err.message}`);
  process.exit(1);
});
