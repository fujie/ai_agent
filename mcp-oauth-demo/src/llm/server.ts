/**
 * LLM (図の "LLM") — ダミー実装。
 *
 * 本物の推論は行わず、決め打ちのルールで
 *  - 「どの MCP ツールを呼ぶか」(図の 4: MCP Server 呼び出し指示)
 *  - ツール結果を受け取った後の最終回答
 * を返すだけ。オーケストレーターとは実際の HTTP でやり取りする。
 */
import express from 'express';
import { PORTS } from '../shared/config.js';
import { createLogger } from '../shared/log.js';

const log = createLogger('llm');
const app = express();
app.use(express.json());

interface Message {
  role: 'user' | 'assistant' | 'tool';
  content: string;
  tool_name?: string;
}
interface ToolSpec {
  name: string;
  description?: string;
}

/** プロンプトから挨拶の相手を拾う (完全にヒューリスティック)。 */
function extractName(prompt: string): string | undefined {
  const patterns = [
    /(?:私|わたし|僕|ぼく|俺)は\s*([^\s、。です]+)\s*(?:です|だ|といいます|と言います)/,
    /([^\s、。「」]+)\s*さん(?:に|へ|を)/,
    /「([^」]+)」/,
    /(?:to|for|greet)\s+([A-Za-z][A-Za-z0-9_-]*)/i,
    /\bname\s*[=:]\s*([A-Za-z0-9_-]+)/i,
  ];
  for (const re of patterns) {
    const m = prompt.match(re);
    if (m?.[1]) return m[1].trim();
  }
  return undefined;
}

app.post('/v1/infer', (req, res) => {
  const messages: Message[] = req.body?.messages ?? [];
  const tools: ToolSpec[] = req.body?.tools ?? [];
  const last = messages.at(-1);
  const userPrompt = [...messages].reverse().find((m) => m.role === 'user')?.content ?? '';

  // ツール結果が返ってきた後のターン: 最終回答を組み立てる
  if (last?.role === 'tool') {
    log.info('ツール結果を受け取ったので最終回答を生成します');
    res.json({
      type: 'message',
      content: `MCP サーバーの ${last.tool_name ?? 'ツール'} を呼び出しました。結果は次のとおりです。\n\n${last.content}`,
    });
    return;
  }

  const hello = tools.find((t) => t.name === 'hello');
  if (hello) {
    const name = extractName(userPrompt);
    log.step(4, `MCP Server 呼び出し指示: hello(${name ?? '既定値'})`);
    res.json({
      type: 'tool_call',
      tool_calls: [
        {
          id: `call_${Date.now().toString(36)}`,
          server: 'hello-mcp-server',
          name: 'hello',
          arguments: name ? { name } : {},
        },
      ],
    });
    return;
  }

  log.info('使えるツールが無いので、そのまま応答します');
  res.json({
    type: 'message',
    content: '呼び出せる MCP ツールが見つかりませんでした。',
  });
});

app.listen(PORTS.llm, () => {
  log.info(`ダミー LLM を起動しました: http://localhost:${PORTS.llm}/v1/infer`);
});
