const COLORS: Record<string, string> = {
  registry: '\x1b[35m',
  auth: '\x1b[33m',
  mcp: '\x1b[32m',
  llm: '\x1b[34m',
  orchestrator: '\x1b[36m',
};
const RESET = '\x1b[0m';

export function createLogger(component: keyof typeof COLORS | string) {
  const color = COLORS[component] ?? '';
  const tag = `${color}[${component}]${RESET}`;
  return {
    info(message: string, extra?: unknown) {
      if (extra === undefined) console.log(`${tag} ${message}`);
      else console.log(`${tag} ${message}`, extra);
    },
    /** 図の番号付きステップを出力する。 */
    step(no: number | string, message: string, extra?: unknown) {
      if (extra === undefined) console.log(`${tag} (${no}) ${message}`);
      else console.log(`${tag} (${no}) ${message}`, extra);
    },
    warn(message: string, extra?: unknown) {
      if (extra === undefined) console.warn(`${tag} ⚠ ${message}`);
      else console.warn(`${tag} ⚠ ${message}`, extra);
    },
    error(message: string, extra?: unknown) {
      if (extra === undefined) console.error(`${tag} ✖ ${message}`);
      else console.error(`${tag} ✖ ${message}`, extra);
    },
  };
}

export type Logger = ReturnType<typeof createLogger>;
