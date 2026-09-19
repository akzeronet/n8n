const argv1 = process.argv[1] || '';
const args = process.argv.slice(2);

const isN8nCli = /\/bin\/n8n$/.test(argv1);
const nonMainCommands = new Set(['worker', 'webhook']);
const isMainProcess = isN8nCli && !args.some((arg) => nonMainCommands.has(arg));

if (isMainProcess) {
  await import('./preload.mjs');
}
