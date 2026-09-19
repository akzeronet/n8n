const argv1 = process.argv[1] || '';
const commandName = process.argv[2] ?? 'start';

const isN8nCli = /\/bin\/n8n$/.test(argv1);
const isMainStart = isN8nCli && commandName === 'start';

if (isMainStart) {
  await import('./preload.mjs');
}
