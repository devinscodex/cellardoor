// Render docs/diagrams/*.mmd to SVG with Pele (dev tool, not a runtime dependency).
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { render } from 'pele';

const dir = new URL('../docs/diagrams/', import.meta.url);
for (const f of readdirSync(dir).filter((n) => n.endsWith('.mmd'))) {
  const { svg } = render(readFileSync(new URL(f, dir), 'utf8'));
  writeFileSync(new URL(f.replace(/\.mmd$/, '.svg'), dir), svg);
  console.log('rendered', f);
}
