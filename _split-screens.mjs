import { readFileSync, writeFileSync, mkdirSync } from 'fs';
const src = readFileSync('store-screenshots.html', 'utf8');
const head = src.slice(0, src.indexOf('<body>') + 6);
const body = src.slice(src.indexOf('<body>') + 6, src.indexOf('</body>'));
const pages = body.split('</div>').filter((s, i, a) => i % 2 === 0 && s.includes('class="page'));
const re = /<div class="page[^"]*"[^>]*>([\s\S]*?)<div class="pg-label">([\s\S]*?)<\/div>\s*<\/div>/g;
let m, i = 0;
const names = ['dashboard', 'detection', 'stats'];
mkdirSync('store-assets', { recursive: true });
while ((m = re.exec(body)) !== null) {
  i++;
  const inner = m[1];
  const label = m[2].trim();
  const html = `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=1280">
<title>AI Personal Firewall — Screenshot ${i}</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { width:1280px; height:800px; overflow:hidden; background:#0f0f1a; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif; }
${extractCss(src)}
</style>
</head><body>
<div class="page" style="width:1280px;height:800px;position:relative;overflow:hidden">
${inner}
<div style="position:absolute;bottom:8px;right:12px;color:#555;font-size:11px;z-index:10">${label}</div>
</div>
</body></html>`;
  writeFileSync(`store-assets/screenshot-${names[i - 1]}.html`, html);
  console.log('Wrote store-assets/screenshot-' + names[i - 1] + '.html (' + i + ')');
}
console.log('Total pages extracted:', i);

function extractCss(html) {
  const m2 = html.match(/<style>([\s\S]*?)<\/style>/);
  return m2 ? m2[1] : '';
}