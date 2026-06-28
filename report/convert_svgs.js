const fs = require('fs');
const path = require('path');
const sharp = require('sharp');

const SRC = path.join(__dirname, 'diagrams');
const OUT = path.join(__dirname, 'diagrams_png');
fs.mkdirSync(OUT, { recursive: true });

const files = fs.readdirSync(SRC).filter(f => f.endsWith('.svg'));
const SCALE = 2;

(async () => {
  for (const f of files) {
    let svg = fs.readFileSync(path.join(SRC, f), 'utf8');
    const m = svg.match(/viewBox="0 0 (\d+(?:\.\d+)?) (\d+(?:\.\d+)?)"/);
    const w = Math.round(parseFloat(m[1]) * SCALE);
    const h = Math.round(parseFloat(m[2]) * SCALE);
    // Give the SVG explicit pixel dimensions and a white background.
    svg = svg.replace('width="100%"', `width="${w}" height="${h}"`);
    const out = path.join(OUT, f.replace('.svg', '.png'));
    await sharp(Buffer.from(svg))
      .flatten({ background: '#ffffff' })
      .png()
      .toFile(out);
    const meta = await sharp(out).metadata();
    console.log(`${f} -> ${path.basename(out)}  ${meta.width}x${meta.height}`);
  }
})();
