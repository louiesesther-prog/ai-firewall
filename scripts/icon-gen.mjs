#!/usr/bin/env node
// Generates PNG icons from the AI Firewall SVG shield shape (pure Node, no deps).
// Uses zlib + manual PNG encoding + 4x supersampling for smooth edges.

import fs from 'fs';
import path from 'path';
import zlib from 'zlib';

const SHIELD_BG = [0x66, 0x7e, 0xea]; // #667eea
const SHIELD_FG = [0xff, 0xff, 0xff]; // white

function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c;
    }
  }
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = table[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const typeBuf = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])));
  return Buffer.concat([len, typeBuf, data, crc]);
}

function encodePNG(width, height, rgba) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0;
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([
    sig,
    chunk('IHDR', ihdr),
    chunk('IDAT', idat),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// ---- shape functions (normalized 0..1 coordinates, matching the SVG) ----
// Background: rounded rect rx=2/16 (12.5% of size)
function inRoundedRect(x, y, w, h, r) {
  if (x < r && y < r) return (x - r) ** 2 + (y - r) ** 2 <= r * r;
  if (x > w - r && y < r) return (x - (w - r)) ** 2 + (y - r) ** 2 <= r * r;
  if (x < r && y > h - r) return (x - r) ** 2 + (y - (h - r)) ** 2 <= r * r;
  if (x > w - r && y > h - r) return (x - (w - r)) ** 2 + (y - (h - r)) ** 2 <= r * r;
  return x >= 0 && x <= w && y >= 0 && y <= h;
}

// Diamond: M8 3 L12 7 L8 11 L4 7 Z  (in 16x16 viewBox -> center 8,7, half 4)
function inDiamond(x, y) {
  const cx = 8, cy = 7, hw = 4;
  return Math.abs(x - cx) / hw + Math.abs(y - cy) / hw <= 1;
}

// Rect: x=6 y=7 w=4 h=5  (16 viewBox)
function inRect(x, y) {
  return x >= 6 && x <= 10 && y >= 7 && y <= 12;
}

function colorAt(x, y, size) {
  // map 0..size -> 0..16 viewBox
  const vx = (x / size) * 16;
  const vy = (y / size) * 16;
  const r = (2 / 16) * 16; // rx proportion stays 2 units in 16-space regardless
  let c = [255, 255, 255, 0]; // transparent outside

  if (inRoundedRect(vx, vy, 16, 16, 2)) {
    c = [...SHIELD_BG, 255];
    // mask: white diamond + white block drawn on top
    if (inDiamond(vx, vy) || inRect(vx, vy)) {
      c = [...SHIELD_FG, Math.round(0.9 * 255)];
    }
  }
  return c;
}

function render(size) {
  const ss = 4; // supersample factor
  const big = size * ss;
  const rgba = Buffer.alloc(size * size * 4);
  const acc = new Float64Array(size * size * 4);
  for (let sy = 0; sy < big; sy++) {
    for (let sx = 0; sx < big; sx++) {
      const px = (sx + 0.5) / ss;
      const py = (sy + 0.5) / ss;
      const c = colorAt(px, py, size);
      const bx = Math.floor(sx / ss);
      const by = Math.floor(sy / ss);
      const idx = (by * size + bx) * 4;
      acc[idx] += c[0];
      acc[idx + 1] += c[1];
      acc[idx + 2] += c[2];
      acc[idx + 3] += c[3];
    }
  }
  for (let i = 0; i < size * size; i++) {
    rgba[i * 4] = Math.round(acc[i * 4] / (ss * ss));
    rgba[i * 4 + 1] = Math.round(acc[i * 4 + 1] / (ss * ss));
    rgba[i * 4 + 2] = Math.round(acc[i * 4 + 2] / (ss * ss));
    rgba[i * 4 + 3] = Math.round(acc[i * 4 + 3] / (ss * ss));
  }
  return encodePNG(size, size, rgba);
}

const targets = process.argv.slice(2);
const sizes = [16, 32, 48, 96, 128];
for (const target of targets) {
  for (const s of sizes) {
    const outPath = path.join(target, `icon${s}.png`);
    const png = render(s);
    fs.writeFileSync(outPath, png);
    console.log(`Wrote ${outPath} (${png.length} bytes)`);
  }
}