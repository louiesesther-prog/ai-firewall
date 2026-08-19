const fs = require('fs');

let Tesseract = null;

function ensureTesseract() {
  if (Tesseract) return Tesseract;
  try {
    Tesseract = require('tesseract.js');
    return Tesseract;
  } catch (e) {
    throw new Error(
      'Image OCR requires tesseract.js: npm install tesseract.js\n' +
      'Error: ' + e.message
    );
  }
}

async function extract(filePath) {
  const tess = ensureTesseract();
  const buf = fs.readFileSync(filePath);
  const { data } = await tess.recognize(buf, 'eng', {});
  return data.text || '';
}

module.exports = { extract };
