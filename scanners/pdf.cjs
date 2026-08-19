const fs = require('fs');

let pdfParse = null;

function ensurePdfParse() {
  if (pdfParse) return pdfParse;
  try {
    pdfParse = require('pdf-parse');
    return pdfParse;
  } catch (e) {
    throw new Error(
      'PDF support requires pdf-parse: npm install pdf-parse\n' +
      'Error: ' + e.message
    );
  }
}

async function extract(filePath) {
  const parse = ensurePdfParse();
  const buf = fs.readFileSync(filePath);
  const data = await parse(buf);
  return data.text || '';
}

module.exports = { extract };
