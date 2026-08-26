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
  let buf;
  try {
    buf = fs.readFileSync(filePath);
  } catch (e) {
    throw new Error('Cannot read file: ' + filePath + ' (' + e.message + ')');
  }
  const data = await parse(buf);
  return data.text || '';
}

module.exports = { extract };
