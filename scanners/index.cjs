const path = require('path');

const DOC_EXTS = ['.pdf', '.docx', '.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.gif', '.webp'];

function isDocument(filePath) {
  return DOC_EXTS.includes(path.extname(filePath).toLowerCase());
}

async function extractText(filePath, options = {}) {
  const ext = path.extname(filePath).toLowerCase();

  if (ext === '.docx') {
    const docx = require('./docx');
    return docx.extract(filePath);
  }

  if (ext === '.pdf') {
    const pdf = require('./pdf');
    return pdf.extract(filePath);
  }

  if (['.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.gif', '.webp'].includes(ext)) {
    if (!options.ocr) {
      throw new Error('Image OCR requires --ocr flag (installs tesseract.js)');
    }
    const ocr = require('./ocr');
    return ocr.extract(filePath);
  }

  return null;
}

module.exports = { extractText, isDocument, DOC_EXTS };
