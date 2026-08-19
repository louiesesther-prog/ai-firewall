const fs = require('fs');
const zlib = require('zlib');

function readUInt32LE(buf, offset) {
  return buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16) | (buf[offset + 3] << 24);
}

function readUInt16LE(buf, offset) {
  return buf[offset] | (buf[offset + 1] << 8);
}

function findLocalFileHeader(buf, offset) {
  const sig = readUInt32LE(buf, offset);
  if (sig !== 0x04034b50) return null;
  const compMethod = readUInt16LE(buf, offset + 8);
  const compSize = readUInt32LE(buf, offset + 18);
  const uncompSize = readUInt32LE(buf, offset + 22);
  const nameLen = readUInt16LE(buf, offset + 26);
  const extraLen = readUInt16LE(buf, offset + 28);
  const name = buf.toString('utf8', offset + 30, offset + 30 + nameLen);
  const dataStart = offset + 30 + nameLen + extraLen;
  return { name, compMethod, compSize, uncompSize, dataStart };
}

function extractDocumentXml(buf) {
  let offset = 0;
  while (offset + 30 <= buf.length) {
    const header = findLocalFileHeader(buf, offset);
    if (!header) break;

    if (header.name === 'word/document.xml' || header.name.endsWith('/document.xml')) {
      const data = buf.slice(header.dataStart, header.dataStart + header.compSize);
      let xml;
      if (header.compMethod === 0) {
        xml = data.toString('utf8');
      } else if (header.compMethod === 8) {
        try {
          xml = zlib.inflateRawSync(data).toString('utf8');
        } catch (e) {
          return null;
        }
      } else {
        return null;
      }
      return xml;
    }

    offset = header.dataStart + header.compSize;
  }
  return null;
}

function xmlToText(xml) {
  let text = '';
  let i = 0;
  while (i < xml.length) {
    if (xml[i] === '<') {
      const close = xml.indexOf('>', i);
      if (close === -1) break;
      const tag = xml.substring(i + 1, close);
      if (tag === 'w:br' || tag === 'w:tab' || tag === 'w:cr') {
        text += tag === 'w:tab' ? '\t' : '\n';
      }
      i = close + 1;
    } else {
      const nextTag = xml.indexOf('<', i);
      const end = nextTag === -1 ? xml.length : nextTag;
      text += xml.substring(i, end);
      i = end;
    }
  }
  return text.replace(/\s+/g, ' ').replace(/ \n/g, '\n').replace(/\n /g, '\n').trim();
}

function extract(filePath) {
  const buf = fs.readFileSync(filePath);
  const zipSig = readUInt32LE(buf, 0);
  if (zipSig !== 0x04034b50) {
    throw new Error('Invalid DOCX file (not a valid ZIP archive)');
  }

  const xml = extractDocumentXml(buf);
  if (!xml) {
    throw new Error('Could not find word/document.xml in DOCX file');
  }

  return xmlToText(xml);
}

module.exports = { extract };
