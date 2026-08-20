'use strict';

// ── CONTEXT-AWARE PII DETECTION ENGINE ────────────────────────────
// Analyzes surrounding text to boost/reduce confidence and catch
// PII that regex alone misses.

// PII-indicative keywords that boost confidence when found nearby
const PII_KEYWORDS = {
  EMAIL_ADDR: {
    boost: /\b(email|e-mail|mailto|send\s+to|contact|inbox|from|reply|write)\b/i,
    boostAmount: 0.15,
  },
  PHONE_NUM: {
    boost: /\b(call|phone|tel|dial|ring|reach|contact|mobile|cell|fax|number)\b/i,
    boostAmount: 0.15,
  },
  SSN_NUM: {
    boost: /\b(ssn|social\s+security|tax\s+id|employee|worker|citizen|national)\b/i,
    boostAmount: 0.2,
  },
  CC_NUM: {
    boost: /\b(card|credit|visa|mastercard|amex|payment|charge|billing|checkout|cvv|exp)\b/i,
    boostAmount: 0.15,
  },
  PASSPORT: {
    boost: /\b(passport|travel|visa|immigration|boarding|flight|identity|id\s*doc)\b/i,
    boostAmount: 0.2,
  },
  DE_ID: {
    boost: /\b(personalausweis|ausweis|id[- ]?karte|deutsch|german)\b/i,
    boostAmount: 0.15,
  },
  LICENSE: {
    boost: /\b(driver|driving|license|dl|permit|vehicle|car|automobile)\b/i,
    boostAmount: 0.15,
  },
  ADDRESS: {
    boost: /\b(address|street|avenue|road|boulevard|drive|lane|apt|suite|building|location|mailing|residence)\b/i,
    boostAmount: 0.15,
  },
  BANK_ACCT: {
    boost: /\b(account|bank|wire|transfer|routing|swift|iban|balance|checking|savings)\b/i,
    boostAmount: 0.15,
  },
  DOB: {
    boost: /\b(birth|born|age|dob|date\s+of|birthday)\b/i,
    boostAmount: 0.2,
  },
  APIKEY: {
    boost: /\b(api[_-]?key|secret[_-]?key|access[_-]?key|token|credential|auth)\b/i,
    boostAmount: 0.15,
  },
  PWD_VAL: {
    boost: /\b(password|passwd|passphrase|secret|credential|login|auth)\b/i,
    boostAmount: 0.15,
  },
  CRYPTO: {
    boost: /\b(wallet|ethereum|eth|crypto|blockchain|defi|contract\s+address)\b/i,
    boostAmount: 0.15,
  },
  MAC_ADDR: {
    boost: /\b(mac|physical|hardware|ethernet|network|interface|ieee)\b/i,
    boostAmount: 0.1,
  },
  IP_ADDR: {
    boost: /\b(server|host|ip|dns|proxy|remote|source|destination|addr|endpoint)\b/i,
    boostAmount: 0.1,
  },
  ROUTING: {
    boost: /\b(routing|aba|wire|transfer|bank|swift|bic)\b/i,
    boostAmount: 0.15,
  },
  UK_NI: {
    boost: /\b(national\s+insurance|ni\s+number|ni\s+no|hmrc|paye)\b/i,
    boostAmount: 0.2,
  },
  UK_NHS: {
    boost: /\b(nhs|patient|medical|health|hospital|gp|doctor|clinic)\b/i,
    boostAmount: 0.2,
  },
  IN_AADHAAR: {
    boost: /\b(aadhaar|aadhar|uidai|unique\s+id|aadhaar\s+number)\b/i,
    boostAmount: 0.2,
  },
  IN_PAN: {
    boost: /\b(pan|permanent\s+account|income\s+tax|it\s+return|pan\s+card)\b/i,
    boostAmount: 0.2,
  },
  CN_ID: {
    boost: /\b(\u8eab\u4efd\u8bc1|id\s+card|citizen|residence|\u5c45\u6c11\u8eab\u4efd\u8bc1)\b/i,
    boostAmount: 0.15,
  },
  CA_SIN: {
    boost: /\b(sin|social\s+insurance|canada|revenue|cra)\b/i,
    boostAmount: 0.2,
  },
  AU_TFN: {
    boost: /\b(tfn|tax\s+file|ato|australian|taxation)\b/i,
    boostAmount: 0.2,
  },
  JP_MY: {
    boost: /\b(my\s+number|\u30de\u30a4\u30ca\u30f3\u30d0\u30fc|tokyo|japan|\u756a\u53f7)\b/i,
    boostAmount: 0.15,
  },
  BR_CPF: {
    boost: /\b(cpf|cadastro|pessoa|f\u00edsica|brazil|receita)\b/i,
    boostAmount: 0.15,
  },
  BR_CNPJ: {
    boost: /\b(cnpj|empresa|cnpj\s+number|brazil|receita|federative)\b/i,
    boostAmount: 0.15,
  },
  FR_INSEE: {
    boost: /\b(insee|nir|num\u00e9ro\s+de\s+s\u00e9curit\u00e9|s\u00e9cu|france)\b/i,
    boostAmount: 0.15,
  },
  DE_TAX: {
    boost: /\b(steuernummer|steuer|tax\s+id|finanzamt|german\s+tax)\b/i,
    boostAmount: 0.15,
  },
  KR_RRN: {
    boost: /\b(\uc8fc\ubcfc\ubc88\ud638|\ub300\ud55c\ubbfc\uad6d|\uc8fc\ubcfc|\uc6d0\uad70|resident\s+registration)\b/i,
    boostAmount: 0.15,
  },
  MX_CURP: {
    boost: /\b(curp|ine|\u00eddenticula|mexico|clave)\b/i,
    boostAmount: 0.15,
  },
  MX_RFC: {
    boost: /\b(rfc|registro|federal|contribuyentes|mexico|taxpayer)\b/i,
    boostAmount: 0.15,
  },
  SE_PN: {
    boost: /\b(personnummer|person\s+number|swedish|sweden|personskod)\b/i,
    boostAmount: 0.15,
  },
  IT_CF: {
    boost: /\b(codice\s+fiscale|fiscale|italian|italy|partita\s+iva)\b/i,
    boostAmount: 0.15,
  },
  JWT: {
    boost: /\b(bearer|authorization|jwt|json\s+web\s+token|auth)\b/i,
    boostAmount: 0.1,
  },
  AWS_KEY: {
    boost: /\b(aws|amazon|access\s+key|iam|s3|ec2)\b/i,
    boostAmount: 0.1,
  },
  GITHUB: {
    boost: /\b(github|pat|personal\s+access\s+token|ghp_|gho_)\b/i,
    boostAmount: 0.1,
  },
  SLACK: {
    boost: /\b(slack|bot\s+token|xoxb|xoxp|workspace)\b/i,
    boostAmount: 0.1,
  },
  PERSON_NAME: {
    boost: /\b(name|patient|client|customer|applicant|person|contact|user)\b/i,
    boostAmount: 0.15,
  },
};

// Code/technical context reduces confidence
const CODE_CONTEXT_REDUCE = {
  patterns: [
    /\b(example|sample|test|demo|mock|fake|dummy|placeholder|template|TODO|FIXME|HACK)\b/i,
    /\b(regex|pattern|match|capture|group)\b/i,
    /\b(const|let|var|function|class|import|export|require|module)\b/i,
    /\b(select|from|where|insert|update|delete|create\s+table)\b/i,
    /['"`].*\b(test|example|demo|sample|foo|bar|baz)\b.*['"`]/i,
  ],
  reduceAmount: 0.3,
};

// Structured data detection (JSON, CSV, XML)
const STRUCTURED_DATA = {
  json: /\{[^}]*"(?:email|phone|ssn|card|address|password|name|user)"[^}]*\}/i,
  csv: /(?:^|,)[^,]*(?:email|phone|ssn|card|address|password|name|user)[^,]*(?:,|$)/i,
  xml: /<(?:user|person|customer|account|contact)[^>]*>/i,
};

// Document-level analysis: detects if text is likely a data dump vs natural language
function analyzeDocument(text) {
  const stats = {
    totalLength: text.length,
    digitRatio: (text.match(/\d/g) || []).length / (text.length || 1),
    alphaRatio: (text.match(/[a-zA-Z]/g) || []).length / (text.length || 1),
    newlineRatio: (text.match(/\n/g) || []).length / (text.length || 1),
    hasJSON: STRUCTURED_DATA.json.test(text),
    hasCSV: STRUCTURED_DATA.csv.test(text),
    hasXML: STRUCTURED_DATA.xml.test(text),
    isStructured: false,
    isCode: false,
    isNaturalLanguage: false,
  };

  stats.isStructured = stats.hasJSON || stats.hasCSV || stats.hasXML;
  stats.isCode = CODE_CONTEXT_REDUCE.patterns.some(p => p.test(text)) ||
    (stats.digitRatio > 0.15 && stats.alphaRatio < 0.3);
  stats.isNaturalLanguage = stats.alphaRatio > 0.6 && stats.newlineRatio > 0.02;

  return stats;
}

// Analyze local context around a match
function analyzeContext(rule, raw, idx, text) {
  const result = { boost: 0, reduce: 0, isPersonalContext: false, isCodeContext: false, isStructuredContext: false };

  const before = text.substring(Math.max(0, idx - 80), idx);
  const after = text.substring(idx + raw.length, Math.min(text.length, idx + raw.length + 80));
  const ctx = before + ' ' + after;

  // Check for PII-indicative keywords
  const keywordInfo = PII_KEYWORDS[rule.label];
  if (keywordInfo && keywordInfo.boost.test(ctx)) {
    result.boost = keywordInfo.boostAmount;
    result.isPersonalContext = true;
  }

  // Check for code/technical context
  for (const pattern of CODE_CONTEXT_REDUCE.patterns) {
    if (pattern.test(ctx)) {
      result.reduce = CODE_CONTEXT_REDUCE.reduceAmount;
      result.isCodeContext = true;
      break;
    }
  }

  // Check for structured data context
  if (STRUCTURED_DATA.json.test(before.slice(-100)) || STRUCTURED_DATA.json.test(after.slice(0, 100))) {
    result.boost = Math.max(result.boost, 0.1);
    result.isStructuredContext = true;
  }

  return result;
}

// Proximity scoring: nearby PII matches boost each other
function proximityBoost(matches, currentIdx, windowSize = 100) {
  let boost = 0;
  for (const m of matches) {
    if (m._index === currentIdx) continue;
    const dist = Math.abs(m._index - currentIdx);
    if (dist < windowSize) {
      boost += 0.05 * (1 - dist / windowSize);
    }
  }
  return Math.min(boost, 0.15);
}

// Main context-aware scoring function
function contextScore(rule, raw, idx, text, baseConf, documentStats, existingMatches) {
  let conf = baseConf;

  // 1. Local context analysis
  const ctx = analyzeContext(rule, raw, idx, text);
  conf += ctx.boost;
  conf -= ctx.reduce;

  // 2. Proximity boost from nearby PII
  if (existingMatches && existingMatches.length > 0) {
    conf += proximityBoost(existingMatches, idx);
  }

  // 3. Document-level adjustments
  if (documentStats) {
    // In structured data, boost all matches slightly
    if (documentStats.isStructured) {
      conf += 0.05;
    }

    // In code-heavy text, reduce confidence for generic patterns
    if (documentStats.isCode && !ctx.isPersonalContext) {
      conf -= 0.1;
    }
  }

  return Math.max(0, Math.min(1, conf));
}

// Enhanced PII detection: catch PII that regex misses using context clues
function detectMissingPII(text, documentStats) {
  const extraMatches = [];

  if (!documentStats) return extraMatches;

  // Detect name patterns: "My name is John Smith" / "I am John Smith"
  const namePatterns = [
    /\b(?:my\s+name\s+is|i\s+am|this\s+is|i'?m)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b/gi,
    /\b(?:name|patient|client|customer|applicant)[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b/gi,
  ];

  for (const re of namePatterns) {
    let m;
    while ((m = re.exec(text)) !== null) {
      const name = m[1];
      const words = name.split(/\s+/);
      if (words.length >= 2 && words.length <= 4) {
        extraMatches.push({
          type: 'PERSON_NAME',
          name: 'Person Name',
          match: name,
          confidence: 0.6,
          line: (text.substring(0, m.index).match(/\n/g) || []).length + 1,
          column: m.index - text.lastIndexOf('\n', m.index - 1),
          _contextDetected: true,
          _index: m.index,
        });
      }
    }
  }

  return extraMatches;
}

module.exports = {
  analyzeDocument,
  analyzeContext,
  proximityBoost,
  contextScore,
  detectMissingPII,
  PII_KEYWORDS,
};
