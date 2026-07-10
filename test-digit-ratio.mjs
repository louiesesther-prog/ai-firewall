function analyze(input) {
  const m = input.match(/\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/);
  if (!m) { console.log('NO MATCH:', input); return; }
  const idx = m.index, raw = m[0];
  const before = input.substring(Math.max(0, idx - 25), idx);
  const after = input.substring(idx + raw.length, Math.min(input.length, idx + raw.length + 25));
  const ctx = before + ' ' + after;
  const letters = (ctx.match(/[a-zA-Z]/g) || []).length;
  const nums = (ctx.match(/\d/g) || []).length;
  const total = ctx.replace(/\s/g, '').length || 1;
  const dr = nums / total;
  const isFp = dr > 0.7 && letters < 3;
  console.log((isFp ? 'FP' : 'OK') + ' dr=' + dr.toFixed(3) + ' letters=' + letters + ' | ' + input.substring(0, 50));
}

['CALL ME AT 555-123-4567',
 'my phone is 555-123-4567',
 'cell: 555-123-4567',
 'tel: 555-123-4567',
 'Phone: 555-123-4567',
 'Dial 555-123-4567 now',
 '12345 67890 1112131415',
 'Order: 1234567890',
 'Item: 1234567890',
 'Reach me at 555-123-4567',
 'Ring 555-123-4567 for',
 'Contact 555-123-4567',
 'You can call 555-123-4567',
].forEach(analyze);
