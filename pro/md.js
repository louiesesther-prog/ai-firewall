// Minimal but robust Markdown -> HTML renderer for the Pro docs reader.
// Handles: headings, code fences, inline code, bold, italic, links, lists,
// tables, blockquotes, horizontal rules, paragraphs.
function renderMarkdown(src) {
  if (typeof src !== 'string') return '<p>No content.</p>';

  // Normalize line endings.
  var text = src.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  // Extract fenced code blocks first so their contents aren't mangled below.
  var blocks = [];
  text = text.replace(/```([\s\S]*?)```/g, function (m, code) {
    var id = 'CB' + blocks.length + 'Z';
    blocks.push('<pre><code>' + escapeHtml(code.replace(/^\n/, '').replace(/\n$/, '')) + '</code></pre>');
    return '\n@@' + id + '@@\n';
  });

  var lines = text.split('\n');
  var html = '';
  var inList = null;
  var inTable = false;
  var tableRows = [];

  function closeList() {
    if (inList === 'ul') html += '</ul>\n';
    else if (inList === 'ol') html += '</ol>\n';
    inList = null;
  }
  function openList(type) {
    if (inList !== type) {
      closeList();
      html += (type === 'ul') ? '<ul>\n' : '<ol>\n';
      inList = type;
    }
  }
  function closeTable() {
    if (!inTable) return;
    inTable = false;
    if (tableRows.length) {
      html += '<table>\n';
      // First row = header
      var header = tableRows.shift();
      html += '<thead><tr>';
      header.forEach(function (c) { html += '<th>' + inline(c) + '</th>'; });
      html += '</tr></thead>\n';
      html += '<tbody>\n';
      tableRows.forEach(function (row) {
        html += '<tr>';
        row.forEach(function (c) { html += '<td>' + inline(c) + '</td>'; });
        html += '</tr>\n';
      });
      html += '</tbody>\n</table>\n';
    }
    tableRows = [];
  }
  function flushTableIfNeeded() {
    if (inTable) closeTable();
  }

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    var trimmed = line.trim();

    // Placeholder for code block.
    var cb = trimmed.match(/^@@(CB\d+Z)@@$/);
    if (cb) {
      closeList(); flushTableIfNeeded();
      html += blocks[parseInt(cb[1].slice(2), 10)] + '\n';
      continue;
    }

    if (trimmed === '') {
      closeList(); flushTableIfNeeded();
      html += '\n';
      continue;
    }

    // Horizontal rule
    if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) {
      closeList(); flushTableIfNeeded();
      html += '<hr>\n';
      continue;
    }

    // Headings
    var h = trimmed.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      closeList(); flushTableIfNeeded();
      var lvl = h[1].length;
      html += '<h' + lvl + '>' + inline(h[2]) + '</h' + lvl + '>\n';
      continue;
    }

    // Blockquote
    if (/^>\s?/.test(trimmed)) {
      closeList(); flushTableIfNeeded();
      html += '<blockquote>' + inline(trimmed.replace(/^>\s?/, '')) + '</blockquote>\n';
      continue;
    }

    // Tables
    if (/^\|/.test(trimmed)) {
      if (!inTable) { closeList(); inTable = true; tableRows = []; }
      var cells = trimmed.replace(/^\|/, '').replace(/\|$/, '').split('|');
      var cleaned = [];
      for (var ci = 0; ci < cells.length; ci++) {
        var ccell = cells[ci].trim();
        // separator row like |---|:---| skip it
        if (/^:?-{3,}:?$/.test(ccell)) continue;
        cleaned.push(ccell);
      }
      if (cleaned.length) tableRows.push(cleaned);
      continue;
    }

    // Lists
    var ul = trimmed.match(/^[-*+]\s+(.*)$/);
    if (ul) {
      openList('ul');
      html += '<li>' + inline(ul[1]) + '</li>\n';
      continue;
    }
    var ol = trimmed.match(/^\d+[.)]\s+(.*)$/);
    if (ol) {
      openList('ol');
      html += '<li>' + inline(ol[1]) + '</li>\n';
      continue;
    }

    // Regular paragraph
    closeList(); flushTableIfNeeded();
    html += '<p>' + inline(trimmed) + '</p>\n';
  }

  closeList(); flushTableIfNeeded();

  // Re-insert code blocks.
  html = html.replace(/@@(CB\d+Z)@@/g, function (m, id) {
    return blocks[parseInt(id.slice(2), 10)];
  });

  return html;
}

function inline(s) {
  return escapeHtml(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
}

function escapeHtml(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
