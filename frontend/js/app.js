document.addEventListener('DOMContentLoaded', () => {
  const codeInput = document.getElementById('code-input');
  const snippetSelect = document.getElementById('snippet-select');
  const analyzeBtn = document.getElementById('analyze-btn');
  const sarifBtn = document.getElementById('sarif-btn');

  const metricStatus = document.getElementById('metric-status');
  const metricRisk = document.getElementById('metric-risk');
  const metricComplexity = document.getElementById('metric-complexity');
  const metricViolations = document.getElementById('metric-violations');
  const violationsCountBadge = document.getElementById('violations-count-badge');
  const violationsList = document.getElementById('violations-list');
  const astTreeView = document.getElementById('ast-tree-view');

  let snippetsMap = {};

  // Fetch pre-loaded snippets
  async function loadSnippets() {
    try {
      const res = await fetch('/api/snippets');
      const data = await res.json();
      snippetsMap = data.snippets || {};

      for (const [id, item] of Object.entries(snippetsMap)) {
        const opt = document.createElement('option');
        opt.value = id;
        opt.textContent = `${item.title} (${item.category})`;
        snippetSelect.appendChild(opt);
      }

      // Pre-select first snippet
      if (snippetsMap['vulnerable_agent']) {
        snippetSelect.value = 'vulnerable_agent';
        codeInput.value = snippetsMap['vulnerable_agent'].code;
        runAnalysis();
      }
    } catch (err) {
      console.error('Failed to load snippets:', err);
    }
  }

  snippetSelect.addEventListener('change', () => {
    const val = snippetSelect.value;
    if (snippetsMap[val]) {
      codeInput.value = snippetsMap[val].code;
      runAnalysis();
    }
  });

  async function runAnalysis() {
    const source = codeInput.value;
    if (!source.trim()) return;

    analyzeBtn.disabled = true;
    analyzeBtn.textContent = 'Analyzing...';

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, filename: 'source_analysis.py' })
      });

      const data = await res.json();
      renderResults(data);
    } catch (err) {
      console.error('Analysis failed:', err);
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.innerHTML = `
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"></circle>
          <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
        </svg>
        Run AST Scan
      `;
    }
  }

  function renderResults(data) {
    if (data.status !== 'success') {
      alert(data.message || 'Error running analysis');
      return;
    }

    const m = data.metrics;
    metricRisk.textContent = `${m.risk_score} / 100`;
    metricComplexity.textContent = m.cyclomatic_complexity;
    metricViolations.textContent = data.violations_count;
    violationsCountBadge.textContent = `${data.violations_count} Issues`;

    // Status pill
    metricStatus.textContent = m.security_status;
    metricStatus.className = 'metric-val';
    if (m.risk_score >= 50) {
      metricStatus.classList.add('status-danger');
    } else if (m.risk_score > 0) {
      metricStatus.classList.add('status-warn');
    } else {
      metricStatus.classList.add('status-clean');
    }

    // Render Violations
    violationsList.innerHTML = '';
    if (data.violations.length === 0) {
      violationsList.innerHTML = '<div class="empty-state">✅ Clean AST! No security or quality violations found.</div>';
    } else {
      data.violations.forEach(v => {
        const card = document.createElement('div');
        card.className = `violation-card ${v.severity}`;
        card.innerHTML = `
          <div class="violation-head">
            <span class="violation-rule">${v.rule}</span>
            <span class="severity-pill ${v.severity}">${v.severity}</span>
          </div>
          <div class="violation-msg">${v.message}</div>
          <div class="violation-meta">Line ${v.line}, Col ${v.col} • ${v.cwe}</div>
          ${v.remediation ? `<div class="remediation-box"><strong>Remediation:</strong> ${v.remediation}</div>` : ''}
        `;
        violationsList.appendChild(card);
      });
    }

    // Render AST Tree Summary
    astTreeView.innerHTML = `<pre>${JSON.stringify(data.ast_tree || {}, null, 2)}</pre>`;
  }

  analyzeBtn.addEventListener('click', runAnalysis);

  // SARIF Export
  sarifBtn.addEventListener('click', async () => {
    const source = codeInput.value;
    try {
      const res = await fetch('/api/sarif', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, filename: 'source_analysis.py' })
      });
      const sarifData = await res.json();
      const blob = new Blob([JSON.stringify(sarifData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'ast_security_report.sarif.json';
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export SARIF:', err);
    }
  });

  loadSnippets();
});
