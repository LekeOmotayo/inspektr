document.addEventListener('DOMContentLoaded', () => {
  const codeInput = document.getElementById('code-input');
  const snippetSelect = document.getElementById('snippet-select');
  const analyzeBtn = document.getElementById('analyze-btn');
  const sarifBtn = document.getElementById('sarif-btn');
  const clearBtn = document.getElementById('clear-btn');
  const editorDirty = document.getElementById('editor-dirty');
  const scanTimestamp = document.getElementById('scan-timestamp');
  const alertBanner = document.getElementById('alert-banner');

  const metricStatus = document.getElementById('metric-status');
  const metricRisk = document.getElementById('metric-risk');
  const metricComplexity = document.getElementById('metric-complexity');
  const metricViolations = document.getElementById('metric-violations');
  const violationsCountBadge = document.getElementById('violations-count-badge');
  const violationsList = document.getElementById('violations-list');
  const astTreeView = document.getElementById('ast-tree-view');
  const metricsRow = document.querySelector('.metrics-row');

  let snippetsMap = {};

  function showAlert(msg) {
    if (alertBanner) {
      alertBanner.textContent = `⚠️ ${msg}`;
      alertBanner.style.display = 'block';
    }
  }

  function hideAlert() {
    if (alertBanner) {
      alertBanner.style.display = 'none';
      alertBanner.textContent = '';
    }
  }

  function markEditorClean() {
    if (editorDirty) editorDirty.style.display = 'none';
  }

  function markEditorDirty() {
    if (editorDirty) editorDirty.style.display = 'inline';
    if (scanTimestamp) {
      scanTimestamp.classList.add('stale');
      scanTimestamp.textContent = '● Unsaved changes - click "Run AST Scan"';
    }
  }

  codeInput.addEventListener('input', () => {
    markEditorDirty();
  });

  // Clear button
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      codeInput.value = '';
      snippetSelect.value = '';
      markEditorClean();
      resetUI();
    });
  }

  function resetUI() {
    hideAlert();
    metricStatus.textContent = 'READY';
    metricStatus.className = 'metric-val status-clean';
    metricRisk.textContent = '0 / 100';
    metricComplexity.textContent = '1';
    metricViolations.textContent = '0';
    violationsCountBadge.textContent = '0 Issues';
    violationsList.innerHTML = '<div class="empty-state">Editor empty. Paste Python code or select a sample snippet, then click "Run AST Scan".</div>';
    astTreeView.innerHTML = '<div class="empty-state">No AST generated.</div>';
    if (scanTimestamp) {
      scanTimestamp.className = 'scan-timestamp';
      scanTimestamp.textContent = '● Ready';
    }
  }

  // Fetch pre-loaded snippets
  async function loadSnippets() {
    try {
      const res = await fetch('/api/snippets');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      snippetsMap = data.snippets || {};

      for (const [id, item] of Object.entries(snippetsMap)) {
        const opt = document.createElement('option');
        opt.value = id;
        opt.textContent = `${item.title} (${item.category})`;
        snippetSelect.appendChild(opt);
      }

      // Pre-select first sample vulnerability for demo
      if (snippetsMap['vulnerable_agent']) {
        snippetSelect.value = 'vulnerable_agent';
        codeInput.value = snippetsMap['vulnerable_agent'].code;
        runAnalysis();
      }
    } catch (err) {
      console.error('Failed to load snippets:', err);
      showAlert(`Could not connect to backend snippets API: ${err.message}`);
    }
  }

  snippetSelect.addEventListener('change', () => {
    const val = snippetSelect.value;
    if (val && snippetsMap[val]) {
      codeInput.value = snippetsMap[val].code;
      markEditorClean();
      runAnalysis();
    } else if (!val) {
      codeInput.value = '';
      resetUI();
    }
  });

  async function runAnalysis() {
    const source = codeInput.value;
    if (!source.trim()) {
      resetUI();
      return;
    }

    hideAlert();
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = `
      <svg class="spin" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-dashoffset="12"></circle>
      </svg>
      Scanning AST...
    `;

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, filename: 'source_analysis.py' })
      });

      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }

      const data = await res.json();
      renderResults(data);
      markEditorClean();
    } catch (err) {
      console.error('Analysis failed:', err);
      showAlert(`AST Scan Failed: ${err.message}`);
      if (scanTimestamp) {
        scanTimestamp.className = 'scan-timestamp stale';
        scanTimestamp.textContent = '❌ Scan error';
      }
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
      showAlert(data.message || 'Inspection error returned by AST parser');
      return;
    }

    const m = data.metrics || {};
    metricRisk.textContent = `${m.risk_score ?? 0} / 100`;
    metricComplexity.textContent = m.cyclomatic_complexity ?? 1;
    metricViolations.textContent = data.violations_count ?? 0;
    violationsCountBadge.textContent = `${data.violations_count ?? 0} Issues`;

    // Status pill
    metricStatus.textContent = m.security_status || 'UNKNOWN';
    metricStatus.className = 'metric-val';
    if ((m.risk_score ?? 0) >= 50) {
      metricStatus.classList.add('status-danger');
    } else if ((m.risk_score ?? 0) > 0) {
      metricStatus.classList.add('status-warn');
    } else {
      metricStatus.classList.add('status-clean');
    }

    // Render Violations
    violationsList.innerHTML = '';
    const violations = data.violations || [];
    if (violations.length === 0) {
      violationsList.innerHTML = '<div class="empty-state">✅ Clean AST! No security or quality violations found.</div>';
    } else {
      violations.forEach(v => {
        const card = document.createElement('div');
        card.className = `violation-card ${v.severity}`;
        card.innerHTML = `
          <div class="violation-head">
            <span class="violation-rule">${v.rule}</span>
            <span class="severity-pill ${v.severity}">${v.severity}</span>
          </div>
          <div class="violation-msg">${v.message}</div>
          <div class="violation-meta">Line ${v.line}, Col ${v.col} • ${v.cwe || 'CWE'}</div>
          ${v.remediation ? `<div class="remediation-box"><strong>Remediation:</strong> ${v.remediation}</div>` : ''}
        `;
        violationsList.appendChild(card);
      });
    }

    // Render AST Tree Summary
    astTreeView.innerHTML = `<pre>${JSON.stringify(data.ast_tree || {}, null, 2)}</pre>`;

    // Update timestamp
    const now = new Date();
    const timeStr = now.toLocaleTimeString();
    if (scanTimestamp) {
      scanTimestamp.className = 'scan-timestamp';
      scanTimestamp.textContent = `● Fresh scan at ${timeStr}`;
    }

    // Pulse animation on metric cards to show active refresh
    if (metricsRow) {
      metricsRow.classList.remove('flash-updated');
      void metricsRow.offsetWidth; // force DOM reflow
      metricsRow.classList.add('flash-updated');
    }
  }

  analyzeBtn.addEventListener('click', runAnalysis);

  // SARIF Export
  sarifBtn.addEventListener('click', async () => {
    const source = codeInput.value;
    if (!source.trim()) {
      showAlert('Enter code first before exporting SARIF report.');
      return;
    }

    sarifBtn.disabled = true;
    sarifBtn.textContent = 'Exporting...';
    try {
      const res = await fetch('/api/sarif', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, filename: 'source_analysis.py' })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
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
      showAlert(`SARIF Export Failed: ${err.message}`);
    } finally {
      sarifBtn.disabled = false;
      sarifBtn.textContent = 'Export SARIF 2.1';
    }
  });

  loadSnippets();
});
