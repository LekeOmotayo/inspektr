/**
 * Violations Component
 * Renders security violation cards, severity pills, CWE references, and remediation diffs.
 */

export class ViolationsComponent {
  constructor() {
    this.container = document.getElementById('findingsContainer');
  }

  render(violations = []) {
    if (!this.container) return;
    this.container.innerHTML = '';

    if (violations.length === 0) {
      this.container.innerHTML = `
        <div class="clean-state">
          <div class="clean-icon">✓</div>
          <h3 style="font-size: 1.2rem; color: #fff;">AST Guardrail Passed</h3>
          <p style="color: #94a3b8; font-size: 0.9rem; max-width: 440px;">
            Zero security violations or dangerous execution primitives detected in the Abstract Syntax Tree. Code is production-ready.
          </p>
        </div>
      `;
      return;
    }

    violations.forEach(v => {
      const card = document.createElement('div');
      card.className = `finding-card ${v.severity}`;
      card.innerHTML = `
        <div class="finding-head">
          <div class="finding-tags">
            <span class="sev-pill ${v.severity}">${v.severity}</span>
            <span class="rule-id-pill">${v.rule_id} • ${v.rule}</span>
          </div>
          <span class="line-chip">Line ${v.line_no}</span>
        </div>
        <div class="finding-cwe">${v.cwe} • ${v.owasp || ''}</div>
        <div class="finding-desc">${v.message}</div>
        ${v.code_snippet ? `<div class="finding-snippet">&gt; ${this._escapeHtml(v.code_snippet)}</div>` : ''}
        <div class="remediation-box">
          <strong>💡 Safe Remediation</strong>
          ${v.remediation}
        </div>
      `;
      this.container.appendChild(card);
    });
  }

  _escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}
