/**
 * Rules Catalog Component
 * Displays the registered security rule definitions, CWE and OWASP mappings.
 */

import { RULES_CATALOG } from '../api.js';

export class RulesCatalogComponent {
  constructor() {
    this.tbody = document.getElementById('rulesTableBody');
  }

  render(rules = RULES_CATALOG) {
    if (!this.tbody) return;
    this.tbody.innerHTML = '';

    rules.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong style="color: #cbd5e1;">${r.rule_id}</strong><br><span style="font-size: 0.75rem; color: #818cf8;">${r.name}</span></td>
        <td><span class="sev-pill ${r.sev}">${r.sev}</span></td>
        <td><strong style="color: #cbd5e1;">${r.cwe}</strong><br><span style="color: #64748b; font-size: 0.75rem;">${r.owasp}</span></td>
        <td>
          <div style="color: #e2e8f0; margin-bottom: 0.35rem;">${r.desc}</div>
          <div style="color: #34d399; font-size: 0.75rem; font-family: monospace;">Fix: ${r.fix}</div>
        </td>
      `;
      this.tbody.appendChild(tr);
    });
  }
}
