/**
 * SARIF Component
 * Formats the findings into standard OASIS SARIF v2.1.0 JSON and provides copy functionality.
 */

export class SarifComponent {
  constructor() {
    this.box = document.getElementById('sarifBox');
  }

  render(violations = []) {
    if (!this.box) return;

    const sarifObj = {
      "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      "version": "2.1.0",
      "runs": [{
        "tool": {
          "driver": {
            "name": "Leke-AST-Code-Inspector",
            "semanticVersion": "2.0.0",
            "informationUri": "https://github.com/lekeomotayo/leke-ast-code-inspector"
          }
        },
        "results": violations.map(v => ({
          "ruleId": v.rule_id,
          "level": (v.severity === 'CRITICAL' || v.severity === 'HIGH') ? 'error' : (v.severity === 'MEDIUM' ? 'warning' : 'note'),
          "message": { "text": v.message },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": { "uri": "agent_code.py" },
              "region": {
                "startLine": v.line_no,
                "snippet": { "text": v.code_snippet || "" }
              }
            }
          }]
        }))
      }]
    };

    this.box.innerText = JSON.stringify(sarifObj, null, 2);
  }

  copyToClipboard() {
    if (!this.box) return;
    const text = this.box.innerText;
    navigator.clipboard.writeText(text).then(() => {
      alert('SARIF v2.1.0 JSON copied to clipboard for CI/CD integration!');
    }).catch(err => {
      console.error('Failed to copy SARIF text:', err);
    });
  }
}
