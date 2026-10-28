/**
 * AST Tree Component
 * Renders the hierarchical tree visualization of Python syntax grammar nodes.
 */

export class AstTreeComponent {
  constructor() {
    this.container = document.getElementById('astTreeContainer');
  }

  render(astTree) {
    if (!this.container) return;
    this.container.innerHTML = '';

    if (!astTree) {
      this.container.innerHTML = '<p style="color: #64748b;">AST Hierarchy unavailable.</p>';
      return;
    }

    this.container.appendChild(this._buildNodeElement(astTree));
  }

  _buildNodeElement(node) {
    const el = document.createElement('div');
    el.className = 'tree-node';

    const label = document.createElement('div');
    label.className = `tree-label type-${node.type}`;
    const lineInfo = node.lineno ? `<span class="tree-line-badge">(L:${node.lineno})</span>` : '';
    label.innerHTML = `<span>●</span> <strong>${this._escapeHtml(node.label || node.name)}</strong> ${lineInfo}`;
    el.appendChild(label);

    if (node.children && node.children.length > 0) {
      node.children.forEach(child => {
        el.appendChild(this._buildNodeElement(child));
      });
    }
    return el;
  }

  _escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}
