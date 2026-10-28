/**
 * Main Application Orchestrator
 * Connects API service and UI components into a clean reactive workflow.
 */

import { ApiService } from './api.js';
import { MetricsComponent } from './components/Metrics.js';
import { EditorComponent } from './components/Editor.js';
import { ViolationsComponent } from './components/Violations.js';
import { AstTreeComponent } from './components/AstTree.js';
import { SarifComponent } from './components/SarifView.js';
import { RulesCatalogComponent } from './components/RulesCatalog.js';

class App {
  constructor() {
    this.api = new ApiService();
    this.metrics = new MetricsComponent();
    this.violations = new ViolationsComponent();
    this.astTree = new AstTreeComponent();
    this.sarif = new SarifComponent();
    this.rules = new RulesCatalogComponent();

    this.editor = new EditorComponent({
      onInspect: (code) => this.runAnalysis(code)
    });

    this.serverBadge = document.getElementById('serverBadge');
    this.serverBadgeText = document.getElementById('serverBadgeText');

    this._setupTabs();
    this._setupActionButtons();
  }

  async init() {
    this.rules.render();
    const health = await this.api.checkHealth();
    this._updateServerStatus(health);

    // Load initial preset and analyze
    this.editor.loadPreset('vulnerable_agent');
  }

  _setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const targetTab = btn.getAttribute('data-tab');
        this.switchTab(targetTab, btn);
      });
    });
  }

  _setupActionButtons() {
    const clearBtn = document.getElementById('clearBtn');
    if (clearBtn) {
      clearBtn.addEventListener('click', () => this.editor.clear());
    }

    const copySarifBtn = document.getElementById('copySarifBtn');
    if (copySarifBtn) {
      copySarifBtn.addEventListener('click', () => this.sarif.copyToClipboard());
    }
  }

  switchTab(tabKey, activeBtn) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    if (activeBtn) activeBtn.classList.add('active');

    const tabContents = {
      violations: document.getElementById('tabContentViolations'),
      astTree: document.getElementById('tabContentAstTree'),
      sarif: document.getElementById('tabContentSarif'),
      rulesCatalog: document.getElementById('tabContentRulesCatalog')
    };

    Object.keys(tabContents).forEach(key => {
      if (tabContents[key]) {
        tabContents[key].style.display = (key === tabKey) ? 'block' : 'none';
      }
    });
  }

  async runAnalysis(code) {
    this.editor.setLoading(true);
    try {
      const result = await this.api.inspectCode(code);
      this.metrics.render(result);
      this.violations.render(result.violations);
      this.astTree.render(result.ast_tree);
      this.sarif.render(result.violations);
    } catch (err) {
      console.error('Analysis error:', err);
    } finally {
      this.editor.setLoading(false);
    }
  }

  _updateServerStatus({ connected, label }) {
    if (!this.serverBadge || !this.serverBadgeText) return;
    this.serverBadgeText.innerText = label;

    if (connected) {
      this.serverBadge.style.background = 'rgba(16, 185, 129, 0.15)';
      this.serverBadge.style.borderColor = 'rgba(16, 185, 129, 0.4)';
      this.serverBadge.style.color = '#34d399';
    } else {
      this.serverBadge.style.background = 'rgba(99, 102, 241, 0.15)';
      this.serverBadge.style.borderColor = 'rgba(99, 102, 241, 0.4)';
      this.serverBadge.style.color = '#818cf8';
    }
  }
}

// Boot application
window.addEventListener('DOMContentLoaded', () => {
  const app = new App();
  app.init();
});
