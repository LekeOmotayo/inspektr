/**
 * Editor Component
 * Manages the code textarea, preset dropdown selection, and inspection triggers.
 */

import { PRESETS } from '../api.js';

export class EditorComponent {
  constructor({ onInspect }) {
    this.textarea = document.getElementById('codeSource');
    this.presetSelect = document.getElementById('samplePresetSelect');
    this.inspectBtn = document.getElementById('inspectBtn');
    this.onInspect = onInspect;

    this._bindEvents();
  }

  _bindEvents() {
    if (this.presetSelect) {
      this.presetSelect.addEventListener('change', (e) => {
        this.loadPreset(e.target.value);
      });
    }

    if (this.inspectBtn) {
      this.inspectBtn.addEventListener('click', () => {
        if (this.onInspect) {
          this.onInspect(this.getCode());
        }
      });
    }
  }

  getCode() {
    return this.textarea ? this.textarea.value : '';
  }

  setCode(code) {
    if (this.textarea) {
      this.textarea.value = code;
    }
  }

  loadPreset(presetKey) {
    if (PRESETS[presetKey]) {
      this.setCode(PRESETS[presetKey]);
      if (this.onInspect) {
        this.onInspect(this.getCode());
      }
    }
  }

  clear() {
    this.setCode('');
    if (this.onInspect) {
      this.onInspect('');
    }
  }

  setLoading(loading) {
    if (this.inspectBtn) {
      this.inspectBtn.disabled = loading;
      this.inspectBtn.innerHTML = loading
        ? '<span>⏳</span> Analyzing AST...'
        : '<span>🔍</span> Inspect Abstract Syntax Tree';
    }
  }
}
