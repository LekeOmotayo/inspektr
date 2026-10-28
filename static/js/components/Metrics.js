/**
 * Metrics Component
 * Renders the score radial badge, violations count, cyclomatic complexity, and maintainability index.
 */

export class MetricsComponent {
  constructor() {
    this.scoreBadge = document.getElementById('scoreBadge');
    this.metricViolations = document.getElementById('metricViolations');
    this.metricComplexity = document.getElementById('metricComplexity');
    this.metricAstNodes = document.getElementById('metricAstNodes');
    this.metricMaintainability = document.getElementById('metricMaintainability');
    this.tabViolationCount = document.getElementById('tabViolationCount');
  }

  render(analysis) {
    const { violations = [], metrics = {}, score = 0, rating = 'F', summary = {} } = analysis;

    // 1. Update Score Badge
    const gradeLetter = rating.charAt(0);
    this.scoreBadge.className = `score-badge ${gradeLetter}`;
    this.scoreBadge.innerText = `Score: ${score} / 100 [Rating: ${rating}]`;

    // 2. Metric Cards
    const critCount = summary.critical || 0;
    const highCount = summary.high || 0;
    this.metricViolations.innerHTML = `${violations.length} <span class="metric-sub">${critCount} Critical / ${highCount} High</span>`;
    this.metricComplexity.innerHTML = `${metrics.cyclomatic_complexity || 1} <span class="metric-sub">McCabe</span>`;
    this.metricAstNodes.innerHTML = `${metrics.ast_nodes || 0} <span class="metric-sub">Depth: ${metrics.max_depth || 0}</span>`;
    this.metricMaintainability.innerHTML = `${metrics.maintainability_index || 100} <span class="metric-sub">/ 100</span>`;

    // 3. Tab Badge
    if (this.tabViolationCount) {
      this.tabViolationCount.innerText = violations.length;
    }
  }
}
