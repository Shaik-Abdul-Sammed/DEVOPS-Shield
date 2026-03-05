const levelThresholds = [
  { level: 'Safe', min: 0, max: 20 },
  { level: 'Low', min: 20, max: 50 },
  { level: 'Medium', min: 50, max: 75 },
  { level: 'High', min: 75, max: 90 },
  { level: 'Critical', min: 90, max: 101 }
];

export const getRiskLevel = (score) => {
  if (typeof score !== 'number' || Number.isNaN(score)) return 'Unknown';
  const normalized = Math.max(0, Math.min(100, score));
  const threshold = levelThresholds.find((entry) => normalized >= entry.min && normalized < entry.max);
  return threshold ? threshold.level : 'Critical';
};

export const getRiskColor = (scoreOrLevel) => {
  const level = typeof scoreOrLevel === 'number' ? getRiskLevel(scoreOrLevel) : scoreOrLevel;
  switch (level) {
    case 'Safe':
      return 'var(--risk-safe)';
    case 'Low':
      return 'var(--risk-low)';
    case 'Medium':
      return 'var(--risk-medium)';
    case 'High':
      return 'var(--risk-high)';
    case 'Critical':
      return 'var(--risk-critical)';
    default:
      return 'var(--risk-unknown)';
  }
};

export const getRiskToneClass = (scoreOrLevel) => {
  const level = typeof scoreOrLevel === 'number' ? getRiskLevel(scoreOrLevel) : scoreOrLevel;
  switch (level) {
    case 'Safe':
    case 'Low':
      return 'tone-safe';
    case 'Medium':
      return 'tone-medium';
    case 'High':
      return 'tone-high';
    case 'Critical':
      return 'tone-critical';
    default:
      return 'tone-unknown';
  }
};

export const describeRiskReasons = (reasons = []) => {
  if (!Array.isArray(reasons) || reasons.length === 0) {
    return 'No risk signals reported.';
  }
  return reasons
    .slice(0, 3)
    .map((reason) => `${reason.type}: ${reason.detail}`)
    .join('\n');
};
