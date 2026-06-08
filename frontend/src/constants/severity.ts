/** Shared severity color maps for Ant Design Tag (name-based) and ECharts (hex). */

/** Ant Design Tag color names — accepts both casings, used with `<Tag color={...}>`. */
export const SEVERITY_TAG_COLORS: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'green',
  unknown: 'default',
  CRITICAL: 'red',
  HIGH: 'orange',
  MEDIUM: 'gold',
  LOW: 'green',
  UNKNOWN: 'default',
};

/** ECharts hex colors — accepts both casings for convenience. */
export const SEVERITY_HEX_COLORS: Record<string, string> = {
  critical: '#ff4d4f',
  high: '#fa8c16',
  medium: '#faad14',
  low: '#52c41a',
  unknown: '#d9d9d9',
  CRITICAL: '#ff4d4f',
  HIGH: '#fa8c16',
  MEDIUM: '#faad14',
  LOW: '#52c41a',
  UNKNOWN: '#d9d9d9',
};
