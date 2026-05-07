// Converts a dragncards layout.regions object into the dnc3d REGIONS format.
// dragncards coordinates are 0-1 fractions (or "5%"/"1/20" strings).
// dnc3d uses 0-100 numbers.

function toPercent(val) {
  if (val === undefined || val === null) return 0;
  if (typeof val === 'number') return val * 100;
  if (typeof val === 'string') {
    if (val.endsWith('%')) return parseFloat(val);
    const m = val.match(/^(\d+(?:\.\d+)?)\/(\d+(?:\.\d+)?)$/);
    if (m) return (parseFloat(m[1]) / parseFloat(m[2])) * 100;
    return parseFloat(val) * 100;
  }
  return 0;
}

// Maps dragncards region types to dnc3d region types.
// dnc3d supports: 'free' | 'row' | 'fan' | 'pile'
const TYPE_MAP = {
  free: 'free',
  row:  'row',
  fan:  'fan',
  pile: 'pile',
  // dragncards aliases
  hand: 'fan',
};

export function adaptRegions(layoutRegions) {
  if (!layoutRegions) return {};
  const regions = {};
  Object.entries(layoutRegions).forEach(([, region]) => {
    if (region.visible === false) return;
    const groupId = region.groupId;
    if (!groupId) return;
    const type = TYPE_MAP[region.type] || 'free';
    regions[groupId] = {
      left:   toPercent(region.left),
      top:    toPercent(region.top),
      width:  toPercent(region.width),
      height: toPercent(region.height),
      type,
      ...(region.direction     ? { direction:       region.direction }      : {}),
      ...(region.layerIndex    ? { layerIndex:       region.layerIndex }     : {}),
      ...(region.backgroundColor ? { backgroundColor: region.backgroundColor } : {}),
    };
  });
  return regions;
}

// Returns just the toPercent helper for use in other modules.
export { toPercent };
