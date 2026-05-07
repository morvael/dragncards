// Resolves a card face's imageUrl using the gameDef prefix/language system,
// mirroring the logic in useVisibleFaceSrc without needing React hooks.
export function resolveImageUrl(face, gameDef, language) {
  if (!face) return null;
  const srcBase = face.imageUrl;
  if (!srcBase) {
    // No url → card back
    return gameDef?.cardBacks?.[face.name]?.imageUrl || null;
  }
  if (srcBase.startsWith('http')) return srcBase;
  // Suffix path: prepend language-specific or default prefix
  const srcLanguage = gameDef?.imageUrlPrefix?.[language]
    ? gameDef.imageUrlPrefix[language] + srcBase
    : null;
  const srcDefault = gameDef?.imageUrlPrefix?.Default
    ? gameDef.imageUrlPrefix.Default + srcBase
    : null;
  return srcLanguage || srcDefault || null;
}

// Converts dragncards game state into the format expected by the dnc3d engine's init.
//
// Returns:
//   cardDescriptors — array of { id, frontImageUrl, backImageUrl, angle }
//                     indexed 0..N, one per card in game.cardById
//   assignments     — { [groupId]: [{ cardIds: [int,...], attachmentDirections, fracX, fracY }] }
//   idMap           — Map<dcCardId, dnc3dIndex> for mapping action callbacks back
export function adaptGameState(game, layoutRegions, gameDef, language) {
  const { cardById = {}, stackById = {}, groupById = {} } = game || {};

  // 1. Build integer index mapping for all cards
  const allCardIds = Object.keys(cardById);
  const idMap = new Map(allCardIds.map((dcId, i) => [dcId, i]));

  // 2. Build card descriptors
  const cardDescriptors = allCardIds.map((dcId, i) => {
    const card = cardById[dcId];
    const sides = card.sides || {};
    const sideKeys = Object.keys(sides);
    const frontSide = card.currentSide || sideKeys[0] || 'A';
    const backSide  = sideKeys.find(s => s !== frontSide) || frontSide;
    const angle = frontSide !== 'A' ? 180 : 0;
    return {
      id: i,
      frontImageUrl: resolveImageUrl(sides[frontSide], gameDef, language),
      backImageUrl:  resolveImageUrl(sides[backSide],  gameDef, language),
      angle,
    };
  });

  // 3. Build assignments keyed by groupId
  const assignments = {};
  Object.entries(layoutRegions || {}).forEach(([, region]) => {
    if (region.visible === false) return;
    const groupId = region.groupId;
    if (!groupId || !groupById[groupId]) return;

    const group = groupById[groupId];
    const stacks = [];

    (group.stackIds || []).forEach(stackId => {
      const stack = stackById[stackId];
      if (!stack) return;

      const dnc3dCardIds = (stack.cardIds || [])
        .map(dcId => idMap.get(dcId))
        .filter(id => id !== undefined);
      if (!dnc3dCardIds.length) return;

      // attachmentDirections for cards[1..] (the parent at [0] has no direction)
      const attachmentDirections = (stack.cardIds || []).slice(1).map(dcId => {
        const dir = cardById[dcId]?.attachmentDirection;
        return (dir === 'left' || dir === 'right') ? dir : 'right';
      });

      // Free-region stacks store their position as 0-1 fractions on the stack
      stacks.push({
        cardIds: dnc3dCardIds,
        attachmentDirections,
        fracX: stack.left  ?? null,
        fracY: stack.top   ?? null,
      });
    });

    assignments[groupId] = stacks;
  });

  return { cardDescriptors, assignments, idMap };
}
