import { useEffect, useRef } from 'react';
import { createDnc3DEngine } from './lib/engine';
import { adaptRegions } from './adapters/regions';
import { adaptGameState } from './adapters/cards';
import { buildEngineCallbacks } from './adapters/actions';
import './Dnc3DTable.css';

// Wrapper component for the dnc3d engine.
//
// Sandbox mode (no game props): renders 20 demo cards in DEFAULT_REGIONS.
//
// Connected mode: pass game, layoutRegions, gameDef, language, doActionList.
// The engine is (re-)initialized whenever the card set changes (deck load).
// Incremental reconciliation for mid-game server updates is Phase 5.
export default function Dnc3DTable({
  tiltDeg      = 15,
  tableOpacity = 100,
  // Connected mode props — all optional; omitting them uses demo mode
  game,
  layoutRegions,
  gameDef,
  language,
  doActionList,
}) {
  const tiltRef    = useRef(null);
  const engineRef  = useRef(null);
  const tiltDegRef = useRef(tiltDeg);
  tiltDegRef.current = tiltDeg;

  // Live refs — always hold the latest prop values so the engine-init effect
  // can read them without needing to be listed as deps (which would cause
  // re-initialization on every Redux tick).
  const gameRef         = useRef(game);
  const layoutRef       = useRef(layoutRegions);
  const gameDefRef      = useRef(gameDef);
  const languageRef     = useRef(language);
  const doActionListRef = useRef(doActionList);
  gameRef.current         = game;
  layoutRef.current       = layoutRegions;
  gameDefRef.current      = gameDef;
  languageRef.current     = language;
  doActionListRef.current = doActionList;

  // Re-initialize the engine whenever the card set changes.
  // This handles: switching to dnc3d after cards are loaded, and loading a
  // deck while already in dnc3d mode. cardCount is a stable numeric dep that
  // only changes on deck load — not on every card state update.
  const cardCount = Object.keys(game?.cardById || {}).length;

  useEffect(() => {
    const tiltEl = tiltRef.current;
    if (!tiltEl) return;

    const g  = gameRef.current;
    const lr = layoutRef.current;
    const connected = g && lr;

    let engineOptions = {};
    let initData      = {};

    if (connected) {
      const regions = adaptRegions(lr);
      const { cardDescriptors, assignments, idMap } = adaptGameState(
        g, lr, gameDefRef.current, languageRef.current
      );
      const reverseIdMap = new Map([...idMap.entries()].map(([k, v]) => [v, k]));
      const callbacks    = buildEngineCallbacks(doActionListRef.current, reverseIdMap);
      engineOptions = { regions, ...callbacks };
      initData      = { cards: cardDescriptors, assignments };
    }

    const engine = createDnc3DEngine(engineOptions);
    engineRef.current = engine;

    engine.applyTilt(tiltEl, tiltDegRef.current);
    const cleanup = engine.init(tiltEl, tiltDegRef.current, initData);

    function handleResize() {
      engine.applyTilt(tiltEl, tiltDegRef.current);
      engine.onTiltUpdated();
    }
    window.addEventListener('resize', handleResize);

    return () => {
      cleanup();
      window.removeEventListener('resize', handleResize);
      engineRef.current = null;
    };
  }, [cardCount]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Respond to tilt angle changes ──────────────────────────────────────────
  useEffect(() => {
    const tiltEl = tiltRef.current;
    const engine = engineRef.current;
    if (!tiltEl || !engine) return;
    engine.setCurrentDeg(tiltDeg);
    engine.applyTilt(tiltEl, tiltDeg);
    engine.onTiltUpdated();
  }, [tiltDeg]);

  // ── Respond to table opacity changes ───────────────────────────────────────
  useEffect(() => {
    const tiltEl = tiltRef.current;
    const engine = engineRef.current;
    if (!tiltEl || !engine) return;
    engine.applyTableOpacity(tiltEl, tableOpacity / 100);
  }, [tableOpacity]);

  return (
    <div className="dnc3d-stage">
      <div className="dnc3d-tilt" ref={tiltRef}>
        <div className="dnc3d-table-surface" />
      </div>
    </div>
  );
}
