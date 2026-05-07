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
// Connected mode (Phase 2+): pass game, layoutRegions, gameDef, language, doActionList.
// The adapters translate dragncards Redux state into the engine's data contract.
// Live reconciliation (state-change re-renders after the server broadcasts back) is Phase 5.
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

  // Capture connected-mode props at mount time (engine is initialized once).
  // Phase 3 will add a separate effect for live reconciliation on game changes.
  const initPropsRef = useRef({ game, layoutRegions, gameDef, language, doActionList });

  // ── One-time engine initialisation ─────────────────────────────────────────
  useEffect(() => {
    const tiltEl = tiltRef.current;
    const { game: g, layoutRegions: lr, gameDef: gd, language: lang, doActionList: dal } = initPropsRef.current;
    const connected = g && lr;

    let engineOptions = {};
    let initData      = {};

    if (connected) {
      const regions = adaptRegions(lr);
      const { cardDescriptors, assignments, idMap } = adaptGameState(g, lr, gd, lang);
      const reverseIdMap = new Map([...idMap.entries()].map(([k, v]) => [v, k]));
      const callbacks    = buildEngineCallbacks(dal, reverseIdMap);
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
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

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
