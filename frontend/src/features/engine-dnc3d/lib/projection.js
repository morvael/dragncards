import { PERSP_VW } from './config';

export function createProjection() {
  // Updated by applyTilt() so card dimensions always scale proportionally
  // with the tilt element's coordinate system rather than the raw viewport.
  let _tiltW = window.innerWidth;
  let _tiltH = window.innerHeight;

  function stagePx() { return PERSP_VW * window.innerWidth / 100; }
  function setTiltDims(w, h) { _tiltW = w; _tiltH = h; }
  function cardWidthPx()  { return _tiltW * 0.05; }
  function cardHeightPx() { return _tiltH * 0.07 * window.innerWidth / window.innerHeight; }

  // Inverse projection: screen coordinates → table-plane coordinates.
  function screenToTable(sx, sy, tiltEl, deg) {
    const rad  = deg * Math.PI / 180;
    const cosA = Math.cos(rad), sinA = Math.sin(rad);
    const vh   = window.innerHeight;
    const vw   = window.innerWidth;
    const w    = parseFloat(tiltEl.style.width);
    const P    = stagePx();

    const ty = P * sy / (P * cosA + (sy - vh / 2) * sinA);
    const tx = w / 2 + (sx - vw / 2) * (P - ty * sinA) / P;
    return { x: tx, y: ty };
  }

  // Inverse projection accounting for a card's translateZ offset.
  function screenToTableAtZ(sx, sy, Z, tiltEl, deg) {
    const rad  = deg * Math.PI / 180;
    const cosA = Math.cos(rad), sinA = Math.sin(rad);
    const vh   = window.innerHeight;
    const vw   = window.innerWidth;
    const w    = parseFloat(tiltEl.style.width);
    const P    = stagePx();
    const D    = P * cosA + (sy - vh / 2) * sinA;
    const ty   = (P * sy + Z * (P * sinA - (sy - vh / 2) * cosA)) / D;
    const tx   = w / 2 + (sx - vw / 2) * (P - ty * sinA - Z * cosA) / P;
    return { x: tx, y: ty };
  }

  // Forward projection: table-plane coordinates at a given Z → screen coordinates.
  function tableToScreen(tx, ty, Z, tiltEl, deg) {
    const rad  = deg * Math.PI / 180;
    const cosA = Math.cos(rad), sinA = Math.sin(rad);
    const vh   = window.innerHeight;
    const vw   = window.innerWidth;
    const w    = parseFloat(tiltEl.style.width);
    const P    = stagePx();
    const D    = P - ty * sinA - Z * cosA;
    const sx   = P * (tx - w / 2) / D + vw / 2;
    const sy   = P * (ty * cosA - Z * sinA - vh / 2) / D + vh / 2;
    return { x: sx, y: sy };
  }

  return { stagePx, setTiltDims, cardWidthPx, cardHeightPx, screenToTable, screenToTableAtZ, tableToScreen };
}
