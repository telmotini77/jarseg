import { useEffect, useRef } from 'react';

export type VisualState = 'idle' | 'listening' | 'processing' | 'speaking' | 'executing' | 'alert' | 'error';

export function JarvisCore({ state, level = 0.12, reducedMotion = false }: { state: VisualState; level?: number; reducedMotion?: boolean }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const node = canvas.current; if (!node) return;
    const ctx = node.getContext('2d'); if (!ctx) return;
    let frame = 0; let active = true;
    const paint = (time: number) => {
      const size = Math.min(node.clientWidth, node.clientHeight); const ratio = devicePixelRatio || 1;
      if (node.width !== size * ratio) { node.width = size * ratio; node.height = size * ratio; }
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0); ctx.clearRect(0, 0, size, size);
      const center = size / 2; const phase = reducedMotion ? 0 : time / (state === 'processing' || state === 'executing' ? 180 : 1100);
      const color = state === 'error' ? '#ff6175' : state === 'alert' ? '#ffc45e' : state === 'listening' ? '#8affed' : '#52c7ff';
      const base = size * (.15 + level * .035 + (state === 'speaking' ? .035 : 0));
      ctx.save(); ctx.translate(center, center);
      for (let ring = 0; ring < 4; ring += 1) { const radius = base + ring * size * .07 + Math.sin(phase + ring) * (reducedMotion ? 0 : 3); ctx.strokeStyle = `${color}${Math.round(140 - ring * 25).toString(16).padStart(2, '0')}`; ctx.lineWidth = ring === 0 ? 2 : 1; ctx.setLineDash(ring % 2 ? [5, 8] : []); ctx.beginPath(); ctx.arc(0, 0, radius, phase * (ring % 2 ? -1 : 1), Math.PI * 2 + phase); ctx.stroke(); }
      ctx.setLineDash([]); for (let dot = 0; dot < 28; dot += 1) { const angle = dot / 28 * Math.PI * 2 + phase * .35; const radius = base + size * (.2 + (dot % 3) * .035); ctx.fillStyle = color; ctx.globalAlpha = .25 + (dot % 4) / 12; ctx.beginPath(); ctx.arc(Math.cos(angle) * radius, Math.sin(angle) * radius, 1.5 + level * 2, 0, Math.PI * 2); ctx.fill(); }
      const glow = ctx.createRadialGradient(0, 0, 0, 0, 0, base * 1.3); glow.addColorStop(0, `${color}cc`); glow.addColorStop(.35, `${color}33`); glow.addColorStop(1, `${color}00`); ctx.globalAlpha = 1; ctx.fillStyle = glow; ctx.beginPath(); ctx.arc(0, 0, base * 1.3, 0, Math.PI * 2); ctx.fill(); ctx.fillStyle = '#e9f8ff'; ctx.beginPath(); ctx.arc(0, 0, base * .42, 0, Math.PI * 2); ctx.fill(); ctx.restore();
      if (active) frame = requestAnimationFrame(paint);
    }; frame = requestAnimationFrame(paint); return () => { active = false; cancelAnimationFrame(frame); };
  }, [state, level, reducedMotion]);
  return <div className={`jarvis-core ${state}`}><canvas ref={canvas} aria-label={`JARVIS core ${state}`} /><div className="core-copy"><b>JARVIS</b><span>◉ CORE</span><small>{state.toUpperCase()}</small></div></div>;
}
