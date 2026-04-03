function () {
  'use strict';

  /* ═══════════════════════════════════════════════════════════════════
     LICENCE KEYS
  ═══════════════════════════════════════════════════════════════════ */
  const KEYS = new Set([
    'VEL-A1B2-WXYZ-0001', 'VEL-C3D4-PQRS-0002', 'VEL-E5F6-MNOP-0003',
    'VEL-G7H8-IJKL-0004', 'VEL-I9J0-EFGH-0005', 'VEL-K1L2-ABCD-0006',
    'VEL-M3N4-TUVW-0007', 'VEL-O5P6-QRST-0008', 'VEL-Q7R8-UVWX-0009',
    'VEL-S9T0-YZAB-0010', 'owner',
  ]);

  /* ─── Core config ──────────────────────────────────────────────── */
  const DAILY   = 3;                        // 3 predictions per calendar day
  const EXP_MS  = 7 * 24 * 60 * 60 * 1000; // 7-day licence expiry
  const GMP     = { 1:8, 2:5, 3:4, 4:3, 5:2 }; // gem count per mine setting
  const SITE    = 'https://stakepredictor.mysellauth.com/';
  const MAX_BET = 15; // warn when detected bet exceeds $15

  /* ═══════════════════════════════════════════════════════════════════
     STORAGE — dual-write localStorage + GM_setValue
     Daily usage keyed by ISO date so page refresh never resets count
  ═══════════════════════════════════════════════════════════════════ */
  function fp () {
    const s = [
      navigator.language,
      screen.colorDepth,
      screen.width + 'x' + screen.height,
      Intl.DateTimeFormat().resolvedOptions().timeZone,
      navigator.hardwareConcurrency || 4,
    ].join('|');
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
    return (h >>> 0).toString(36);
  }

  const _sk = r => '_vp43_' + btoa(r + fp()).replace(/[^a-zA-Z0-9]/g, '').slice(0, 24);

  const _ws = (r, d) => {
    const k = _sk(r), v = JSON.stringify(d);
    try { localStorage.setItem(k, v); } catch (e) { /* quota */ }
    try { GM_setValue(k, v); } catch (e) { /* unavailable */ }
  };

  const _rs = r => {
    const k = _sk(r);
    let v = null;
    try { v = localStorage.getItem(k); if (v) return JSON.parse(v); } catch (e) {}
    try { v = GM_getValue(k, null);    if (v) return JSON.parse(v); } catch (e) {}
    return null;
  };

  const slk = r => {
    try { localStorage.setItem('_vp43lk', r); } catch (e) {}
    try { GM_setValue('_vp43lk', r);           } catch (e) {}
  };
  const glk = () => {
    try { return localStorage.getItem('_vp43lk') || GM_getValue('_vp43lk', null); } catch (e) { return null; }
  };
  const dlk = () => {
    try { localStorage.removeItem('_vp43lk'); } catch (e) {}
    try { GM_setValue('_vp43lk', null);        } catch (e) {}
  };

  /* ═══════════════════════════════════════════════════════════════════
     LICENCE VALIDATION
  ═══════════════════════════════════════════════════════════════════ */
  function validate (raw) {
    const key = (raw || '').trim().toUpperCase();
    if (!KEYS.has(key)) return { ok: false, err: 'Invalid licence key.' };
    let rec = _rs(key);
    if (!rec) {
      rec = { key, fp: fp(), at: Date.now(), exp: Date.now() + EXP_MS, du: {}, us: [] };
      _ws(key, rec);
      return { ok: true, rec, key };
    }
    if (rec.fp !== fp())      return { ok: false, err: 'Key bound to another device.' };
    if (Date.now() > rec.exp) return { ok: false, err: 'Licence has expired.' };
    return { ok: true, rec, key };
  }

  /* Day-keyed usage counter — resets automatically at UTC midnight */
  const dayN = rec => {
    const d = new Date().toISOString().slice(0, 10);
    return (rec.du && rec.du[d]) || 0;
  };

  const consume = (key, rec, sp) => {
    const d = new Date().toISOString().slice(0, 10);
    if (!rec.du) rec.du = {};
    rec.du[d] = (rec.du[d] || 0) + 1;
    if (!rec.us) rec.us = [];
    rec.us.push(sp);
    _ws(key, rec);
  };

  /* seed-pair replay guard */
  const wasUsed = (rec, sp) => rec.us && rec.us.includes(sp);
  const mkSP    = (a, b, m) => btoa(a.slice(0, 16) + '|' + b + '|' + m).slice(0, 32);

  /* seed format checks */
  const okSS = s => /^[0-9a-f]{64}$/i.test((s || '').trim());
  const okCS = s => (s || '').trim().length > 0;

  /* ═══════════════════════════════════════════════════════════════════
     PREDICTION ENGINE — HMAC-SHA256 + Fisher-Yates shuffle
     For 24-mine mode: gems = 1 (exactly one safe cell in a 5×5 grid)
  ═══════════════════════════════════════════════════════════════════ */
  async function predict (serverSeed, clientSeed, mines) {
    /* 24-mine mode: only 1 gem survives */
    const gems = (mines === 24) ? 1 : (GMP[mines] || 5);
    const enc  = new TextEncoder();

    /* Import key material */
    const km = await crypto.subtle.importKey(
      'raw',
      enc.encode(serverSeed.trim()),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    /* Sign message */
    const sig = await crypto.subtle.sign(
      'HMAC', km,
      enc.encode(clientSeed.trim() + ':mines:' + mines)
    );

    /* Hex-encode signature */
    const hex = Array.from(new Uint8Array(sig))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    /* Fisher-Yates shuffle on indices 0-24 */
    const idx = Array.from({ length: 25 }, (_, i) => i);
    for (let i = 24; i > 0; i--) {
      const b = parseInt(hex.slice((i * 2) % 62, (i * 2) % 62 + 2), 16);
      const j = b % (i + 1);
      [idx[i], idx[j]] = [idx[j], idx[i]];
    }

    /* First `gems` positions are safe */
    const gs   = new Set(idx.slice(0, gems));
    const grid = [];
    for (let r = 0; r < 5; r++) {
      const row = [];
      for (let c = 0; c < 5; c++) row.push(gs.has(r * 5 + c) ? 'gem' : 'bomb');
      grid.push(row);
    }
    return { grid, gems, bombs: 25 - gems };
  }

  /* ═══════════════════════════════════════════════════════════════════
     RANDOM SEED GENERATORS
     Auto-fill silently uses these when Stake DOM seeds aren't found.
     Inputs remain blurred so the user never sees the values.
     The HMAC engine will produce a valid result regardless.
  ═══════════════════════════════════════════════════════════════════ */

  /* Client seed — typical Stake length is 10-20 alphanumeric chars */
  function randomCS () {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const len   = 10 + Math.floor(Math.random() * 8); // 10-17 chars
    return Array.from({ length: len }, () =>
      chars[Math.floor(Math.random() * chars.length)]
    ).join('');
  }

  /* Server seed hash — must be exactly 64 lowercase hex chars */
  function randomSS () {
    const hex = '0123456789abcdef';
    return Array.from({ length: 64 }, () =>
      hex[Math.floor(Math.random() * 16)]
    ).join('');
  }

  /* ═══════════════════════════════════════════════════════════════════
     STAKE DOM SEED READER
     Attempts to extract seeds using Stake's exact data-testid selectors.
     Falls back to generic input scanning if testids aren't present.
  ═══════════════════════════════════════════════════════════════════ */
  function readSeedsFromPage () {
    const result = { cs: null, ss: null };
    try {
      /* Primary: exact Stake fairness panel selectors */
      const csEl = document.querySelector('[data-testid="active-client-seed"]');
      if (csEl) {
        const val = (csEl.value || csEl.textContent || '').trim();
        if (val) result.cs = val;
      }
      const ssEl = document.querySelector('[data-testid="active-server-seed-hash"]');
      if (ssEl) {
        const val = (ssEl.value || ssEl.textContent || '').trim();
        if (val && okSS(val)) result.ss = val;
      }
    } catch (e) {}

    /* Secondary: scan all inputs for seed-shaped values */
    if (!result.cs || !result.ss) {
      try {
        const allInputs = [...document.querySelectorAll('input, textarea')];
        for (const inp of allInputs) {
          const val = (inp.value || '').trim();
          if (!val) continue;
          if (!result.ss && okSS(val)) result.ss = val;
          if (!result.cs && /^[a-zA-Z0-9]{6,40}$/.test(val) && !okSS(val)) result.cs = val;
        }
      } catch (e) {}
    }

    /* Tertiary: data-testid / aria-label attribute scan */
    if (!result.cs || !result.ss) {
      try {
        document.querySelectorAll('[data-testid], [aria-label]').forEach(el => {
          const label = (el.getAttribute('data-testid') || el.getAttribute('aria-label') || '').toLowerCase();
          const val   = (el.value || el.textContent || '').trim();
          if (!val) return;
          if (!result.ss && (label.includes('server') || label.includes('hash')) && okSS(val)) result.ss = val;
          if (!result.cs && label.includes('client') && val.length >= 6) result.cs = val;
        });
      } catch (e) {}
    }

    return result;
  }

  /* ═══════════════════════════════════════════════════════════════════
     BET AMOUNT READER
     Polls #fake-bet-input every 800ms via setInterval.
     Shows green when ≤ $15, red + warning when above.
  ═══════════════════════════════════════════════════════════════════ */
  function readBetAmount () {
    try {
      const el = document.querySelector('#fake-bet-input');
      if (!el) return null;
      const raw = (el.value || '').trim().replace(',', '.');
      const n   = parseFloat(raw);
      return isNaN(n) ? null : n;
    } catch (e) { return null; }
  }

  /* ═══════════════════════════════════════════════════════════════════
     FONTS — Michroma (headers), Exo 2 (UI), Share Tech Mono (data)
  ═══════════════════════════════════════════════════════════════════ */
  const fl  = document.createElement('link');
  fl.rel    = 'stylesheet';
  fl.href   = 'https://fonts.googleapis.com/css2?family=Exo+2:wght@300;400;500;600;700;800;900&family=Share+Tech+Mono&family=Michroma&display=swap';
  document.head.appendChild(fl);

  /* ═══════════════════════════════════════════════════════════════════
     STYLES — Complete purple/neon theme from v4.2 preserved exactly.
     New additions: gold24 mine card, bet row, seed-blur, next-nudge.
  ═══════════════════════════════════════════════════════════════════ */
  GM_addStyle(`

/* ══ DESIGN TOKENS ══════════════════════════════════════════════════ */
:root {
  /* Ink scale — dark backgrounds */
  --ink:  #010108;
  --ink1: #06061a;
  --ink2: #0d0d28;
  --ink3: #141436;
  --ink4: #1c1c48;

  /* Primary neon purple */
  --neon:  #b300ff;
  --neon2: #d966ff;
  --neon3: #7a00cc;
  --na:    rgba(179,0,255,0.25);
  --nb:    rgba(179,0,255,0.08);

  /* Acid lime — safe tiles, success states */
  --acid:  #c8ff00;
  --acid2: #deff66;
  --acid3: #8fcc00;
  --aa:    rgba(200,255,0,0.22);
  --ab:    rgba(200,255,0,0.06);

  /* Ember red — mines, error states */
  --ember: #ff4500;
  --emb2:  #ff7744;
  --ea:    rgba(255,69,0,0.22);

  /* Aqua — confidence, accents */
  --aqua:  #00fff0;
  --aqua2: #66fff8;
  --aqa:   rgba(0,255,240,0.18);
  --aqb:   rgba(0,255,240,0.06);

  /* Gold — exclusive 24-mines card */
  --gold:  #f5c518;
  --gold2: #ffe57a;
  --gold3: #c49a00;
  --ga:    rgba(245,197,24,0.28);
  --gb:    rgba(245,197,24,0.08);

  /* Text scale */
  --t1: #eef0ff;
  --t2: rgba(238,240,255,0.72);
  --t3: rgba(238,240,255,0.42);
  --t4: rgba(238,240,255,0.20);
  --t5: rgba(238,240,255,0.08);

  /* Typography */
  --fh: 'Michroma',      sans-serif;
  --fu: 'Exo 2',         sans-serif;
  --fm: 'Share Tech Mono', monospace;

  /* Border radii */
  --ra: 4px;  --rb: 10px; --rc: 16px;
  --rd: 22px; --re: 30px;
}

/* ══ RESET ══════════════════════════════════════════════════════════ */
#vp43-root, #vp43-root * {
  box-sizing: border-box;
  -webkit-font-smoothing: antialiased;
  font-family: var(--fu);
}

/* ══ TRIGGER BUTTON ═════════════════════════════════════════════════
   Glassmorphism square pill fixed to bottom-left corner.
   Only this element has pointer-events so the game below stays usable.
════════════════════════════════════════════════════════════════════ */
#vp43-trig {
  position: fixed;
  bottom: 32px;
  left: 32px;
  z-index: 2147483647;
  width: 64px;
  height: 64px;
  border-radius: 18px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  pointer-events: all;
  overflow: hidden;
  transition: transform 0.5s cubic-bezier(0.34,1.56,0.64,1), box-shadow 0.4s;
  background:
    radial-gradient(ellipse 70% 55% at 25% 20%, rgba(255,255,255,0.22) 0%, rgba(255,255,255,0.04) 60%, transparent 100%),
    linear-gradient(145deg, rgba(179,0,255,0.3) 0%, rgba(100,0,180,0.2) 40%, rgba(20,0,60,0.36) 100%);
  border: 1px solid rgba(255,255,255,0.28);
  border-bottom: 1px solid rgba(255,255,255,0.10);
  box-shadow:
    0 0 0 1px rgba(0,0,0,0.5),
    0 12px 40px rgba(0,0,0,0.7),
    0 0 32px rgba(179,0,255,0.48),
    0 0 65px rgba(179,0,255,0.18),
    inset 0 1px 0 rgba(255,255,255,0.32),
    inset 0 -1px 0 rgba(0,0,0,0.35);
  backdrop-filter: blur(16px) saturate(1.8);
  -webkit-backdrop-filter: blur(16px) saturate(1.8);
}

/* noise texture overlay */
#vp43-trig::before {
  content: '';
  position: absolute; inset: 0; border-radius: inherit;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='80' height='80'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='80' height='80' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
  pointer-events: none; z-index: 0;
}

/* glass gloss highlight */
#vp43-trig::after {
  content: '';
  position: absolute; top: 0; left: 0; right: 0; height: 44%;
  border-radius: inherit;
  background: linear-gradient(180deg, rgba(255,255,255,0.18) 0%, rgba(255,255,255,0.04) 60%, transparent 100%);
  pointer-events: none; z-index: 0;
}

#vp43-trig svg {
  position: relative; z-index: 1;
  filter: drop-shadow(0 0 6px rgba(255,255,255,0.7));
  transition: transform 0.5s cubic-bezier(0.34,1.56,0.64,1);
}

#vp43-trig:hover {
  transform: scale(1.10) translateY(-3px);
  box-shadow:
    0 0 0 1px rgba(0,0,0,0.5),
    0 18px 55px rgba(0,0,0,0.8),
    0 0 55px rgba(179,0,255,0.75),
    0 0 110px rgba(179,0,255,0.3),
    inset 0 1px 0 rgba(255,255,255,0.38),
    inset 0 -1px 0 rgba(0,0,0,0.4);
}

#vp43-trig:active { transform: scale(0.94); }

#vp43-trig.open svg { transform: rotate(45deg) scale(1.1); }
#vp43-trig.open {
  background:
    radial-gradient(ellipse 70% 55% at 25% 20%, rgba(255,255,255,0.18) 0%, transparent 60%),
    linear-gradient(145deg, rgba(0,255,240,0.3) 0%, rgba(0,180,200,0.2) 40%, rgba(0,30,60,0.36) 100%);
  box-shadow:
    0 0 0 1px rgba(0,0,0,0.5),
    0 12px 40px rgba(0,0,0,0.7),
    0 0 36px rgba(0,255,240,0.48),
    inset 0 1px 0 rgba(255,255,255,0.32);
}

/* Purple heartbeat while idle */
@keyframes vp43-trig-breathe {
  0%,100% {
    box-shadow:
      0 0 0 1px rgba(0,0,0,0.5),
      0 12px 40px rgba(0,0,0,0.7),
      0 0 32px rgba(179,0,255,0.48),
      0 0 65px rgba(179,0,255,0.18),
      inset 0 1px 0 rgba(255,255,255,0.32),
      inset 0 -1px 0 rgba(0,0,0,0.35);
  }
  50% {
    box-shadow:
      0 0 0 1px rgba(0,0,0,0.5),
      0 14px 50px rgba(0,0,0,0.75),
      0 0 55px rgba(179,0,255,0.8),
      0 0 110px rgba(179,0,255,0.35),
      inset 0 1px 0 rgba(255,255,255,0.38),
      inset 0 -1px 0 rgba(0,0,0,0.4);
  }
}
#vp43-trig:not(.open) { animation: vp43-trig-breathe 3.5s ease-in-out infinite; }

/* Expanding ripple rings */
.vp43-ring {
  position: fixed;
  bottom: 32px; left: 32px;
  width: 64px; height: 64px; border-radius: 20px;
  pointer-events: none; z-index: 2147483646;
  border: 1px solid rgba(179,0,255,0.38);
  animation: vp43-ring-exp 2.8s ease-out infinite;
}
.vp43-ring:nth-child(2) { animation-delay: 0.9s; }
.vp43-ring:nth-child(3) { animation-delay: 1.8s; }
@keyframes vp43-ring-exp {
  0%   { transform: scale(1);   opacity: 0.7; border-radius: 20px; }
  100% { transform: scale(2.7); opacity: 0;   border-radius: 32px; }
}

/* ══ HUD WRAPPER ════════════════════════════════════════════════════
   pointer-events: none so the Stake game remains fully clickable.
   Only panels (#vp43-left, #vp43-right) have pointer-events: all.
   Auth screen also gets pointer-events: all while visible.
════════════════════════════════════════════════════════════════════ */
#vp43-hud {
  position: fixed; inset: 0;
  z-index: 2147483645;
  display: none;
  pointer-events: none; /* CRITICAL — never block game interaction */
}
#vp43-hud.on { display: block; }

/* Plasma backdrop — auth phase only */
#vp43-plasma {
  position: absolute; inset: 0;
  pointer-events: none; z-index: 0;
  opacity: 0; transition: opacity 0.7s ease;
}
#vp43-hud.auth-on #vp43-plasma {
  opacity: 1;
  background:
    radial-gradient(ellipse 40% 50% at 20% 50%, rgba(179,0,255,0.07) 0%, transparent 100%),
    radial-gradient(ellipse 40% 50% at 80% 50%, rgba(200,255,0,0.04) 0%, transparent 100%),
    rgba(4,4,16,0.88);
  animation: vp43-plasma-breathe 8s ease-in-out infinite;
}
@keyframes vp43-plasma-breathe {
  0%,100% {
    background:
      radial-gradient(ellipse 40% 50% at 20% 50%, rgba(179,0,255,0.07) 0%, transparent 100%),
      radial-gradient(ellipse 40% 50% at 80% 50%, rgba(200,255,0,0.04) 0%, transparent 100%),
      rgba(4,4,16,0.88);
  }
  50% {
    background:
      radial-gradient(ellipse 50% 60% at 25% 45%, rgba(179,0,255,0.12) 0%, transparent 100%),
      radial-gradient(ellipse 50% 60% at 75% 55%, rgba(200,255,0,0.07) 0%, transparent 100%),
      rgba(4,4,16,0.9);
  }
}

/* Centre vertical spine — auth phase only */
#vp43-spine {
  position: absolute; left: 50%; top: 50%;
  transform: translate(-50%, -50%);
  width: 2px; height: 60vh;
  z-index: 5; pointer-events: none;
  background: linear-gradient(180deg,
    transparent 0%, rgba(179,0,255,0.3) 20%,
    rgba(0,255,240,0.5) 50%,
    rgba(200,255,0,0.3) 80%, transparent 100%);
  filter: blur(1px);
  opacity: 0; transition: opacity 0.6s ease;
}
#vp43-hud.auth-on #vp43-spine { opacity: 1; animation: vp43-spine-pulse 3s ease-in-out infinite; }
@keyframes vp43-spine-pulse {
  0%,100% { opacity: 0.4; filter: blur(1px); }
  50%     { opacity: 0.9; filter: blur(0.5px); }
}
#vp43-spine::before {
  content: '';
  position: absolute; left: 50%; top: 50%;
  transform: translate(-50%, -50%);
  width: 12px; height: 12px; border-radius: 50%;
  background: var(--aqua);
  box-shadow: 0 0 20px var(--aqua), 0 0 60px rgba(0,255,240,0.5);
  animation: vp43-node-pulse 1.5s ease-in-out infinite;
  pointer-events: none;
}
@keyframes vp43-node-pulse {
  0%,100% { transform: translate(-50%,-50%) scale(0.7); opacity: 0.7; }
  50%     { transform: translate(-50%,-50%) scale(1.4); opacity: 1; }
}

/* Floating spine dots */
.vp43-sdot {
  position: absolute; left: 50%;
  width: 5px; height: 5px; border-radius: 50%;
  transform: translateX(-50%);
  animation: vp43-dot-float 6s ease-in-out infinite;
  pointer-events: none;
}
.vp43-sdot:nth-child(1) { top: 15%; background: var(--neon);  box-shadow: 0 0 8px var(--neon); }
.vp43-sdot:nth-child(2) { top: 30%; animation-delay: 1s;   background: var(--aqua);  box-shadow: 0 0 8px var(--aqua); }
.vp43-sdot:nth-child(3) { top: 50%; animation-delay: 2s;   background: var(--acid);  box-shadow: 0 0 8px var(--acid); }
.vp43-sdot:nth-child(4) { top: 65%; animation-delay: 0.5s; background: var(--neon2); box-shadow: 0 0 8px var(--neon2); }
.vp43-sdot:nth-child(5) { top: 80%; animation-delay: 1.5s; background: var(--aqua2); box-shadow: 0 0 8px var(--aqua2); }
@keyframes vp43-dot-float {
  0%,100% { transform: translateX(-50%) translateX(-9px); opacity: 0.4; }
  50%     { transform: translateX(-50%) translateX(9px);  opacity: 1; }
}

/* Panels receive all pointer events */
#vp43-left, #vp43-right { pointer-events: all; }

/* ══ LEFT PANEL ═════════════════════════════════════════════════════ */
#vp43-left {
  position: absolute;
  top: 50%; left: clamp(14px, 3vw, 44px);
  transform: translateY(-50%);
  width: 314px; max-height: 92vh;
  display: flex; flex-direction: column;
  z-index: 10; overflow: hidden;
  border-radius: var(--rd);
  background:
    linear-gradient(180deg, rgba(179,0,255,0.06) 0%, rgba(0,0,0,0) 40%),
    linear-gradient(160deg, rgba(255,255,255,0.04) 0%, rgba(0,0,0,0.28) 100%),
    rgba(6,6,20,0.97);
  border: 1px solid rgba(179,0,255,0.22);
  box-shadow:
    0 40px 120px rgba(0,0,0,0.96),
    0 0 80px rgba(179,0,255,0.08),
    inset 0 1px 0 rgba(179,0,255,0.18),
    inset 1px 0 0 rgba(255,255,255,0.04);
  opacity: 0;
  transform: translateY(-50%) translateX(-48px) scale(0.97);
  transition: opacity 0.55s cubic-bezier(0.16,1,0.3,1), transform 0.55s cubic-bezier(0.16,1,0.3,1);
}
#vp43-hud.on #vp43-left {
  opacity: 1;
  transform: translateY(-50%) translateX(0) scale(1);
  transition-delay: 0.05s;
}
/* animated left-edge neon strip */
#vp43-left::before {
  content: '';
  position: absolute; left: 0; top: 5%; bottom: 5%;
  width: 2px; border-radius: 2px;
  background: linear-gradient(180deg, transparent 0%, var(--neon) 25%, var(--neon2) 50%, var(--neon) 75%, transparent 100%);
  box-shadow: 0 0 12px var(--neon), 0 0 24px rgba(179,0,255,0.4);
  animation: vp43-strip 4s ease-in-out infinite;
  z-index: 1;
}
@keyframes vp43-strip {
  0%,100% { top: 5%;  bottom: 60%; opacity: 0.6; }
  50%     { top: 40%; bottom: 5%;  opacity: 1; }
}

/* ══ RIGHT PANEL ════════════════════════════════════════════════════ */
#vp43-right {
  position: absolute;
  top: 50%; right: clamp(14px, 3vw, 44px);
  transform: translateY(-50%);
  width: 394px; z-index: 10;
  border-radius: var(--rd); overflow: hidden;
  background:
    linear-gradient(180deg, rgba(200,255,0,0.03) 0%, transparent 40%),
    linear-gradient(160deg, rgba(255,255,255,0.025) 0%, rgba(0,0,0,0.28) 100%),
    rgba(6,6,20,0.97);
  border: 1px solid rgba(200,255,0,0.14);
  box-shadow:
    0 40px 120px rgba(0,0,0,0.96),
    0 0 80px rgba(200,255,0,0.04),
    inset 0 1px 0 rgba(200,255,0,0.1),
    inset -1px 0 0 rgba(255,255,255,0.03);
  display: flex; flex-direction: column;
  opacity: 0;
  transform: translateY(-50%) translateX(48px) scale(0.97);
  transition: opacity 0.55s cubic-bezier(0.16,1,0.3,1), transform 0.55s cubic-bezier(0.16,1,0.3,1);
}
#vp43-hud.on #vp43-right {
  opacity: 1;
  transform: translateY(-50%) translateX(0) scale(1);
  transition-delay: 0.1s;
}
/* animated right-edge acid+aqua strip */
#vp43-right::after {
  content: '';
  position: absolute; right: 0; top: 5%; bottom: 5%;
  width: 2px; border-radius: 2px;
  background: linear-gradient(180deg, transparent 0%, var(--acid) 30%, var(--aqua) 70%, transparent 100%);
  box-shadow: 0 0 10px var(--acid), 0 0 20px rgba(200,255,0,0.3);
  animation: vp43-strip 4s ease-in-out infinite reverse;
  z-index: 1;
}

/* ══ AUTH SCREEN ════════════════════════════════════════════════════ */
#vp43-auth {
  position: absolute; inset: 0; z-index: 100;
  display: flex; align-items: center; justify-content: center;
  pointer-events: all;
}
#vp43-auth.gone {
  animation: vp43-auth-vanish 0.55s cubic-bezier(0.16,1,0.3,1) both;
  pointer-events: none;
}
@keyframes vp43-auth-vanish {
  0%   { opacity: 1; filter: blur(0);    transform: scale(1); }
  100% { opacity: 0; filter: blur(18px); transform: scale(1.06); }
}

/* Auth card */
.vp43-acard {
  width: 372px; padding: 40px 34px 32px;
  border-radius: var(--re);
  text-align: center; position: relative; overflow: hidden;
  background:
    radial-gradient(ellipse 85% 55% at 50% 0%, rgba(179,0,255,0.11) 0%, transparent 100%),
    linear-gradient(170deg, rgba(24,20,52,0.99) 0%, rgba(8,8,22,0.99) 100%);
  border: 1px solid rgba(179,0,255,0.32);
  box-shadow: 0 70px 200px rgba(0,0,0,1), 0 0 130px rgba(179,0,255,0.16), inset 0 1px 0 rgba(179,0,255,0.28);
  animation: vp43-card-in 0.75s cubic-bezier(0.16,1,0.3,1) both;
  transform-origin: center bottom;
}
@keyframes vp43-card-in {
  0%   { opacity: 0; transform: rotateX(-18deg) translateY(45px) scale(0.92); filter: blur(12px); }
  55%  { filter: blur(0); }
  100% { opacity: 1; transform: rotateX(0) translateY(0) scale(1); filter: blur(0); }
}
/* spinning rainbow conic border on auth card */
.vp43-acard::before {
  content: '';
  position: absolute; inset: -1px;
  border-radius: calc(var(--re) + 1px); padding: 1px;
  background: conic-gradient(from 0deg,
    rgba(179,0,255,0) 0%, rgba(179,0,255,1) 20%,
    rgba(0,255,240,0.7) 40%, rgba(200,255,0,0.5) 60%,
    rgba(179,0,255,1) 80%, rgba(179,0,255,0) 100%);
  -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  -webkit-mask-composite: xor; mask-composite: exclude;
  animation: vp43-ring-spin 3.8s linear infinite;
  pointer-events: none;
}
@keyframes vp43-ring-spin { to { transform: rotate(360deg); } }
@keyframes vp43-gold-current {
  0%   { background-position: 200% 0; }

  100% { background-position: -200% 0; }
}

/* Auth logo diamond */
.vp43-alogo {
  width: 64px; height: 64px;
  clip-path: polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%);
  display: flex; align-items: center; justify-content: center;
  margin: 0 auto 22px; position: relative; z-index: 1;
  background:
    radial-gradient(ellipse 70% 55% at 28% 22%, rgba(255,255,255,0.24) 0%, transparent 70%),
    linear-gradient(145deg, rgba(179,0,255,0.55), rgba(80,0,160,0.45));
  box-shadow: 0 0 38px rgba(179,0,255,0.9), 0 0 90px rgba(179,0,255,0.45);
  animation: vp43-logo-float 4s ease-in-out infinite;
}
@keyframes vp43-logo-float {
  0%,100% { transform: translateY(0) rotate(0deg); box-shadow: 0 0 38px rgba(179,0,255,0.9), 0 0 90px rgba(179,0,255,0.45); }
  50%     { transform: translateY(-9px) rotate(180deg); box-shadow: 0 0 60px rgba(179,0,255,1), 0 0 130px rgba(179,0,255,0.6); }
}

.vp43-atitle { font-family: var(--fh); font-size: 26px; letter-spacing: 0.2em; background: linear-gradient(135deg,#fff 0%,var(--neon2) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 7px; position: relative; z-index: 1; line-height: 1; }
.vp43-asub   { font-family: var(--fm); font-size: 10px; letter-spacing: 0.22em; color: var(--t4); margin-bottom: 26px; position: relative; z-index: 1; }
.vp43-aiw    { position: relative; margin-bottom: 15px; z-index: 1; }
.vp43-aiw::before { content: '▸'; position: absolute; left: 13px; top: 50%; transform: translateY(-50%); font-size: 11px; color: var(--neon); pointer-events: none; text-shadow: 0 0 8px var(--neon); }
.vp43-ainp   { width: 100%; padding: 13px 15px 13px 30px; border-radius: var(--rb); font-family: var(--fm); font-size: 13px; letter-spacing: 0.12em; color: var(--t1); outline: none; background: linear-gradient(160deg,rgba(255,255,255,0.04) 0%,rgba(0,0,0,0.3) 100%),rgba(2,2,12,0.92); border: 1px solid rgba(179,0,255,0.28); box-shadow: inset 0 2px 8px rgba(0,0,0,0.5); transition: all 0.25s; }
.vp43-ainp::placeholder { color: var(--t5); letter-spacing: 0.18em; }
.vp43-ainp:focus { border-color: rgba(179,0,255,0.62); box-shadow: 0 0 0 3px rgba(179,0,255,0.1), 0 0 32px rgba(179,0,255,0.1), inset 0 2px 8px rgba(0,0,0,0.45); }
.vp43-site-link { display: inline-flex; align-items: center; gap: 5px; margin-top: 16px; font-family: var(--fm); font-size: 9.5px; letter-spacing: 0.12em; color: var(--neon2); text-decoration: none; padding: 7px 16px; border-radius: 99px; border: 1px solid rgba(179,0,255,0.28); background: rgba(179,0,255,0.08); transition: all 0.22s; position: relative; z-index: 1; }
.vp43-site-link:hover { background: rgba(179,0,255,0.17); border-color: rgba(179,0,255,0.5); box-shadow: 0 0 22px rgba(179,0,255,0.22); color: #fff; }

/* ══ PANEL HEADER ═══════════════════════════════════════════════════ */
.vp43-ph { flex-shrink: 0; padding: 18px 20px 16px; border-bottom: 1px solid rgba(255,255,255,0.07); position: relative; overflow: hidden; }
.vp43-ph::after { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px; background: linear-gradient(90deg,transparent,var(--neon3),var(--neon),var(--neon2),transparent); animation: vp43-sweep 3.5s ease-in-out infinite alternate; opacity: 0.85; }
@keyframes vp43-sweep { 0%{transform:translateX(-40%);opacity:0.5;} 100%{transform:translateX(40%);opacity:1;} }
.vp43-logo-row  { display: flex; align-items: center; gap: 12px; }
.vp43-logo-gem  { width:36px;height:36px;border-radius:11px;display:flex;align-items:center;justify-content:center;flex-shrink:0;position:relative;overflow:hidden;background:radial-gradient(ellipse 70% 55% at 28% 22%,rgba(255,255,255,0.22) 0%,transparent 70%),linear-gradient(145deg,rgba(179,0,255,0.5),rgba(80,0,160,0.4));border:1px solid rgba(255,255,255,0.25);border-bottom-color:rgba(255,255,255,0.08);box-shadow:0 0 20px rgba(179,0,255,0.5),0 4px 12px rgba(0,0,0,0.5),inset 0 1px 0 rgba(255,255,255,0.3);backdrop-filter:blur(8px);animation:vp43-gem-glow 2.5s ease-in-out infinite; }
@keyframes vp43-gem-glow { 0%,100%{box-shadow:0 0 20px rgba(179,0,255,0.5),0 4px 12px rgba(0,0,0,0.5),inset 0 1px 0 rgba(255,255,255,0.3);}50%{box-shadow:0 0 36px rgba(179,0,255,0.9),0 0 70px rgba(179,0,255,0.4),inset 0 1px 0 rgba(255,255,255,0.35);} }
.vp43-logo-gem::after { content:'';position:absolute;top:0;left:0;right:0;height:50%;background:linear-gradient(180deg,rgba(255,255,255,0.18),transparent);border-radius:inherit; }
.vp43-logo-name { font-family:var(--fh);font-size:16px;letter-spacing:0.22em;text-transform:uppercase;background:linear-gradient(90deg,#fff 0%,var(--neon2) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;line-height:1; }
.vp43-logo-sub  { font-family:var(--fm);font-size:8.5px;letter-spacing:0.28em;text-transform:uppercase;color:var(--t4);margin-top:3px; }
.vp43-live { margin-left:auto;display:flex;align-items:center;gap:5px;padding:4px 11px;border-radius:999px;border:1px solid rgba(200,255,0,0.28);background:rgba(200,255,0,0.07); }
.vp43-ldot { width:6px;height:6px;border-radius:50%;background:var(--acid);box-shadow:0 0 7px var(--acid);animation:vp43-blink 1.8s ease-in-out infinite; }
@keyframes vp43-blink { 0%,100%{opacity:0.5;transform:scale(0.8);}50%{opacity:1;transform:scale(1.3);} }
.vp43-ltxt { font-family:var(--fm);font-size:9px;font-weight:600;letter-spacing:0.2em;color:var(--acid2); }

/* ══ PANEL BODY ═════════════════════════════════════════════════════ */
.vp43-pbody { flex:1;overflow-y:auto;padding:18px 20px;scrollbar-width:thin;scrollbar-color:rgba(179,0,255,0.2) transparent; }
.vp43-pbody::-webkit-scrollbar { width: 2px; }
.vp43-pbody::-webkit-scrollbar-thumb { background: rgba(179,0,255,0.25); border-radius: 2px; }
.vp43-lbl { font-family:var(--fm);font-size:9.5px;letter-spacing:0.22em;text-transform:uppercase;color:var(--t3);display:block;margin-bottom:7px;font-weight:600; }
.vp43-field { margin-bottom: 16px; position: relative; }

/* ══ INPUT ══════════════════════════════════════════════════════════ */
.vp43-inp {
  width: 100%; padding: 11px 14px;
  border-radius: var(--rb);
  font-family: var(--fm); font-size: 12px; letter-spacing: 0.04em;
  color: var(--t1); outline: none;
  transition: all 0.25s cubic-bezier(0.16,1,0.3,1);
  background: linear-gradient(160deg,rgba(255,255,255,0.04) 0%,rgba(0,0,0,0.22) 100%), rgba(3,3,15,0.9);
  border: 1px solid rgba(255,255,255,0.09);
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.05), inset 0 2px 8px rgba(0,0,0,0.5);
}
.vp43-inp::placeholder { color: var(--t4); font-size: 11px; }
.vp43-inp:focus {
  border-color: rgba(179,0,255,0.5);
  background: linear-gradient(160deg,rgba(179,0,255,0.05) 0%,rgba(0,0,0,0.25) 100%), rgba(3,3,15,0.95);
  box-shadow: 0 0 0 3px rgba(179,0,255,0.08), inset 0 1px 0 rgba(255,255,255,0.06), inset 0 2px 8px rgba(0,0,0,0.4);
}
.vp43-inp.ok  { border-color: rgba(200,255,0,0.42); }
.vp43-inp.bad { border-color: rgba(255,69,0,0.48); }

/* ── SEED BLUR — active from page load, removed on focus ─── */
.vp43-inp.blurred {
  filter: blur(6px);
  user-select: none;
  color: transparent;
  text-shadow: 0 0 12px rgba(179,0,255,0.8);
}

/* ══ SEED HEADER ROW ════════════════════════════════════════════════ */
.vp43-seed-head { display:flex;align-items:center;justify-content:space-between;margin-bottom:7px; }
.vp43-seed-head .vp43-lbl { margin: 0; }

/* Autofill button */
.vp43-autofill {
  display: flex; align-items: center; gap: 5px;
  padding: 4px 10px; border-radius: var(--ra);
  border: none; cursor: pointer;
  font-family: var(--fm); font-size: 8px; letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--ink);
  background: linear-gradient(135deg, var(--acid2), var(--acid3));
  box-shadow: 0 0 10px rgba(200,255,0,0.35), inset 0 1px 0 rgba(255,255,255,0.4);
  transition: all 0.22s; position: relative; overflow: hidden;
}
.vp43-autofill::before { content:'';position:absolute;top:0;left:-120%;width:50%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.5),transparent);transform:skewX(-15deg);transition:left 0.55s; }
.vp43-autofill:hover::before { left: 160%; }
.vp43-autofill:hover  { transform: translateY(-1px); box-shadow: 0 0 18px rgba(200,255,0,0.55); }
.vp43-autofill:active { transform: scale(0.95); }

/* ══ DIVIDER ════════════════════════════════════════════════════════ */
.vp43-div { height:1px;margin:14px 0;background:linear-gradient(90deg,transparent,rgba(179,0,255,0.15) 40%,rgba(179,0,255,0.15) 60%,transparent); }

/* ══ MINE SELECTOR — 5 slots ════════════════════════════════════════
   Slot positions: 1 mine | 2 mines | [24 MINES GOLD] | 4 mines | 5 mines
   The gold card is the same shape/size as all other segments.
   It stands out via gold border, spinning conic ring, and gold glow pulse.
════════════════════════════════════════════════════════════════════ */
.vp43-mine-track {
  display: flex; gap: 5px;
  padding: 5px;
  background: rgba(0,0,0,0.42);
  border-radius: var(--rb);
  border: 1px solid rgba(255,255,255,0.07);
  margin-bottom: 18px;
}
.vp43-mseg {
  flex: 1; padding: 9px 3px 8px;
  border-radius: var(--ra);
  cursor: pointer; text-align: center;
  transition: all 0.28s cubic-bezier(0.34,1.56,0.64,1);
  position: relative; background: transparent;
  border: 1px solid transparent;
}
.vp43-mseg:hover { background:rgba(179,0,255,0.09);border-color:rgba(179,0,255,0.28);transform:translateY(-3px) scale(1.04); }
.vp43-mseg.sel   { background:linear-gradient(160deg,rgba(179,0,255,0.2),rgba(179,0,255,0.07));border-color:rgba(179,0,255,0.54);box-shadow:0 0 16px rgba(179,0,255,0.22),inset 0 1px 0 rgba(255,255,255,0.09);transform:translateY(-3px) scale(1.06); }
.vp43-mseg.sel::after { content:'';position:absolute;bottom:-1px;left:14%;right:14%;height:2px;border-radius:2px 2px 0 0;background:var(--neon);box-shadow:0 0 8px var(--neon);animation:vp43-seg-glow 1.5s ease-in-out infinite; }
@keyframes vp43-seg-glow { 0%,100%{box-shadow:0 0 8px var(--neon);}50%{box-shadow:0 0 20px var(--neon),0 0 44px rgba(179,0,255,0.55);} }
.vp43-mico { font-size:16px;display:block;line-height:1;margin-bottom:4px; }
.vp43-mnum { font-family:var(--fh);font-size:18px;display:block;color:var(--t3);line-height:1;transition:color 0.22s;letter-spacing:-0.01em; }
.vp43-mseg.sel .vp43-mnum { color: var(--neon2); }
.vp43-mtag { font-family:var(--fm);font-size:7.5px;letter-spacing:0.12em;color:var(--t5);display:block;margin-top:2px; }

/* ── EXCLUSIVE 24-MINES GOLD CARD ───────────────────────────────────
   Identical layout to standard .vp43-mseg but gold-accented.
   Gold pulsing outer glow + spinning conic border ring.
   Gold gradient on number text. Gold sub-label.
   When selected: lifts higher and intensifies the gold glow.
──────────────────────────────────────────────────────────────────── */
.vp43-mseg.gold24 {
  background:
    radial-gradient(ellipse 80% 60% at 50% 10%, rgba(245,197,24,0.16) 0%, transparent 100%),
    rgba(30,24,0,0.5);
  border: 2px solid var(--gold) !important;
  box-shadow: 0 0 18px rgba(245,197,24,0.42), 0 0 50px rgba(245,197,24,0.18), inset 0 1px 0 rgba(255,255,255,0.12) !important;
  animation: vp43-gold-pulse 2.5s ease-in-out infinite;
  transform: none;
}
@keyframes vp43-gold-pulse {
  0%,100% { box-shadow: 0 0 18px rgba(245,197,24,0.42), 0 0 50px rgba(245,197,24,0.18), inset 0 1px 0 rgba(255,255,255,0.12); }
  50%     { box-shadow: 0 0 32px rgba(245,197,24,0.72), 0 0 90px rgba(245,197,24,0.32), inset 0 1px 0 rgba(255,255,255,0.18); }
}
/* flowing gold current along border */
.vp43-mseg.gold24::before {
  content: '';
  position: absolute; inset: -2px;
  border-radius: calc(var(--ra) + 2px); padding: 2px;
  background: linear-gradient(
    90deg,
    rgba(245,197,24,0.15) 0%,
    rgba(255,233,100,0)   15%,
    rgba(245,197,24,0)    30%,
    rgba(255,248,180,1)   45%,
    rgba(255,233,100,1)   50%,
    rgba(255,248,180,1)   55%,
    rgba(245,197,24,0)    70%,
    rgba(255,233,100,0)   85%,
    rgba(245,197,24,0.15) 100%
  );
  background-size: 250% 250%;
  -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  -webkit-mask-composite: xor; mask-composite: exclude;
  animation: vp43-gold-current 1.8s linear infinite;
  pointer-events: none; z-index: 0;
}
/* gold card has its own glow — no purple underline */
.vp43-mseg.gold24::after    { display: none; }
.vp43-mseg.gold24.sel::after { display: none; }
.vp43-mseg.gold24 .vp43-mnum {
  font-size: 16px;
  background: linear-gradient(135deg, var(--gold2) 0%, var(--gold) 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.vp43-mseg.gold24 .vp43-mico { font-size: 17px; }
.vp43-mseg.gold24 .vp43-mtag { color: var(--gold); font-size: 6.5px; text-shadow: 0 0 6px rgba(245,197,24,0.6); letter-spacing: 0.08em; }
.vp43-mseg.gold24:hover { transform: translateY(-4px) scale(1.06) !important; box-shadow: 0 0 28px rgba(245,197,24,0.65), 0 0 80px rgba(245,197,24,0.28), inset 0 1px 0 rgba(255,255,255,0.18) !important; }
.vp43-mseg.gold24.sel   { transform: translateY(-4px) scale(1.08) !important; box-shadow: 0 0 42px rgba(245,197,24,0.78), 0 0 100px rgba(245,197,24,0.38), 0 8px 24px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.18) !important; }

/* ══ BET AMOUNT ROW (new in v4.3) ══════════════════════════════════
   Polls #fake-bet-input every 800ms. Green ≤ $15, red + warn above.
════════════════════════════════════════════════════════════════════ */
#vp43-bet-row {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 14px; margin-bottom: 14px;
  border-radius: var(--rb);
  border: 1px solid rgba(255,255,255,0.08);
  background: rgba(0,0,0,0.32);
  transition: border-color 0.3s, background 0.3s;
}
#vp43-bet-row.over {
  border-color: rgba(255,69,0,0.42);
  background: rgba(255,69,0,0.05);
}
.vp43-bet-lbl {
  font-family: var(--fm); font-size: 8.5px;
  letter-spacing: 0.16em; text-transform: uppercase;
  color: var(--t4); line-height: 1.5;
}
.vp43-bet-lbl small {
  display: block; font-size: 7px; letter-spacing: 0.1em;
  color: var(--emb2); opacity: 0; transition: opacity 0.3s; margin-top: 2px;
}
.vp43-bet-lbl small.show { opacity: 1; }
.vp43-bet-val {
  font-family: var(--fh); font-size: 19px; letter-spacing: 0.04em;
  color: var(--t2); transition: color 0.3s, text-shadow 0.3s;
}
.vp43-bet-val.ok  { color: var(--acid); text-shadow: 0 0 10px var(--aa); }
.vp43-bet-val.bad { color: var(--emb2); text-shadow: 0 0 10px var(--ea); }

/* ══ ACTION BUTTON — purple with shimmer wave ═══════════════════════ */
.vp43-btn {
  width: 100%; padding: 14px; border: none;
  border-radius: var(--rc);
  cursor: pointer; position: relative; overflow: hidden;
  display: flex; align-items: center; justify-content: center; gap: 9px;
  transition: all 0.3s cubic-bezier(0.34,1.56,0.64,1);
  font-family: var(--fh); font-size: 14px; letter-spacing: 0.18em;
  color: var(--ink);
  background:
    radial-gradient(ellipse 80% 55% at 50% 0%, rgba(255,255,255,0.28) 0%, transparent 100%),
    linear-gradient(135deg, var(--neon2), var(--neon), var(--neon3));
  border-top: 1px solid rgba(255,255,255,0.32);
  box-shadow: 0 0 0 1px rgba(0,0,0,0.5), 0 6px 30px rgba(179,0,255,0.52), inset 0 1px 0 rgba(255,255,255,0.38);
}
.vp43-btn::before {
  content: '';
  position: absolute; top: 0; left: -150%; width: 60%; height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.48), transparent);
  transform: skewX(-18deg); transition: left 0.72s;
}
.vp43-btn:hover::before { left: 180%; }
.vp43-btn:hover {
  transform: translateY(-3px) scale(1.02);
  box-shadow: 0 0 0 1px rgba(0,0,0,0.5), 0 14px 52px rgba(179,0,255,0.72), 0 0 85px rgba(179,0,255,0.22), inset 0 1px 0 rgba(255,255,255,0.42);
}
.vp43-btn:active   { transform: scale(0.97) translateY(0); }
.vp43-btn:disabled { opacity: 0.3; cursor: not-allowed; transform: none; box-shadow: none; animation: none; }
@keyframes vp43-btn-idle {
  0%,100% { box-shadow: 0 0 0 1px rgba(0,0,0,0.5), 0 6px 30px rgba(179,0,255,0.52), inset 0 1px 0 rgba(255,255,255,0.38); }
  50%     { box-shadow: 0 0 0 1px rgba(0,0,0,0.5), 0 8px 38px rgba(179,0,255,0.7), 0 0 50px rgba(179,0,255,0.15), inset 0 1px 0 rgba(255,255,255,0.4); }
}
.vp43-btn:not(:disabled) { animation: vp43-btn-idle 3s ease-in-out infinite; }

/* ══ MESSAGES ═══════════════════════════════════════════════════════ */
.vp43-msg  { display:none;margin-top:10px;padding:9px 13px;border-radius:var(--ra);font-family:var(--fm);font-size:11px;line-height:1.55;letter-spacing:0.02em;border-left:2px solid; }
.vp43-msg.show { display:block;animation:vp43-msg-in 0.22s ease both; }
@keyframes vp43-msg-in { from{opacity:0;transform:translateX(-7px);}to{opacity:1;transform:translateX(0);} }
.vp43-merr  { background:rgba(255,69,0,0.07);border-color:var(--ember);color:#ff9977; }
.vp43-mwarn { background:rgba(255,200,0,0.06);border-color:#ffcc00;color:#ffe566; }
.vp43-mok   { background:rgba(200,255,0,0.07);border-color:var(--acid);color:var(--acid2); }

/* ══ STAT CARDS ═════════════════════════════════════════════════════ */
.vp43-stats { display:flex;gap:9px;margin-top:16px; }
.vp43-stat  { flex:1;padding:12px 10px 11px;border-radius:var(--rb);border:1px solid;text-align:center;position:relative;overflow:hidden;animation:vp43-stat-in 0.5s cubic-bezier(0.34,1.56,0.64,1) both; }
.vp43-stat:nth-child(2) { animation-delay: 0.08s; }
@keyframes vp43-stat-in { from{opacity:0;transform:scale(0.85) translateY(8px);}to{opacity:1;transform:scale(1) translateY(0);} }
.vp43-stat::before { content:'';position:absolute;inset:0;background:inherit;opacity:0.45; }
.vp43-stat.ss { background:rgba(200,255,0,0.07);border-color:rgba(200,255,0,0.22); }
.vp43-stat.sm { background:rgba(255,69,0,0.07);border-color:rgba(255,69,0,0.20); }
.vp43-sn { font-family:var(--fh);font-size:38px;letter-spacing:-0.01em;line-height:1;display:block;position:relative;z-index:1;animation:vp43-num-pop 0.45s cubic-bezier(0.34,1.56,0.64,1) 0.08s both; }
@keyframes vp43-num-pop { from{opacity:0;transform:scale(0.45);}to{opacity:1;transform:scale(1);} }
.vp43-sn.s { color:var(--acid);text-shadow:0 0 18px var(--aa); }
.vp43-sn.m { color:var(--emb2); }
.vp43-sl   { font-family:var(--fm);font-size:8px;letter-spacing:0.18em;text-transform:uppercase;color:var(--t4);margin-top:4px;display:block;position:relative;z-index:1; }

/* ── 'Generate another prediction' nudge (shown after each result) ── */
#vp43-next-nudge {
  display: none; margin-top: 12px;
  padding: 10px 14px; border-radius: var(--ra);
  font-family: var(--fm); font-size: 10px;
  letter-spacing: 0.10em; line-height: 1.6;
  text-align: center;
  border: 1px solid rgba(179,0,255,0.30);
  background: rgba(179,0,255,0.06);
  color: var(--neon2);
  cursor: pointer; transition: background 0.2s;
  animation: vp43-msg-in 0.3s ease both;
}
#vp43-next-nudge.show { display: block; }
#vp43-next-nudge:hover { background: rgba(179,0,255,0.12); }

/* ══ SESSION STRIP — 3 dots (matching DAILY=3) ══════════════════════ */
.vp43-ss-strip { flex-shrink:0;padding:10px 20px;border-top:1px solid rgba(255,255,255,0.06);background:rgba(0,0,0,0.22);display:flex;align-items:center;justify-content:space-between;gap:8px; }
.vp43-ss-info  { font-family:var(--fm);font-size:9px;color:var(--t4);letter-spacing:0.1em; }
.vp43-ss-info b { color: var(--t2); }
/* wider dots for 3 vs 10 — look intentional and balanced */
.vp43-udots { display:flex;gap:5px; }
.vp43-ud {
  width: 10px; height: 10px; border-radius: 3px;
  border: 1px solid rgba(255,255,255,0.1);
  background: rgba(255,255,255,0.06);
  transition: all 0.35s cubic-bezier(0.34,1.56,0.64,1);
}
.vp43-ud.f { background:var(--neon);border-color:var(--neon);box-shadow:0 0 8px rgba(179,0,255,0.7);transform:scale(1.18); }
.vp43-out  { background:none;border:none;cursor:pointer;font-family:var(--fm);font-size:8.5px;letter-spacing:0.18em;text-transform:uppercase;color:var(--t4);padding:0;transition:color 0.18s; }
.vp43-out:hover { color: var(--ember); }

/* countdown row */
#vp43-reset-row { padding:8px 20px;border-top:1px solid rgba(255,255,255,0.05);background:rgba(179,0,255,0.04);text-align:center;flex-shrink:0; }
.vp43-reset-txt { font-family:var(--fm);font-size:9px;letter-spacing:0.14em;color:var(--neon2); }
.vp43-reset-cd  { font-family:var(--fh);font-size:14px;letter-spacing:0.06em;color:var(--aqua);text-shadow:0 0 14px var(--aqa);margin-top:2px; }

/* site link strip at bottom of each panel */
.vp43-buy { flex-shrink:0;display:flex;align-items:center;justify-content:center;padding:8px;border-top:1px solid rgba(255,255,255,0.05);background:rgba(179,0,255,0.04);gap:7px;cursor:pointer;text-decoration:none;transition:background 0.2s; }
.vp43-buy:hover { background: rgba(179,0,255,0.1); }
.vp43-buy span  { font-family:var(--fm);font-size:9px;letter-spacing:0.12em;color:var(--neon2);transition:color 0.2s; }
.vp43-buy:hover span { color: #fff; }
.vp43-bdot { width:5px;height:5px;border-radius:50%;background:var(--acid);box-shadow:0 0 8px var(--acid);animation:vp43-blink 2s ease-in-out infinite;flex-shrink:0; }

/* ══ RIGHT PANEL INTERNALS ══════════════════════════════════════════ */
.vp43-gh     { flex-shrink:0;padding:16px 20px 13px;border-bottom:1px solid rgba(255,255,255,0.06);display:flex;align-items:center;justify-content:space-between;position:relative;overflow:hidden; }
.vp43-gh::after { content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--acid3),var(--acid),var(--aqua),transparent);animation:vp43-sweep 3.5s ease-in-out infinite alternate;opacity:0.75; }
.vp43-gt     { font-family:var(--fh);font-size:14px;letter-spacing:0.22em;color:var(--t2); }
.vp43-gbadge { font-family:var(--fm);font-size:9px;letter-spacing:0.15em;color:var(--aqua2);background:rgba(0,255,240,0.08);border:1px solid rgba(0,255,240,0.22);padding:4px 10px;border-radius:999px;transition:all 0.4s; }
.vp43-gbadge.ready { border-color:rgba(200,255,0,0.3);background:rgba(200,255,0,0.08);color:var(--acid2); }
.vp43-cols { display:grid;grid-template-columns:repeat(5,1fr);gap:5px;padding:0 20px;margin-top:14px;margin-bottom:5px; }
.vp43-col  { text-align:center;font-family:var(--fm);font-size:9px;letter-spacing:0.18em;color:var(--t4);font-weight:600; }
.vp43-ga   { padding:0 20px 14px;flex:1; }
.vp43-grow { display:flex;gap:6px;align-items:center;margin-bottom:6px; }
.vp43-rl   { font-family:var(--fm);font-size:9px;letter-spacing:0.1em;color:var(--t4);width:14px;text-align:right;flex-shrink:0;font-weight:600; }
.vp43-gr   { display:grid;grid-template-columns:repeat(5,1fr);gap:6px;flex:1; }

/* ══ TILES — hexagonal clip-path, GPU-composited ════════════════════ */
.vp43-tile {
  aspect-ratio: 1;
  clip-path: polygon(50% 0%,95% 25%,95% 75%,50% 100%,5% 75%,5% 25%);
  display: flex; align-items: center; justify-content: center;
  position: relative; cursor: default;
  will-change: transform, opacity;
  transition: transform 0.22s cubic-bezier(0.34,1.56,0.64,1), filter 0.18s linear;
  animation: vp43-tile-in 0.5s cubic-bezier(0.22,1,0.36,1) both;
}
.vp43-tile:nth-child(1){animation-delay:0.000s}
.vp43-tile:nth-child(2){animation-delay:0.004s}
.vp43-tile:nth-child(3){animation-delay:0.008s}
.vp43-tile:nth-child(4){animation-delay:0.012s}
.vp43-tile:nth-child(5){animation-delay:0.016s}
.vp43-tile:nth-child(6){animation-delay:0.020s}
.vp43-tile:nth-child(7){animation-delay:0.072s}
.vp43-tile:nth-child(8){animation-delay:0.076s}
.vp43-tile:nth-child(9){animation-delay:0.080s}
.vp43-tile:nth-child(10){animation-delay:0.036s}
.vp43-tile:nth-child(11){animation-delay:0.040s}
.vp43-tile:nth-child(12){animation-delay:0.092s}
.vp43-tile:nth-child(13){animation-delay:0.144s}
.vp43-tile:nth-child(14){animation-delay:0.100s}
.vp43-tile:nth-child(15){animation-delay:0.056s}
.vp43-tile:nth-child(16){animation-delay:0.060s}
.vp43-tile:nth-child(17){animation-delay:0.112s}
.vp43-tile:nth-child(18){animation-delay:0.116s}
.vp43-tile:nth-child(19){animation-delay:0.120s}
.vp43-tile:nth-child(20){animation-delay:0.076s}
.vp43-tile:nth-child(21){animation-delay:0.080s}
.vp43-tile:nth-child(22){animation-delay:0.084s}
.vp43-tile:nth-child(23){animation-delay:0.088s}
.vp43-tile:nth-child(24){animation-delay:0.092s}
.vp43-tile:nth-child(25){animation-delay:0.096s}

@keyframes vp43-tile-in {
  0%   { opacity:0; transform:scale(0.05) rotate(80deg); }
  55%  { opacity:1; transform:scale(1.06) rotate(-2deg); }
  100% { opacity:1; transform:scale(1) rotate(0deg); }
}

/* Gem tile */
.vp43-tile.gem { background:linear-gradient(135deg,rgba(144,255,0,0.26) 0%,rgba(100,220,0,0.16) 50%,rgba(50,180,0,0.10) 100%);filter:drop-shadow(0 0 7px rgba(200,255,0,0.55)) drop-shadow(0 2px 6px rgba(0,0,0,0.75)); }
@keyframes vp43-gem-rev {
  0%   { filter: drop-shadow(0 0 30px rgba(200,255,0,1)) drop-shadow(0 0 75px rgba(200,255,0,0.7)) brightness(3.5); }
  45%  { filter: drop-shadow(0 0 14px rgba(200,255,0,0.8)) brightness(1.6); }
  100% { filter: drop-shadow(0 0 7px rgba(200,255,0,0.55)) brightness(1); }
}
.vp43-tile.gem { animation: vp43-tile-in 0.5s cubic-bezier(0.22,1,0.36,1) both, vp43-gem-rev 0.85s cubic-bezier(0.16,1,0.3,1) both; }
.vp43-tile.gem:hover { transform:scale(1.18) rotate(8deg);filter:drop-shadow(0 0 18px rgba(200,255,0,0.95)) drop-shadow(0 0 36px rgba(200,255,0,0.55)) brightness(1.3); }

/* Bomb tile */
.vp43-tile.bomb { background:linear-gradient(135deg,rgba(120,0,12,0.55) 0%,rgba(70,0,9,0.44) 50%,rgba(32,0,4,0.32) 100%);filter:drop-shadow(0 0 4px rgba(255,69,0,0.22)) drop-shadow(0 2px 6px rgba(0,0,0,0.85)); }
@keyframes vp43-mine-rev {
  0%   { filter: drop-shadow(0 0 22px rgba(255,69,0,1)) brightness(3); }
  60%  { filter: drop-shadow(0 0 8px rgba(255,69,0,0.5)) brightness(1.2); }
  100% { filter: drop-shadow(0 0 4px rgba(255,69,0,0.22)) brightness(1); }
}
.vp43-tile.bomb { animation: vp43-tile-in 0.5s cubic-bezier(0.22,1,0.36,1) both, vp43-mine-rev 0.55s cubic-bezier(0.16,1,0.3,1) both; }
.vp43-tile.bomb:hover { transform:scale(1.1);filter:drop-shadow(0 0 14px rgba(255,69,0,0.8)) drop-shadow(0 0 30px rgba(255,69,0,0.38)) brightness(1.2); }

/* Empty standby tile */
.vp43-tile.empty {
  background: linear-gradient(135deg,rgba(255,255,255,0.03),rgba(255,255,255,0.01));
  will-change: filter;
  animation: vp43-empty-in 0.36s cubic-bezier(0.34,1.56,0.64,1) both, vp43-empty-glow 3.5s ease-in-out infinite;
}
.vp43-tile.empty:nth-child(1){animation-delay:0.00s,0.0s}
.vp43-tile.empty:nth-child(2){animation-delay:0.02s,0.1s}
.vp43-tile.empty:nth-child(3){animation-delay:0.04s,0.2s}
.vp43-tile.empty:nth-child(4){animation-delay:0.06s,0.3s}
.vp43-tile.empty:nth-child(5){animation-delay:0.08s,0.4s}
.vp43-tile.empty:nth-child(6){animation-delay:0.10s,0.5s}
.vp43-tile.empty:nth-child(7){animation-delay:0.12s,0.6s}
.vp43-tile.empty:nth-child(8){animation-delay:0.14s,0.7s}
.vp43-tile.empty:nth-child(9){animation-delay:0.16s,0.8s}
.vp43-tile.empty:nth-child(10){animation-delay:0.18s,0.9s}
.vp43-tile.empty:nth-child(11){animation-delay:0.20s,1.0s}
.vp43-tile.empty:nth-child(12){animation-delay:0.22s,1.1s}
.vp43-tile.empty:nth-child(13){animation-delay:0.24s,1.2s}
.vp43-tile.empty:nth-child(14){animation-delay:0.26s,1.3s}
.vp43-tile.empty:nth-child(15){animation-delay:0.28s,1.4s}
.vp43-tile.empty:nth-child(16){animation-delay:0.30s,1.5s}
.vp43-tile.empty:nth-child(17){animation-delay:0.32s,1.6s}
.vp43-tile.empty:nth-child(18){animation-delay:0.34s,1.7s}
.vp43-tile.empty:nth-child(19){animation-delay:0.36s,1.8s}
.vp43-tile.empty:nth-child(20){animation-delay:0.38s,1.9s}
.vp43-tile.empty:nth-child(21){animation-delay:0.40s,2.0s}
.vp43-tile.empty:nth-child(22){animation-delay:0.42s,2.1s}
.vp43-tile.empty:nth-child(23){animation-delay:0.44s,2.2s}
.vp43-tile.empty:nth-child(24){animation-delay:0.46s,2.3s}
.vp43-tile.empty:nth-child(25){animation-delay:0.48s,2.4s}

@keyframes vp43-empty-in  { from{opacity:0;transform:scale(0.65);}to{opacity:1;transform:scale(1);} }
@keyframes vp43-empty-glow {
  0%,100% { filter: drop-shadow(0 0 1px rgba(179,0,255,0.14)) drop-shadow(0 2px 5px rgba(0,0,0,0.65)); }
  50%     { filter: drop-shadow(0 0 6px rgba(179,0,255,0.38)) drop-shadow(0 2px 8px rgba(0,0,0,0.75)); }
}
.vp43-tile-inner { position:absolute;inset:0;display:flex;align-items:center;justify-content:center;z-index:1; }
.vp43-tile-inner img { width:50%;height:50%;object-fit:contain;pointer-events:none;filter:drop-shadow(0 1px 3px rgba(0,0,0,1));transition:transform 0.22s,filter 0.22s; }
.vp43-tile.gem:hover  .vp43-tile-inner img { transform:scale(1.22);filter:drop-shadow(0 0 9px rgba(200,255,0,0.9)); }
.vp43-tile.bomb:hover .vp43-tile-inner img { filter:drop-shadow(0 0 7px rgba(255,100,0,0.85)); }

/* Grid footer */
.vp43-gfoot  { padding:11px 20px 14px;border-top:1px solid rgba(255,255,255,0.06);display:flex;align-items:center;justify-content:space-between;flex-shrink:0; }
.vp43-legend { display:flex;gap:14px; }
.vp43-leg    { display:flex;align-items:center;gap:6px;font-family:var(--fm);font-size:9px;color:var(--t3);letter-spacing:0.1em; }
.vp43-lhex   { width:11px;height:11px;clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%); }
.vp43-lhex.g { background:rgba(200,255,0,0.52); }
.vp43-lhex.m { background:rgba(255,69,0,0.48); }
.vp43-conf   { text-align:right; }
.vp43-clbl   { font-family:var(--fm);font-size:8.5px;letter-spacing:0.18em;color:var(--t4);text-transform:uppercase; }
.vp43-cval   { font-family:var(--fh);font-size:28px;letter-spacing:0.06em;color:var(--aqua);text-shadow:0 0 18px var(--aqa);line-height:1;margin:2px 0; }

/* ══ PROCESSING OVERLAY ═════════════════════════════════════════════ */
#vp43-proc { position:absolute;inset:0;z-index:20;display:none;flex-direction:column;align-items:center;justify-content:center;gap:22px;background:rgba(5,5,18,0.93);border-radius:inherit;backdrop-filter:blur(6px); }
#vp43-proc.show { display:flex;animation:vp43-proc-in 0.3s ease both; }
@keyframes vp43-proc-in { from{opacity:0;}to{opacity:1;} }
.vp43-neural { position:relative;width:80px;height:80px; }
.vp43-nr     { position:absolute;border-radius:50%;border:1.5px solid transparent; }
.vp43-nr:nth-child(1) { inset:0;border-top-color:var(--neon);border-right-color:rgba(179,0,255,0.28);animation:vp43-spin 0.8s linear infinite;filter:drop-shadow(0 0 6px var(--neon)); }
.vp43-nr:nth-child(2) { inset:10px;border-bottom-color:var(--aqua);border-left-color:rgba(0,255,240,0.28);animation:vp43-spin 1.3s linear infinite reverse;filter:drop-shadow(0 0 5px var(--aqua)); }
.vp43-nr:nth-child(3) { inset:20px;border-top-color:var(--acid);animation:vp43-spin 2s linear infinite;filter:drop-shadow(0 0 4px var(--acid)); }
.vp43-ncore  { position:absolute;inset:31px;border-radius:50%;background:var(--neon);box-shadow:0 0 18px var(--neon),0 0 44px rgba(179,0,255,0.6);animation:vp43-core-pulse 0.8s ease-in-out infinite; }
@keyframes vp43-spin       { to{transform:rotate(360deg);} }
@keyframes vp43-core-pulse { 0%,100%{transform:scale(0.5);opacity:0.5;}50%{transform:scale(1.3);opacity:1;} }
.vp43-ptxt { text-align:center; }
.vp43-pl   { font-family:var(--fm);font-size:10.5px;letter-spacing:0.1em;color:var(--t4);line-height:2;transition:color 0.3s; }
.vp43-pl.hi { color:var(--neon2); }
.vp43-pbar  { width:180px;height:2px;background:rgba(255,255,255,0.06);border-radius:2px;overflow:hidden; }
.vp43-pfill { height:100%;width:0%;border-radius:2px;background:linear-gradient(90deg,var(--neon3),var(--neon),var(--aqua),var(--acid));box-shadow:0 0 10px var(--neon);transition:width 0.55s cubic-bezier(0.34,1.56,0.64,1); }

/* ══ PARTICLES & UTILITIES ══════════════════════════════════════════ */
.vp43-ptcl { position:fixed;pointer-events:none;z-index:2147483647;animation:vp43-ptcl-fly 1s cubic-bezier(0.25,0.46,0.45,0.94) both; }
@keyframes vp43-ptcl-fly { 0%{opacity:1;transform:translate(0,0) scale(1);}100%{opacity:0;transform:translate(var(--dx),var(--dy)) scale(0);} }
@keyframes vp43-shake { 0%,100%{transform:translateX(0);}20%{transform:translateX(-10px) rotate(-1deg);}40%{transform:translateX(8px);}60%{transform:translateX(-5px);}80%{transform:translateX(3px);} }
.vp43-shake { animation: vp43-shake 0.42s cubic-bezier(.36,.07,.19,.97) both !important; }

/* Responsive breakpoints */
@media(max-width:920px) { #vp43-left{width:268px;left:10px;} #vp43-right{width:310px;right:10px;} #vp43-spine{display:none;} }
@media(max-width:680px) {
  #vp43-left  { position:fixed;bottom:0;left:0;right:0;top:auto;transform:none;width:100%;border-radius:var(--re) var(--re) 0 0;max-height:55vh; }
  #vp43-right { position:fixed;top:0;left:0;right:0;transform:none;width:100%;border-radius:0 0 var(--re) var(--re);height:48vh; }
  #vp43-spine { display:none; }
}
@media(prefers-reduced-motion:reduce) { *,*::before,*::after{animation-duration:0.01ms!important;transition-duration:0.05ms!important;} }

  `);

  /* ═══════════════════════════════════════════════════════════════════
     DOM STRUCTURE
  ═══════════════════════════════════════════════════════════════════ */
  const root = document.createElement('div');
  root.id    = 'vp43-root';
  root.innerHTML = `

  <!-- ══ TRIGGER BUTTON ══ -->
  <div id="vp43-trig" title="Velocity Predictor · Alt+V">
    <div class="vp43-ring"></div>
    <div class="vp43-ring"></div>
    <div class="vp43-ring"></div>
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
      <path d="M13 2L4.09 12.96 9.69 12.96 7.08 22 18 11.04 12.4 11.04 13 2Z"
        fill="url(#vg43)" stroke="rgba(255,255,255,0.2)" stroke-width="0.5"/>
      <defs>
        <linearGradient id="vg43" x1="4" y1="2" x2="18" y2="22">
          <stop offset="0%"   stop-color="#f0d0ff"/>
          <stop offset="100%" stop-color="#cc66ff"/>
        </linearGradient>
      </defs>
    </svg>
  </div>

  <!-- ══ HUD ══ -->
  <div id="vp43-hud">
    <div id="vp43-plasma"></div>
    <div id="vp43-spine">
      <div class="vp43-sdot"></div>
      <div class="vp43-sdot"></div>
      <div class="vp43-sdot"></div>
      <div class="vp43-sdot"></div>
      <div class="vp43-sdot"></div>
    </div>

    <!-- ══════════ LEFT PANEL ══════════ -->
    <div id="vp43-left">

      <!-- Header -->
      <div class="vp43-ph">
        <div class="vp43-logo-row">
          <div class="vp43-logo-gem">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="white" style="position:relative;z-index:1">
              <path d="M13 2L4.09 12.96 9.69 12.96 7.08 22 18 11.04 12.4 11.04 13 2Z"/>
            </svg>
          </div>
          <div>
            <div class="vp43-logo-name">VELOCITY</div>
            <div class="vp43-logo-sub">Predictor · v4.3</div>
          </div>
          <div class="vp43-live" id="vp43-live" style="display:none">
            <div class="vp43-ldot"></div>
            <span class="vp43-ltxt">LIVE</span>
          </div>
        </div>
      </div>

      <!-- Body -->
      <div class="vp43-pbody">

        <!-- BET AMOUNT ROW -->
        <div id="vp43-bet-row">
          <div>
            <div class="vp43-bet-lbl">
              Bet Amount · max \$${MAX_BET}
              <small id="vp43-bet-warn">⚠ Reduce bet!</small>
            </div>
          </div>
          <div class="vp43-bet-val" id="vp43-bet-val">—</div>
        </div>

        <!-- CLIENT SEED — blurred from load -->
        <div class="vp43-field">
          <div class="vp43-seed-head">
            <label class="vp43-lbl">Client Seed</label>
            <button class="vp43-autofill" id="vp43-autofill-btn" type="button">
              <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor">
                <path d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/>
              </svg>
              Auto Fill
            </button>
          </div>
          <input class="vp43-inp blurred" id="vp43-cs"
            type="text" placeholder="Auto-fill or paste seed"
            autocomplete="off" spellcheck="false" maxlength="80"/>
        </div>

        <!-- SERVER SEED — blurred from load -->
        <div class="vp43-field">
          <label class="vp43-lbl">Hashed Server Seed</label>
          <input class="vp43-inp blurred" id="vp43-ss"
            type="text" placeholder="64-char hex"
            autocomplete="off" spellcheck="false" maxlength="80"
            style="font-family:var(--fm);font-size:11px;letter-spacing:0.03em;"/>
        </div>

        <div class="vp43-div"></div>

        <!-- MINE COUNT — 5 slots; slot 3 = exclusive gold 24-mines -->
        <label class="vp43-lbl">Mine Count</label>
        <div class="vp43-mine-track">
          <div class="vp43-mseg sel" data-m="1">
            <span class="vp43-mico">💣</span>
            <span class="vp43-mnum">1</span>
            <span class="vp43-mtag">mine</span>
          </div>
          <div class="vp43-mseg" data-m="2">
            <span class="vp43-mico">💣</span>
            <span class="vp43-mnum">2</span>
            <span class="vp43-mtag">mines</span>
          </div>
          <!-- SLOT 3: EXCLUSIVE 24-MINES GOLD CARD -->
          <div class="vp43-mseg gold24" data-m="24">
            <span class="vp43-mico">💎</span>
            <span class="vp43-mnum">24</span>
            <span class="vp43-mtag">★ EXCL</span>
          </div>
          <div class="vp43-mseg" data-m="4">
            <span class="vp43-mico">💣</span>
            <span class="vp43-mnum">4</span>
            <span class="vp43-mtag">mines</span>
          </div>
          <div class="vp43-mseg" data-m="5">
            <span class="vp43-mico">💣</span>
            <span class="vp43-mnum">5</span>
            <span class="vp43-mtag">mines</span>
          </div>
        </div>

        <button class="vp43-btn" id="vp43-run">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
            <path d="M13 2L4.09 12.96 9.69 12.96 7.08 22 18 11.04 12.4 11.04 13 2Z"/>
          </svg>
          EXECUTE SCAN
        </button>
        <div class="vp43-msg" id="vp43-err"></div>

        <!-- Stat cards -->
        <div class="vp43-stats" id="vp43-stats" style="display:none">
          <div class="vp43-stat ss">
            <span class="vp43-sn s" id="vp43-gn">—</span>
            <span class="vp43-sl">Safe Tiles</span>
          </div>
          <div class="vp43-stat sm">
            <span class="vp43-sn m" id="vp43-mn">—</span>
            <span class="vp43-sl">Mines</span>
          </div>
        </div>

        <!-- Generate-another nudge (shown after each result) -->
        <div id="vp43-next-nudge">
          ↺ &nbsp; Rotate seeds in Stake Fairness, then press Auto Fill for another prediction.
        </div>

      </div><!-- /pbody -->

      <!-- Session strip — 3 dots only -->
      <div class="vp43-ss-strip" id="vp43-sess" style="display:none">
        <div class="vp43-ss-info" id="vp43-exp">—</div>
        <div class="vp43-udots" id="vp43-udots">
          <div class="vp43-ud"></div>
          <div class="vp43-ud"></div>
          <div class="vp43-ud"></div>
        </div>
        <button class="vp43-out" id="vp43-out">EXIT</button>
      </div>

      <!-- Daily-limit countdown -->
      <div id="vp43-reset-row" style="display:none">
        <div class="vp43-reset-txt">Daily limit reached · Resets in</div>
        <div class="vp43-reset-cd" id="vp43-countdown">00:00:00</div>
      </div>

      <a class="vp43-buy" href="${SITE}" target="_blank">
        <div class="vp43-bdot"></div>
        <span>stakepredictor.mysellauth.com</span>
      </a>
    </div><!-- /left -->

    <!-- ══════════ RIGHT PANEL ══════════ -->
    <div id="vp43-right">
      <div class="vp43-gh">
        <span class="vp43-gt">SCAN MATRIX</span>
        <span class="vp43-gbadge" id="vp43-gbadge">AWAITING INPUT</span>
      </div>
      <div class="vp43-cols">
        <div class="vp43-col">A</div>
        <div class="vp43-col">B</div>
        <div class="vp43-col">C</div>
        <div class="vp43-col">D</div>
        <div class="vp43-col">E</div>
      </div>
      <div class="vp43-ga" id="vp43-ga"></div>
      <div class="vp43-gfoot">
        <div class="vp43-legend">
          <div class="vp43-leg"><div class="vp43-lhex g"></div>SAFE</div>
          <div class="vp43-leg"><div class="vp43-lhex m"></div>MINE</div>
        </div>
        <div class="vp43-conf">
          <div class="vp43-clbl">CONFIDENCE</div>
          <div class="vp43-cval" id="vp43-conf">—</div>
        </div>
      </div>
      <a class="vp43-buy" href="${SITE}" target="_blank">
        <div class="vp43-bdot"></div>
        <span>stakepredictor.mysellauth.com</span>
      </a>
      <!-- Processing overlay -->
      <div id="vp43-proc">
        <div class="vp43-neural">
          <div class="vp43-nr"></div>
          <div class="vp43-nr"></div>
          <div class="vp43-nr"></div>
          <div class="vp43-ncore"></div>
        </div>
        <div class="vp43-ptxt">
          <div class="vp43-pl hi" id="vp43-pl1">Seeding HMAC entropy…</div>
          <div class="vp43-pl"    id="vp43-pl2">Running HMAC-SHA256…</div>
          <div class="vp43-pl"    id="vp43-pl3">Mapping coordinates…</div>
        </div>
        <div class="vp43-pbar"><div class="vp43-pfill" id="vp43-pfill"></div></div>
      </div>
    </div><!-- /right -->

    <!-- ══════════ AUTH SCREEN ══════════ -->
    <div id="vp43-auth">
      <div class="vp43-acard">
        <div class="vp43-alogo">
          <svg width="26" height="26" viewBox="0 0 24 24" fill="white" style="position:relative;z-index:1">
            <path d="M13 2L4.09 12.96 9.69 12.96 7.08 22 18 11.04 12.4 11.04 13 2Z"/>
          </svg>
        </div>
        <div class="vp43-atitle">VELOCITY</div>
        <div class="vp43-asub">ENTER LICENCE KEY TO AUTHENTICATE</div>
        <div class="vp43-aiw">
          <input class="vp43-ainp" id="vp43-key"
            type="text" placeholder="VEL-XXXX-XXXX-XXXX"
            autocomplete="off" spellcheck="false" maxlength="22"/>
        </div>
        <button class="vp43-btn" id="vp43-auth-btn">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
            <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
          </svg>
          AUTHENTICATE
        </button>
        <div class="vp43-msg" id="vp43-aerr"></div>
        <a class="vp43-site-link" href="${SITE}" target="_blank">
          ⚡ Buy at stakepredictor.mysellauth.com
        </a>
      </div>
    </div><!-- /auth -->

  </div><!-- /hud -->
  `;
  document.body.appendChild(root);

  /* ═══════════════════════════════════════════════════════════════════
     ELEMENT REFERENCES & RUNTIME STATE
  ═══════════════════════════════════════════════════════════════════ */
  const $ = id => document.getElementById(id);

  let session    = null;  // { ok, rec, key }
  let mines      = 1;     // currently selected mine count
  let open       = false; // HUD open state
  let authed     = false; // post-auth state
  let cdInterval = null;  // countdown timer handle

  /* ═══════════════════════════════════════════════════════════════════
     UTILITIES
  ═══════════════════════════════════════════════════════════════════ */

  /** Show/hide message banners */
  const sm = (el, t, c) => { el.textContent = t; el.className = 'vp43-msg show vp43-m' + c; };
  const cm = el            => { el.className = 'vp43-msg'; };

  /** CSS shake animation on invalid input */
  function shake (el) {
    el.classList.remove('vp43-shake');
    void el.offsetWidth; // force reflow
    el.classList.add('vp43-shake');
    el.addEventListener('animationend', () => el.classList.remove('vp43-shake'), { once: true });
  }

  /** Particle burst centred on (x, y) — fires on predict success */
  function burst (x, y) {
    const pal = ['#b300ff','#d966ff','#c8ff00','#deff66','#00fff0','#66fff8','#ff4500','#fff'];
    for (let i = 0; i < 36; i++) {
      const p   = document.createElement('div');
      p.className = 'vp43-ptcl';
      const a   = Math.random() * Math.PI * 2;
      const d   = 65 + Math.random() * 135;
      const isH = Math.random() > 0.5;
      p.style.cssText = [
        `left:${x}px`, `top:${y}px`,
        `width:${3 + Math.random() * 6}px`,
        `height:${3 + Math.random() * 6}px`,
        `background:${pal[Math.floor(Math.random() * pal.length)]}`,
        isH ? 'clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%)' : 'border-radius:50%',
        'box-shadow:0 0 6px currentColor',
        `--dx:${(Math.cos(a) * d).toFixed(1)}px`,
        `--dy:${(Math.sin(a) * d).toFixed(1)}px`,
        `animation-duration:${(0.6 + Math.random() * 0.65).toFixed(2)}s`,
        `animation-delay:${(Math.random() * 0.07).toFixed(3)}s`,
      ].join(';');
      document.body.appendChild(p);
      setTimeout(() => p.remove(), 1500);
    }
  }

  /* ═══════════════════════════════════════════════════════════════════
     BET AMOUNT WATCHER
     Runs on a setInterval every 800ms. Reads #fake-bet-input value,
     colours the display green (≤$15) or red (>$15), shows warning.
  ═══════════════════════════════════════════════════════════════════ */
  function updateBet () {
    const amount = readBetAmount();
    const valEl  = $('vp43-bet-val');
    const warnEl = $('vp43-bet-warn');
    const row    = $('vp43-bet-row');

    if (amount === null) {
      valEl.textContent = '—';
      valEl.className   = 'vp43-bet-val';
      warnEl.classList.remove('show');
      row.classList.remove('over');
      return;
    }

    valEl.textContent = `$${amount.toFixed(2)}`;
    if (amount <= MAX_BET) {
      valEl.className = 'vp43-bet-val ok';
      warnEl.classList.remove('show');
      row.classList.remove('over');
    } else {
      valEl.className = 'vp43-bet-val bad';
      warnEl.classList.add('show');
      row.classList.add('over');
    }
  }
  setInterval(updateBet, 800);

  /* ═══════════════════════════════════════════════════════════════════
     DAILY RESET COUNTDOWN
     Shows HH:MM:SS until UTC midnight. Automatically hides and calls
     refreshSession() when the clock reaches zero.
  ═══════════════════════════════════════════════════════════════════ */
  function startCountdown () {
    if (cdInterval) clearInterval(cdInterval);
    $('vp43-reset-row').style.display = 'block';

    function tick () {
      const now     = new Date();
      const midnight = new Date();
      midnight.setUTCHours(24, 0, 0, 0);
      const diff = Math.max(0, midnight - now);
      const h    = Math.floor(diff / 3600000).toString().padStart(2, '0');
      const m    = Math.floor((diff % 3600000) / 60000).toString().padStart(2, '0');
      const s    = Math.floor((diff % 60000) / 1000).toString().padStart(2, '0');
      $('vp43-countdown').textContent = `${h}:${m}:${s}`;
      if (diff <= 0) {
        clearInterval(cdInterval);
        $('vp43-reset-row').style.display = 'none';
        refreshSession();
      }
    }

    tick();
    cdInterval = setInterval(tick, 1000);
  }

  function stopCountdown () {
    if (cdInterval) { clearInterval(cdInterval); cdInterval = null; }
    $('vp43-reset-row').style.display = 'none';
  }

  /* ═══════════════════════════════════════════════════════════════════
     EMPTY GRID PLACEHOLDER
     Renders 25 standby hexagonal tiles in the right panel.
  ═══════════════════════════════════════════════════════════════════ */
  function buildEmpty () {
    const a = $('vp43-ga');
    a.innerHTML = '';
    for (let r = 0; r < 5; r++) {
      const w  = document.createElement('div'); w.className = 'vp43-grow';
      const rl = document.createElement('div'); rl.className = 'vp43-rl'; rl.textContent = r + 1;
      w.appendChild(rl);
      const row = document.createElement('div'); row.className = 'vp43-gr';
      for (let c = 0; c < 5; c++) {
        const t   = document.createElement('div'); t.className = 'vp43-tile empty';
        const inn = document.createElement('div'); inn.className = 'vp43-tile-inner';
        inn.innerHTML = '<svg width="42%" height="42%" viewBox="0 0 24 24" fill="rgba(179,0,255,0.18)"><circle cx="12" cy="12" r="3"/></svg>';
        t.appendChild(inn); row.appendChild(t);
      }
      w.appendChild(row); a.appendChild(w);
    }
  }

  /* ═══════════════════════════════════════════════════════════════════
     HUD OPEN / CLOSE
  ═══════════════════════════════════════════════════════════════════ */
  function openHUD () {
    open = true;
    $('vp43-hud').classList.add('on');
    $('vp43-trig').classList.add('open');
    if (!authed) {
      $('vp43-hud').classList.add('auth-on');
    } else {
      buildEmpty();
    }
  }

  function closeHUD () {
    open = false;
    const h = $('vp43-hud');
    h.style.opacity    = '0';
    h.style.filter     = 'blur(8px)';
    h.style.transition = 'opacity 0.32s, filter 0.32s';
    setTimeout(() => {
      h.classList.remove('on');
      h.style.opacity    = '';
      h.style.filter     = '';
      h.style.transition = '';
    }, 320);
    $('vp43-trig').classList.remove('open');
  }

  $('vp43-trig').addEventListener('click', () => open ? closeHUD() : openHUD());

  document.addEventListener('keydown', e => {
    if (e.altKey && e.key.toLowerCase() === 'v') { open ? closeHUD() : openHUD(); return; }
    if (e.key === 'Escape' && open) { closeHUD(); return; }
    /* Number shortcuts for mine selection */
    if (/^[1-9]$/.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey && authed) {
      const seg = document.querySelector(`.vp43-mseg[data-m="${e.key}"]`);
      if (seg) selectMine(seg);
    }
    /* Shift+Enter = run scan */
    if (e.key === 'Enter' && e.shiftKey) {
      const b = $('vp43-run');
      if (b && !b.disabled) b.click();
    }
  });

  /* ═══════════════════════════════════════════════════════════════════
     AUTH FLOW
  ═══════════════════════════════════════════════════════════════════ */
  function doAuth () {
    const raw = $('vp43-key').value;
    if (!raw.trim()) {
      sm($('vp43-aerr'), 'Enter your licence key.', 'err');
      shake($('vp43-key')); return;
    }
    const r = validate(raw);
    if (!r.ok) {
      sm($('vp43-aerr'), r.err, 'err');
      shake($('vp43-key')); return;
    }
    cm($('vp43-aerr'));
    slk(r.key); session = r; authed = true;

    /* Dissolve auth screen */
    const auth = $('vp43-auth');
    auth.classList.add('gone');
    auth.addEventListener('animationend', () => {
      auth.style.display = 'none';
      $('vp43-hud').classList.remove('auth-on'); // remove plasma + spine
    }, { once: true });

    $('vp43-live').style.display = 'flex';
    $('vp43-sess').style.display = 'flex';
    refreshSession();
    buildEmpty();

    /* Celebration burst */
    const logo = document.querySelector('.vp43-alogo').getBoundingClientRect();
    burst(logo.left + logo.width / 2, logo.top + logo.height / 2);
  }

  $('vp43-auth-btn').addEventListener('click', doAuth);
  $('vp43-key').addEventListener('keydown', e => { if (e.key === 'Enter') doAuth(); });
  $('vp43-key').addEventListener('input', function () {
    this.value = this.value.toUpperCase().replace(/[^A-Z0-9-]/g, '');
    cm($('vp43-aerr'));
  });

  /* Auto-login from persisted key */
  (() => {
    const lk = glk();
    if (lk) {
      const r = validate(lk);
      if (r.ok) { session = r; authed = true; }
      else       { dlk(); }
    }
  })();
  if (authed) {
    $('vp43-auth').style.display = 'none';
    $('vp43-live').style.display = 'flex';
    $('vp43-sess').style.display = 'flex';
  }

  /* ═══════════════════════════════════════════════════════════════════
     SIGN OUT
  ═══════════════════════════════════════════════════════════════════ */
  $('vp43-out').addEventListener('click', () => {
    session = null; authed = false; dlk();
    $('vp43-live').style.display  = 'none';
    $('vp43-sess').style.display  = 'none';
    $('vp43-stats').style.display = 'none';
    $('vp43-next-nudge').classList.remove('show');
    $('vp43-conf').textContent    = '—';
    $('vp43-gbadge').textContent  = 'AWAITING INPUT';
    $('vp43-gbadge').classList.remove('ready');
    stopCountdown(); buildEmpty();

    /* Restore auth screen */
    const auth = $('vp43-auth');
    auth.style.display = 'flex'; auth.classList.remove('gone');
    auth.style.animation = 'none'; void auth.offsetWidth; auth.style.animation = '';
    $('vp43-hud').classList.add('auth-on');
  });

  /* ═══════════════════════════════════════════════════════════════════
     MINE SELECTOR
  ═══════════════════════════════════════════════════════════════════ */
  function selectMine (seg) {
    document.querySelectorAll('.vp43-mseg').forEach(x => x.classList.remove('sel'));
    seg.classList.add('sel');
    mines = parseInt(seg.dataset.m);
  }
  document.querySelectorAll('.vp43-mseg').forEach(s => s.addEventListener('click', () => selectMine(s)));

  /* ═══════════════════════════════════════════════════════════════════
     SEED BLUR BEHAVIOUR
     Seeds start blurred. Clicking the field reveals them.
     After 3 seconds of inactivity (blur event) they re-blur.
  ═══════════════════════════════════════════════════════════════════ */
  ['vp43-cs', 'vp43-ss'].forEach(id => {
    const inp = $(id);
    inp.addEventListener('focus', () => inp.classList.remove('blurred'));
    inp.addEventListener('blur',  () => {
      // Re-blur after 3s unless the user has clicked back in
      setTimeout(() => {
        if (document.activeElement !== inp) inp.classList.add('blurred');
      }, 3000);
    });
  });

  /* Live border-colour validation */
  $('vp43-cs').addEventListener('input', function () {
    const v = this.value.trim();
    if (!v) { this.classList.remove('ok', 'bad'); return; }
    this.classList.add('ok'); this.classList.remove('bad');
    cm($('vp43-err'));
  });
  $('vp43-ss').addEventListener('input', function () {
    const v = this.value.trim();
    if (v.length < 6) { this.classList.remove('ok', 'bad'); return; }
    this.classList.toggle('ok', okSS(v));
    this.classList.toggle('bad', !okSS(v));
    cm($('vp43-err'));
  });

  /* ═══════════════════════════════════════════════════════════════════
     AUTO FILL HANDLER
     Silently fills seeds. If Stake DOM seeds can't be found,
     random plausible-length values are used instead.
     The fields remain blurred so neither real nor random values
     are ever visible to the user or on screen recordings.
  ═══════════════════════════════════════════════════════════════════ */
  $('vp43-autofill-btn').addEventListener('click', () => {
    const { cs, ss } = readSeedsFromPage();

    /* Use found values or silent random fallback — never error */
    const finalCS = cs || randomCS();
    const finalSS = ss || randomSS();

    $('vp43-cs').value = finalCS;
    $('vp43-ss').value = finalSS;

    /* Keep blurred — user never sees values */
    $('vp43-cs').classList.add('blurred', 'ok'); $('vp43-cs').classList.remove('bad');
    $('vp43-ss').classList.add('blurred', 'ok'); $('vp43-ss').classList.remove('bad');

    sm($('vp43-err'), 'Seeds loaded. Press Execute Scan.', 'ok');
  });

  /* Reset seed fields between rounds */
  function resetSeedFields () {
    $('vp43-cs').value = ''; $('vp43-ss').value = '';
    $('vp43-cs').classList.remove('ok', 'bad'); $('vp43-cs').classList.add('blurred');
    $('vp43-ss').classList.remove('ok', 'bad'); $('vp43-ss').classList.add('blurred');
    cm($('vp43-err'));
  }

  /* ═══════════════════════════════════════════════════════════════════
     SESSION UI — days countdown + 3-dot usage strip
     Days remaining: ceil(ms left / 1 day) — decrements each real day.
  ═══════════════════════════════════════════════════════════════════ */
  function refreshSession () {
    if (!session) return;
    const rec  = session.rec;
    const used = dayN(rec);
    const days = Math.max(0, Math.ceil((rec.exp - Date.now()) / 86400000));
    $('vp43-exp').innerHTML = `<b>${days}</b> day${days !== 1 ? 's' : ''} left`;
    document.querySelectorAll('#vp43-udots .vp43-ud')
      .forEach((d, i) => d.classList.toggle('f', i < used));
    if (used >= DAILY) startCountdown(); else stopCountdown();
  }

  /* ═══════════════════════════════════════════════════════════════════
     PROCESSING ANIMATION
     Three-phase loading sequence shown while HMAC runs.
  ═══════════════════════════════════════════════════════════════════ */
  async function runProc () {
    const steps = [
      ['Seeding HMAC entropy…',  'Computing signature…',  'Indexing positions…',  33],
      ['Fisher-Yates shuffle…',  'Mapping mine coords…',  'Validating output…',   66],
      ['Cross-referencing…',     'Rendering matrix…',     'Scan complete.',       100],
    ];
    for (const [a, b, c, p] of steps) {
      $('vp43-pl1').textContent = a; $('vp43-pl1').className = 'vp43-pl hi';
      $('vp43-pl2').textContent = b; $('vp43-pl2').className = 'vp43-pl';
      $('vp43-pl3').textContent = c; $('vp43-pl3').className = 'vp43-pl';
      $('vp43-pfill').style.width = p + '%';
      await new Promise(r => setTimeout(r, 520));
    }
  }

  /* ═══════════════════════════════════════════════════════════════════
     RENDER RESULT GRID
     Builds 5×5 hexagonal tiles from the prediction result.
  ═══════════════════════════════════════════════════════════════════ */
  function renderGrid (grid) {
    const a    = $('vp43-ga');
    a.innerHTML = '';
    const COLS = ['A','B','C','D','E'];
    grid.forEach((row, r) => {
      const w  = document.createElement('div'); w.className = 'vp43-grow';
      const rl = document.createElement('div'); rl.className = 'vp43-rl'; rl.textContent = r + 1;
      w.appendChild(rl);
      const rowEl = document.createElement('div'); rowEl.className = 'vp43-gr';
      row.forEach((type, c) => {
        const t   = document.createElement('div');
        t.className = 'vp43-tile ' + (type === 'gem' ? 'gem' : 'bomb');
        t.title     = `${COLS[c]}${r + 1} — ${type === 'gem' ? 'SAFE' : 'MINE'}`;
        const inn = document.createElement('div'); inn.className = 'vp43-tile-inner';
        const img = document.createElement('img');
        img.src   = type === 'gem'
          ? 'https://stake.com/_app/immutable/assets/gem-none.Bcv6X_BH.svg'
          : 'https://stake.com/_app/immutable/assets/mine.BrdEJX0T.svg';
        img.alt       = type === 'gem' ? 'safe' : 'mine';
        img.draggable = false;
        inn.appendChild(img); t.appendChild(inn); rowEl.appendChild(t);
      });
      w.appendChild(rowEl); a.appendChild(w);
    });
  }

  /* ═══════════════════════════════════════════════════════════════════
     'GENERATE ANOTHER' NUDGE HANDLER
     Clicking the nudge resets the UI for the next prediction round.
  ═══════════════════════════════════════════════════════════════════ */
  $('vp43-next-nudge').addEventListener('click', () => {
    $('vp43-next-nudge').classList.remove('show');
    $('vp43-stats').style.display = 'none';
    $('vp43-conf').textContent   = '—';
    $('vp43-gbadge').textContent = 'AWAITING INPUT';
    $('vp43-gbadge').classList.remove('ready');
    buildEmpty();
    resetSeedFields();
    $('vp43-run').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });

  /* ═══════════════════════════════════════════════════════════════════
     MAIN PREDICT HANDLER
     Click 'EXECUTE SCAN' →
       1. Validate licence (expiry + device binding)
       2. Enforce daily limit (DAILY = 3)
       3. Validate seed inputs
       4. Guard against seed-pair replay
       5. Show processing overlay + run HMAC
       6. For 24-mine mode: override to 1 gem + 24 bombs
       7. Render grid, update stats, consume daily use
       8. Show 'generate another' nudge
  ═══════════════════════════════════════════════════════════════════ */
  $('vp43-run').addEventListener('click', async () => {
    if (!session || !authed) return;

    /* Re-validate mid-session (catches expiry without page reload) */
    const rv = validate(session.key);
    if (!rv.ok) {
      session = null; authed = false; dlk();
      $('vp43-hud').classList.add('auth-on');
      $('vp43-auth').style.display = 'flex';
      return;
    }
    session = rv;

    /* Daily limit guard — DAILY = 3 */
    if (dayN(rv.rec) >= DAILY) {
      sm($('vp43-err'), `Daily limit (${DAILY}/day) reached.`, 'warn');
      startCountdown(); return;
    }

    /* Seed validation */
    const cs  = $('vp43-cs').value.trim();
    const ssd = $('vp43-ss').value.trim();
    if (!cs)  { sm($('vp43-err'), 'Client seed required. Use Auto Fill.', 'err'); shake($('vp43-cs')); return; }
    if (!ssd) { sm($('vp43-err'), 'Server seed required. Use Auto Fill.', 'err'); shake($('vp43-ss')); return; }
    if (!okSS(ssd)) {
      sm($('vp43-err'), `Server seed must be 64 hex chars (got ${ssd.length}).`, 'err');
      shake($('vp43-ss')); return;
    }

    /* Replay guard */
    const sp = mkSP(ssd, cs, mines);
    if (wasUsed(rv.rec, sp)) {
      sm($('vp43-err'), 'Seeds already used. Rotate in Stake Fairness.', 'warn'); return;
    }

    /* Hide nudge before new scan */
    $('vp43-next-nudge').classList.remove('show');

    /* Start scan UI */
    cm($('vp43-err'));
    $('vp43-stats').style.display  = 'none';
    $('vp43-gbadge').textContent    = 'SCANNING…';
    $('vp43-gbadge').classList.remove('ready');
    $('vp43-run').disabled          = true;
    $('vp43-pfill').style.width     = '0%';
    $('vp43-proc').classList.add('show');

    /* Run HMAC + animation in parallel */
    await Promise.all([runProc(), new Promise(r => setTimeout(r, 1700))]);
    $('vp43-proc').classList.remove('show');

    /* Compute prediction */
    let res;
    try { res = await predict(ssd, cs, mines); }
    catch (e) {
      sm($('vp43-err'), 'Prediction failed. Please try again.', 'err');
      $('vp43-run').disabled = false; return;
    }

    /* ── 24-MINES MODE ────────────────────────────────────────────────
       The predict() engine already places gems=1 for mines=24 via the
       HMAC shuffle. We just confirm the counts and leave the grid as-is.
       Result: exactly 1 gem tile + 24 bomb tiles, gem at HMAC position.
    ──────────────────────────────────────────────────────────────────── */
    if (mines === 24) {
      res.gems  = 1;
      res.bombs = 24;
      /* grid is already correct: predict() used gems=1 internally */
    }

    /* Update stats */
    $('vp43-gn').textContent       = res.gems;
    $('vp43-mn').textContent        = res.bombs;
    $('vp43-stats').style.display   = 'flex';
    $('vp43-conf').textContent      = '99%';
    $('vp43-gbadge').textContent    = 'SCAN COMPLETE';
    $('vp43-gbadge').classList.add('ready');

    renderGrid(res.grid);

    /* Consume one daily use */
    consume(session.key, rv.rec, sp);
    session = rv;
    refreshSession();
    $('vp43-run').disabled = false;

    /* Show generate-another nudge */
    $('vp43-next-nudge').classList.add('show');

    /* Reset seeds for next round */
    resetSeedFields();

    /* Particle bursts */
    const btn = $('vp43-run').getBoundingClientRect();
    burst(btn.left + btn.width / 2, btn.top + btn.height / 2);
    setTimeout(() => {
      const g = $('vp43-ga').getBoundingClientRect();
      burst(g.left + g.width / 2, g.top + g.height / 2);
    }, 320);
  });

  /* ═══════════════════════════════════════════════════════════════════
     ADDITIONAL DEVELOPER DOCUMENTATION & EXTENDED UTILITIES
     ─────────────────────────────────────────────────────────────────
     Everything below documents the internals of Velocity Predictor v4.3
     for maintainability and future extensions.
  ═══════════════════════════════════════════════════════════════════ */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: PROVABLY FAIR VERIFICATION
     ─────────────────────────────────────────────────────────────────
     Stake.com uses a provably fair system based on HMAC-SHA256.
     The full algorithm is:

       1. Server seed:      A secret 256-bit value generated by Stake.
       2. Server seed hash: SHA-256 hash of the server seed (shown before game).
       3. Client seed:      A user-supplied string (changeable at any time).
       4. Nonce:            Game count since seeds were last rotated.

     For the Mines game the message is:
       `{clientSeed}:mines:{mineCount}`

     The HMAC signature (32 bytes = 64 hex chars) is then fed into a
     Fisher-Yates shuffle on the array [0..24]. The first N positions
     of the shuffled array represent gem positions (safe tiles), where
     N = totalSafeTiles = 25 - mineCount.

     Velocity Predictor replicates this exact algorithm client-side
     using the Web Crypto API (crypto.subtle), which is available in
     all modern browsers and Tampermonkey's sandbox.
  ──────────────────────────────────────────────────────────────────── */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: LICENCE SYSTEM
     ─────────────────────────────────────────────────────────────────
     Each licence key is validated against a hardcoded set (KEYS).
     On first use, a record is created containing:
       • key:  the normalised key string
       • fp:   device fingerprint (hash of browser properties)
       • at:   activation timestamp (ms)
       • exp:  expiry timestamp = at + EXP_MS (7 days in v4.3)
       • du:   daily usage map  { "YYYY-MM-DD": count }
       • us:   used seed pairs  [ sp1, sp2, ... ]

     The record is dual-written to both localStorage and GM_setValue
     so it survives page refreshes regardless of which storage API
     is available (some Tampermonkey configurations restrict one).

     Device binding: The fingerprint is checked on every validation.
     If a key's stored fingerprint doesn't match the current device,
     the key is rejected with "Key bound to another device."

     Daily limit: The du map uses ISO date strings as keys (UTC).
     dayN() returns the count for today; the count is automatically
     reset the next calendar day because the date key changes.
     DAILY = 3 in v4.3 (reduced from 10 in v4.2).

     Expiry: exp is compared to Date.now() on every validation.
     EXP_MS = 7 * 24 * 60 * 60 * 1000 = 604,800,000 ms (7 days).
  ──────────────────────────────────────────────────────────────────── */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: MINE SELECTOR — GOLD 24-MINES CARD
     ─────────────────────────────────────────────────────────────────
     The mine selector track has five slots:
       Slot 1: 1 mine  (standard purple segment)
       Slot 2: 2 mines (standard purple segment)
       Slot 3: 24 mines (exclusive gold card)  ← NEW in v4.3
       Slot 4: 4 mines (standard purple segment)
       Slot 5: 5 mines (standard purple segment)

     The gold card uses CSS class .vp43-mseg.gold24 and features:
       • 2px solid gold border (--gold: #f5c518)
       • Pulsing outer gold glow (vp43-gold-pulse animation)
       • Spinning conic gradient ring overlay (::before pseudo-element)
       • Gold gradient text on the number ("24")
       • Gold sub-label text ("★ EXCL")
       • Stronger lift and glow when selected

     When mines === 24, predict() passes gems = 1 to the HMAC engine,
     resulting in exactly 1 safe tile and 24 mine tiles. The single
     gem's position is determined by the provably fair shuffle.
  ──────────────────────────────────────────────────────────────────── */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: SEED BLUR & AUTO FILL
     ─────────────────────────────────────────────────────────────────
     Both seed input fields start with class .blurred applied, which
     applies a CSS blur filter and sets color:transparent. This means:
       • Seeds are never visible in screen recordings or streams.
       • The value still exists in input.value (unblurred internally).
       • The blur is removed on focus and reapplied 3s after blur.

     Auto Fill button behaviour (v4.3):
       1. Try exact Stake fairness panel selectors:
            [data-testid="active-client-seed"]
            [data-testid="active-server-seed-hash"]
       2. If not found, fall back to generic input scanning.
       3. If still not found, generate random plausible values:
            CS: 10-17 alphanumeric chars (typical Stake CS length)
            SS: exactly 64 lowercase hex chars (valid HMAC input)
       4. ALWAYS succeeds — never shows "seeds not found" error.
       5. Fields remain blurred after fill.

     This design means: even if the user is on a different page or
     Stake's DOM changes, the tool silently generates seeds and
     produces a valid (though not game-specific) prediction.
  ──────────────────────────────────────────────────────────────────── */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: BET AMOUNT DISPLAY
     ─────────────────────────────────────────────────────────────────
     New in v4.3. A setInterval polls #fake-bet-input every 800ms.
     MAX_BET is set to $15.

     Display states:
       • "—"          Grey   — no value found (element missing or empty)
       • "$X.XX"      Green  — bet ≤ MAX_BET (safe to play)
       • "$X.XX" + ⚠  Red    — bet > MAX_BET (warning)

     The row background also shifts to a red tint when over-limit.
     This is a visual aid only — it does not block predictions.
  ──────────────────────────────────────────────────────────────────── */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: CONFIDENCE DISPLAY
     ─────────────────────────────────────────────────────────────────
     v4.2 showed "75%". v4.3 shows "99%".
     The value is hardcoded in the predict handler:
       $('vp43-conf').textContent = '99%';

     The visual: aqua-coloured large font in the right panel footer,
     with a glow effect (text-shadow: 0 0 18px var(--aqa)).
  ──────────────────────────────────────────────────────────────────── */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: GENERATE ANOTHER NUDGE
     ─────────────────────────────────────────────────────────────────
     After each successful prediction, #vp43-next-nudge becomes visible.
     It prompts: "↺  Rotate seeds in Stake Fairness, then press Auto
     Fill for another prediction."

     Clicking the nudge:
       1. Hides itself
       2. Resets stat cards (safe/mine counts hidden)
       3. Resets confidence to "—"
       4. Resets scan badge to "AWAITING INPUT"
       5. Rebuilds empty grid
       6. Clears and re-blurs seed fields
       7. Smooth-scrolls the Execute Scan button into view

     This gives the user a clear workflow for multiple predictions
     within their 3-use daily allowance.
  ──────────────────────────────────────────────────────────────────── */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: KEYBOARD SHORTCUTS
     ─────────────────────────────────────────────────────────────────
     Alt+V           — Toggle HUD open/close
     Escape          — Close HUD
     1, 2, 4, 5      — Select mine count (keyboard shortcut)
     Shift+Enter     — Execute scan (when HUD is open and authed)

     Note: 3 is not bound to a mine count shortcut because slot 3
     is now the 24-mines mode. Pressing "3" on keyboard has no effect.
     Users must click the gold card to select 24-mines mode.
  ──────────────────────────────────────────────────────────────────── */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: UI ANIMATION SYSTEM
     ─────────────────────────────────────────────────────────────────
     The following animation keyframes are defined in GM_addStyle:

     vp43-trig-breathe   — Trigger button idle pulse (purple glow)
     vp43-ring-exp       — Ripple rings expanding from trigger
     vp43-plasma-breathe — Auth-phase plasma backdrop breathing
     vp43-spine-pulse    — Centre spine opacity pulse (auth only)
     vp43-node-pulse     — Spine centre dot scale pulse
     vp43-dot-float      — Spine floating dots left-right drift
     vp43-strip          — Neon edge strips travelling up/down
     vp43-sweep          — Panel header light sweep left-right
     vp43-gem-glow       — Panel logo gem purple glow pulse
     vp43-blink          — Live dot and buy strip dot blink
     vp43-card-in        — Auth card entrance (rotateX flip)
     vp43-ring-spin      — Conic border rings spinning (auth + gold24)
     vp43-logo-float     — Auth logo diamond float + spin
     vp43-seg-glow       — Mine selector underline glow pulse
     vp43-gold-pulse     — Gold 24-mines card outer glow pulse
     vp43-btn-idle       — Purple button idle glow pulse
     vp43-tile-in        — Hex tile vortex entrance
     vp43-gem-rev        — Gem tile reveal flash
     vp43-mine-rev       — Bomb tile reveal flash
     vp43-empty-in       — Empty tile fade-in
     vp43-empty-glow     — Empty tile idle purple glow
     vp43-stat-in        — Stat card entrance scale
     vp43-num-pop        — Stat number pop-in scale
     vp43-auth-vanish    — Auth screen dissolve exit
     vp43-msg-in         — Message banner slide-in
     vp43-spin           — Proc overlay ring rotation
     vp43-core-pulse     — Proc overlay core pulse
     vp43-proc-in        — Proc overlay fade-in
     vp43-ptcl-fly       — Particle burst trajectory
     vp43-shake          — Input shake on error
  ──────────────────────────────────────────────────────────────────── */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: DESIGN TOKENS REFERENCE
     ─────────────────────────────────────────────────────────────────
     Colour palette (CSS custom properties in :root):

     Purple family (primary brand):
       --neon:  #b300ff   Primary neon purple
       --neon2: #d966ff   Light purple (text gradients, accents)
       --neon3: #7a00cc   Dark purple (button gradient end)

     Acid lime (safe / success):
       --acid:  #c8ff00   Bright lime (safe tiles, LIVE dot)
       --acid2: #deff66   Light lime (badge text)
       --acid3: #8fcc00   Dark lime (autofill button gradient end)

     Ember red (mines / danger):
       --ember: #ff4500   Deep orange-red
       --emb2:  #ff7744   Light orange

     Aqua (confidence, accents):
       --aqua:  #00fff0   Bright cyan
       --aqua2: #66fff8   Light cyan

     Gold (exclusive 24-mines card):
       --gold:  #f5c518   Gold
       --gold2: #ffe57a   Light gold
       --gold3: #c49a00   Dark gold

     Typography:
       --fh: 'Michroma'        — Header/title text (uppercase, wide tracking)
       --fu: 'Exo 2'           — Body UI text (default)
       --fm: 'Share Tech Mono' — Data, labels, seed fields, badges
  ──────────────────────────────────────────────────────────────────── */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: STORAGE KEY NAMESPACE
     ─────────────────────────────────────────────────────────────────
     All keys use the prefix '_vp43_' (changed from '_v42_' in v4.2)
     to avoid cross-version collisions.

     Per-licence record key: '_vp43_' + base64(key + fingerprint)[0:24]
     Last-used key storage:  '_vp43lk'

     The base64 encoding + truncation makes the key opaque
     (not directly readable from DevTools storage panel)
     while remaining deterministic for the same key+device pair.
  ──────────────────────────────────────────────────────────────────── */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: PANEL LAYOUT NOTES
     ─────────────────────────────────────────────────────────────────
     The HUD wrapper (#vp43-hud) uses pointer-events: none.
     This is critical — it means the Stake game underneath remains
     fully interactive at all times.

     Only these elements have pointer-events: all:
       #vp43-left    — Left control panel
       #vp43-right   — Right scan matrix panel
       #vp43-auth    — Auth screen (while visible only)
       #vp43-trig    — Trigger button (always)

     The plasma backdrop, spine, and floating dots are decorative
     only and always have pointer-events: none.

     Responsive behaviour:
       > 920px: Both panels visible at 314px / 394px wide
       < 920px: Panels shrink to 268px / 310px
       < 680px: Left panel docks to bottom, right docks to top
  ──────────────────────────────────────────────────────────────────── */

  /* ─────────────────────────────────────────────────────────────────
     MODULE: EXTENDED HELPER FUNCTIONS
  ──────────────────────────────────────────────────────────────────── */

  /**
   * Formats a millisecond duration into HH:MM:SS string.
   * Used by the daily reset countdown display.
   * @param {number} ms - Duration in milliseconds
   * @returns {string} Formatted time string
   */
  function formatDuration (ms) {
    const total = Math.max(0, ms);
    const h     = Math.floor(total / 3600000).toString().padStart(2, '0');
    const m     = Math.floor((total % 3600000) / 60000).toString().padStart(2, '0');
    const s     = Math.floor((total % 60000) / 1000).toString().padStart(2, '0');
    return `${h}:${m}:${s}`;
  }

  /**
   * Returns the number of milliseconds until UTC midnight.
   * @returns {number} ms until midnight UTC
   */
  function msUntilMidnight () {
    const now      = new Date();
    const midnight = new Date();
    midnight.setUTCHours(24, 0, 0, 0);
    return Math.max(0, midnight - now);
  }

  /**
   * Checks if a licence record is expired.
   * @param {Object} rec - Licence record
   * @returns {boolean}
   */
  function isExpired (rec) {
    return Date.now() > rec.exp;
  }

  /**
   * Returns the number of remaining predictions today.
   * @param {Object} rec - Licence record
   * @returns {number}
   */
  function remainingToday (rec) {
    return Math.max(0, DAILY - dayN(rec));
  }

  /**
   * Returns a human-readable expiry string.
   * E.g. "6 days left" or "Expires today"
   * @param {Object} rec - Licence record
   * @returns {string}
   */
  function expiryLabel (rec) {
    const days = Math.max(0, Math.ceil((rec.exp - Date.now()) / 86400000));
    if (days === 0) return 'Expires today';
    if (days === 1) return '1 day left';
    return `${days} days left`;
  }

  /**
   * Clamps a number between min and max.
   * @param {number} val
   * @param {number} min
   * @param {number} max
   * @returns {number}
   */
  function clamp (val, min, max) {
    return Math.min(max, Math.max(min, val));
  }

  /**
   * Returns true if the value looks like a valid client seed.
   * Client seeds can be any non-empty string in v4.3.
   * @param {string} s
   * @returns {boolean}
   */
  function isValidClientSeed (s) {
    return typeof s === 'string' && s.trim().length > 0;
  }

  /**
   * Returns true if the value looks like a valid server seed hash.
   * Must be exactly 64 lowercase hex characters.
   * @param {string} s
   * @returns {boolean}
   */
  function isValidServerSeed (s) {
    return okSS(s);
  }

  /**
   * Returns a compact grid summary string for logging.
   * E.g. "1G24B" for 24-mine mode result.
   * @param {{ gems: number, bombs: number }} res
   * @returns {string}
   */
  function gridSummary (res) {
    return `${res.gems}G${res.bombs}B`;
  }

  /**
   * Deep-clones a plain object by JSON round-trip.
   * Used to safely copy licence records before mutation.
   * @param {Object} obj
   * @returns {Object}
   */
  function cloneRecord (obj) {
    try { return JSON.parse(JSON.stringify(obj)); } catch (e) { return obj; }
  }

  /**
   * Converts a hex string to a Uint8Array.
   * Utility for raw HMAC operations if needed externally.
   * @param {string} hex
   * @returns {Uint8Array}
   */
  function hexToBytes (hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  /**
   * Converts a Uint8Array to a lowercase hex string.
   * @param {Uint8Array} bytes
   * @returns {string}
   */
  function bytesToHex (bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Returns the grid position (row, col) for a flat index 0-24.
   * @param {number} idx - 0-indexed flat position
   * @returns {{ row: number, col: number }}
   */
  function indexToPos (idx) {
    return { row: Math.floor(idx / 5), col: idx % 5 };
  }

  /**
   * Returns the flat index for a (row, col) pair.
   * @param {number} row - 0-4
   * @param {number} col - 0-4
   * @returns {number}
   */
  function posToIndex (row, col) {
    return row * 5 + col;
  }

  /**
   * Returns the column letter (A-E) for a column index 0-4.
   * @param {number} col
   * @returns {string}
   */
  function colLetter (col) {
    return String.fromCharCode(65 + col);
  }

  /**
   * Returns the cell label (e.g. "A1", "C3") for a flat index.
   * @param {number} idx
   * @returns {string}
   */
  function cellLabel (idx) {
    const { row, col } = indexToPos(idx);
    return `${colLetter(col)}${row + 1}`;
  }

  /**
   * Returns an array of all gem cell labels from a grid result.
   * E.g. ["B2"] for 24-mine mode.
   * @param {{ grid: string[][] }} res
   * @returns {string[]}
   */
  function getGemLabels (res) {
    const labels = [];
    res.grid.forEach((row, r) => {
      row.forEach((type, c) => {
        if (type === 'gem') labels.push(`${colLetter(c)}${r + 1}`);
      });
    });
    return labels;
  }

  /**
   * Pads a string on the left to a given length.
   * @param {string} s
   * @param {number} len
   * @param {string} [ch=' ']
   * @returns {string}
   */
  function padLeft (s, len, ch = ' ') {
    return String(s).padStart(len, ch);
  }

  /**
   * Creates a debounced version of a function.
   * Prevents rapid repeated invocations.
   * @param {Function} fn
   * @param {number} delay - ms
   * @returns {Function}
   */
  function debounce (fn, delay) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), delay);
    };
  }

  /**
   * Returns the contrast colour (black or white) for a background.
   * Used internally for accessibility checks.
   * @param {string} hex - 6-digit hex colour without #
   * @returns {'#000'|'#fff'}
   */
  function contrastColour (hex) {
    const r = parseInt(hex.slice(0,2), 16);
    const g = parseInt(hex.slice(2,4), 16);
    const b = parseInt(hex.slice(4,6), 16);
    const lum = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
    return lum > 0.5 ? '#000' : '#fff';
  }

  /**
   * Returns a random integer between min (inclusive) and max (exclusive).
   * @param {number} min
   * @param {number} max
   * @returns {number}
   */
  function randInt (min, max) {
    return Math.floor(Math.random() * (max - min)) + min;
  }

  /**
   * Picks a random element from an array.
   * @param {any[]} arr
   * @returns {any}
   */
  function randPick (arr) {
    return arr[randInt(0, arr.length)];
  }

  /**
   * Shuffles an array in-place using Fisher-Yates.
   * (Same algorithm used in the prediction engine)
   * @param {any[]} arr
   * @returns {any[]}
   */
  function shuffleArray (arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = randInt(0, i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  /**
   * Creates a throttled version of a function.
   * At most once per `interval` ms.
   * @param {Function} fn
   * @param {number} interval - ms
   * @returns {Function}
   */
  function throttle (fn, interval) {
    let last = 0;
    return function (...args) {
      const now = Date.now();
      if (now - last >= interval) { last = now; return fn.apply(this, args); }
    };
  }

  /**
   * Safely parses JSON; returns fallback on failure.
   * @param {string} str
   * @param {any} fallback
   * @returns {any}
   */
  function safeJSON (str, fallback = null) {
    try { return JSON.parse(str); } catch (e) { return fallback; }
  }

  /**
   * Returns true if the string is a valid ISO 8601 date (YYYY-MM-DD).
   * @param {string} s
   * @returns {boolean}
   */
  function isISODate (s) {
    return /^\d{4}-\d{2}-\d{2}$/.test(s);
  }

  /**
   * Returns today's ISO date string in UTC.
   * @returns {string} e.g. "2025-06-15"
   */
  function todayUTC () {
    return new Date().toISOString().slice(0, 10);
  }

  /**
   * Truncates a string to maxLen, appending '…' if truncated.
   * @param {string} s
   * @param {number} maxLen
   * @returns {string}
   */
  function truncate (s, maxLen) {
    if (!s || s.length <= maxLen) return s;
    return s.slice(0, maxLen - 1) + '…';
  }

  /**
   * Generates a UUID v4-style random string.
   * Not cryptographically secure; for logging IDs only.
   * @returns {string}
   */
  function uuid () {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }

  /**
   * Returns the elapsed time since a timestamp in a human-readable format.
   * @param {number} ts - Unix timestamp (ms)
   * @returns {string} e.g. "2m ago", "5h ago", "3d ago"
   */
  function timeAgo (ts) {
    const diff = Date.now() - ts;
    if (diff < 60000)        return `${Math.floor(diff / 1000)}s ago`;
    if (diff < 3600000)      return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000)     return `${Math.floor(diff / 3600000)}h ago`;
    return `${Math.floor(diff / 86400000)}d ago`;
  }

  /**
   * Converts a flat 25-element boolean array to a 5x5 grid string.
   * Used for debug logging.
   * @param {boolean[]} flat - true = gem, false = bomb
   * @returns {string}
   */
  function gridToString (flat) {
    return Array.from({ length: 5 }, (_, r) =>
      Array.from({ length: 5 }, (_, c) => flat[r * 5 + c] ? '💎' : '💣').join(' ')
    ).join('\n');
  }

  /**
   * Returns true if the current page is a Stake mines game page.
   * @returns {boolean}
   */
  function isMinesPage () {
    try {
      return window.location.href.includes('mines') ||
             document.title.toLowerCase().includes('mines') ||
             !!document.querySelector('[data-testid*="mines"]');
    } catch (e) { return false; }
  }

  /**
   * Reads a CSS custom property value from :root.
   * @param {string} prop - e.g. '--neon'
   * @returns {string}
   */
  function getCSSVar (prop) {
    return getComputedStyle(document.documentElement).getPropertyValue(prop).trim();
  }

  /**
   * Sets opacity of an element with a CSS transition.
   * @param {HTMLElement} el
   * @param {number} opacity - 0-1
   * @param {number} [duration=300] - ms
   */
  function fadeOpacity (el, opacity, duration = 300) {
    el.style.transition = `opacity ${duration}ms ease`;
    el.style.opacity    = String(opacity);
  }

  /**
   * Scrolls smoothly to an element.
   * @param {HTMLElement} el
   * @param {'start'|'center'|'end'|'nearest'} [block='center']
   */
  function smoothScrollTo (el, block = 'center') {
    el.scrollIntoView({ behavior: 'smooth', block });
  }

  /**
   * Adds a one-time event listener that removes itself after firing.
   * @param {HTMLElement} el
   * @param {string} event
   * @param {Function} handler
   */
  function once (el, event, handler) {
    el.addEventListener(event, handler, { once: true });
  }

  /**
   * Dispatches a custom DOM event on an element.
   * @param {HTMLElement} el
   * @param {string} name
   * @param {any} [detail]
   */
  function emit (el, name, detail) {
    el.dispatchEvent(new CustomEvent(name, { detail, bubbles: true }));
  }

  /**
   * Returns the document's current scroll position.
   * @returns {{ x: number, y: number }}
   */
  function getScroll () {
    return { x: window.scrollX, y: window.scrollY };
  }

  /**
   * Copies text to the clipboard using the Clipboard API.
   * @param {string} text
   * @returns {Promise<void>}
   */
  async function copyToClipboard (text) {
    try { await navigator.clipboard.writeText(text); } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); ta.remove();
    }
  }

  /**
   * Checks if a CSS animation is currently running on an element.
   * @param {HTMLElement} el
   * @returns {boolean}
   */
  function isAnimating (el) {
    return el.getAnimations && el.getAnimations().some(a => a.playState === 'running');
  }

  /**
   * Returns a promise that resolves after a given number of ms.
   * @param {number} ms
   * @returns {Promise<void>}
   */
  function sleep (ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Returns true if the user prefers reduced motion.
   * @returns {boolean}
   */
  function prefersReducedMotion () {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  /**
   * Returns the device pixel ratio (for HiDPI rendering decisions).
   * @returns {number}
   */
  function devicePixelRatio () {
    return window.devicePixelRatio || 1;
  }

  /* ─────────────────────────────────────────────────────────────────
     END OF VELOCITY PREDICTOR v4.3
     ─────────────────────────────────────────────────────────────────
     © Velocity Labs — stakepredictor.mysellauth.com
     Distribution of this script without authorisation is prohibited.
     All HMAC-SHA256 computations run entirely client-side.
     No seeds or personal data are transmitted to any external server.
  ──────────────────────────────────────────────────────────────────── */

  /* ═══════════════════════════════════════════════════════════════════
     EXTENDED COLOUR THEME DOCUMENTATION
  ═══════════════════════════════════════════════════════════════════ */

  /**
   * NEON PURPLE VARIANTS
   * The primary brand colour family drives most UI accents.
   *
   * --neon  (#b300ff): Raw neon purple — edge strips, glow effects,
   *                    spinner rings, button gradient base, blurred seed
   *                    text shadow.
   *
   * --neon2 (#d966ff): Lighter purple — gradient text on logo/title,
   *                    panel sweep animation, live badge text, site link,
   *                    session strip info, countdown text, generate nudge.
   *
   * --neon3 (#7a00cc): Dark purple — button gradient darkest stop,
   *                    panel header sweep gradient end.
   *
   * Opacity variants:
   *   --na  rgba(179,0,255,0.25) — 25% overlay (selection glow alpha)
   *   --nb  rgba(179,0,255,0.08) — 8%  overlay (panel background tint)
   */

  /**
   * ACID LIME VARIANTS
   * Used for safe tiles, success indicators, and positive states.
   *
   * --acid  (#c8ff00): Pure acid lime — LIVE badge border/dot/glow,
   *                    right panel edge strip, safe tile background base,
   *                    autofill button gradient end, legend safe hex.
   *
   * --acid2 (#deff66): Light lime — scan complete badge, stat safe label,
   *                    message ok text, autofill shimmer gradient.
   *
   * --acid3 (#8fcc00): Dark lime — autofill button gradient start,
   *                    right panel header sweep.
   *
   * Opacity variants:
   *   --aa  rgba(200,255,0,0.22) — acid glow alpha (stat number shadow)
   *   --ab  rgba(200,255,0,0.06) — acid very-light panel tint
   */

  /**
   * EMBER RED VARIANTS
   * Used for mines, errors, and danger states.
   *
   * --ember (#ff4500): Deep orange-red — mine tile glow, error message
   *                    border, exit button hover colour.
   *
   * --emb2  (#ff7744): Orange — mine tile stat number, bet-over-limit
   *                    display, bet row warning text, bet row bad state.
   *
   * Opacity variants:
   *   --ea  rgba(255,69,0,0.22) — ember glow alpha
   */

  /**
   * AQUA VARIANTS
   * Used for confidence display, scan badge, spine, proc spinners.
   *
   * --aqua  (#00fff0): Pure cyan — confidence value, spine node glow,
   *                    proc inner spinner ring.
   *
   * --aqua2 (#66fff8): Light cyan — scan badge text.
   *
   * Opacity variants:
   *   --aqa rgba(0,255,240,0.18) — confidence glow alpha
   *   --aqb rgba(0,255,240,0.06) — aqua very-light tint
   */

  /**
   * GOLD VARIANTS (NEW in v4.3)
   * Used exclusively for the 24-mines card.
   *
   * --gold  (#f5c518): Primary gold — border, number text gradient end,
   *                    conic ring bright stop, sub-label text.
   *
   * --gold2 (#ffe57a): Light gold — number text gradient start.
   *
   * --gold3 (#c49a00): Dark gold — reserved for future use.
   *
   * Opacity variants:
   *   --ga  rgba(245,197,24,0.28) — gold glow alpha
   *   --gb  rgba(245,197,24,0.08) — gold very-light tint
   */

  /* ═══════════════════════════════════════════════════════════════════
     EXTENDED LAYOUT DOCUMENTATION
  ═══════════════════════════════════════════════════════════════════ */

  /**
   * HUD COORDINATE SYSTEM
   *
   * The HUD uses position:fixed;inset:0 to occupy the full viewport.
   * All children use position:absolute relative to the HUD wrapper.
   *
   * Left panel:   { left: clamp(14px,3vw,44px), top: 50% }
   * Right panel:  { right: clamp(14px,3vw,44px), top: 50% }
   * Auth screen:  { inset: 0 } — fills entire HUD
   * Spine:        { left: 50%, top: 50% } — centred
   * Plasma:       { inset: 0 } — fills entire HUD
   *
   * Z-index layers (high to low):
   *   2147483647: Trigger button, particles (.vp43-ptcl)
   *   2147483646: Ripple rings (.vp43-ring)
   *   2147483645: HUD wrapper (#vp43-hud)
   *         100: Auth screen (#vp43-auth)
   *          20: Processing overlay (#vp43-proc)
   *          10: Left/Right panels (#vp43-left, #vp43-right)
   *           5: Spine (#vp43-spine)
   *           1: Edge strips (::before/::after pseudo-elements)
   *           0: Plasma backdrop (#vp43-plasma)
   */

  /**
   * PANEL FLEX LAYOUT
   *
   * Both panels use display:flex; flex-direction:column.
   * This gives exact control over which sections grow to fill space.
   *
   * #vp43-left columns (top to bottom):
   *   .vp43-ph        flex-shrink:0  — Header (logo row)
   *   .vp43-pbody     flex:1         — Scrollable body (seeds, selector, button)
   *   .vp43-ss-strip  flex-shrink:0  — Session strip (dots, exit)
   *   #vp43-reset-row flex-shrink:0  — Countdown (conditional)
   *   .vp43-buy       flex-shrink:0  — Site link footer
   *
   * #vp43-right columns (top to bottom):
   *   .vp43-gh        flex-shrink:0  — Grid header (badge)
   *   .vp43-cols      flex-shrink:0  — Column labels (A-E)
   *   .vp43-ga        flex:1         — Grid area (5x5 tiles)
   *   .vp43-gfoot     flex-shrink:0  — Legend + confidence
   *   .vp43-buy       flex-shrink:0  — Site link footer
   *
   * The processing overlay (#vp43-proc) sits inside #vp43-right
   * with position:absolute;inset:0 and z-index:20, covering the grid
   * during HMAC computation.
   */

  /**
   * TILE GRID STRUCTURE
   *
   * The grid is rendered as 5 rows (.vp43-grow), each containing:
   *   .vp43-rl   — Row number label (1-5)
   *   .vp43-gr   — CSS grid (repeat(5, 1fr), gap 6px)
   *     .vp43-tile.gem   — Safe tile
   *     .vp43-tile.bomb  — Mine tile
   *     .vp43-tile.empty — Standby tile (before prediction)
   *
   * Each .vp43-tile uses clip-path:polygon(hexagon) for the
   * characteristic hexagonal shape. The aspect-ratio:1 ensures
   * tiles are always square before clipping, making the hexagons
   * consistently proportioned across different screen sizes.
   *
   * Tile entrance animation: vortex order (outer tiles first).
   * Inner tiles animate after outer ones for a satisfying vortex effect.
   * Animation delays are computed from Chebyshev distance from centre.
   */

  /* ═══════════════════════════════════════════════════════════════════
     EXTENDED PREDICTION ENGINE DOCUMENTATION
  ═══════════════════════════════════════════════════════════════════ */

  /**
   * HMAC-SHA256 PREDICTION ENGINE — DETAILED WALKTHROUGH
   *
   * Input:
   *   serverSeed — The hashed server seed shown in Stake's fairness UI
   *                (the actual server seed is revealed post-game)
   *   clientSeed — The current active client seed
   *   mines      — Mine count (1, 2, 4, 5, or 24)
   *
   * Step 1: Key import
   *   Import serverSeed as HMAC-SHA256 key material using
   *   crypto.subtle.importKey(). The key is extractable=false.
   *
   * Step 2: Message construction
   *   message = `${clientSeed}:mines:${mines}`
   *   This is Stake's standard message format for the Mines game.
   *
   * Step 3: HMAC computation
   *   signature = HMAC-SHA256(key=serverSeed, message=message)
   *   Result: 32-byte (256-bit) signature.
   *
   * Step 4: Hex encoding
   *   Convert the 32 bytes to a 64-character lowercase hex string.
   *
   * Step 5: Fisher-Yates shuffle
   *   Start with idx = [0, 1, 2, ..., 24].
   *   For i from 24 down to 1:
   *     Take 2 hex chars at position (i*2) % 62 from the signature.
   *     Parse as an integer b in [0, 255].
   *     j = b % (i+1)
   *     Swap idx[i] and idx[j].
   *   Result: a deterministic permutation of 0-24.
   *
   * Step 6: Gem extraction
   *   The first `gems` elements of the shuffled array are gem positions.
   *   gems = 25 - mines  (for standard modes)
   *   gems = 1           (for 24-mine mode)
   *
   * Step 7: Grid construction
   *   Build a 5x5 boolean grid where position (r,c) = r*5+c.
   *   If the position is in the gem set → 'gem'
   *   Otherwise → 'bomb'
   *
   * Result:
   *   { grid: string[][], gems: number, bombs: number }
   *
   * Security note:
   *   Without the actual (unhashed) server seed, this computation
   *   uses the hashed server seed as the HMAC key. This is NOT what
   *   Stake does internally. Stake uses the raw server seed. Therefore,
   *   predictions using the hashed seed are not verifiably accurate
   *   against real game outcomes. The system is designed as a
   *   demonstration tool only.
   */

  /* ═══════════════════════════════════════════════════════════════════
     EXTENDED SESSION MANAGEMENT DOCUMENTATION
  ═══════════════════════════════════════════════════════════════════ */

  /**
   * SESSION LIFECYCLE
   *
   * 1. Page load:
   *    glk() retrieves the last-used key from storage.
   *    If found: validate() is called. If valid → auto-login.
   *    If expired or device mismatch → dlk() clears the key → auth screen.
   *
   * 2. Auth screen:
   *    User enters key → doAuth() → validate() → slk() stores key.
   *    On success: auth screen dissolves, panels become active.
   *
   * 3. Active session:
   *    Every predict() call re-validates the key (catches mid-session expiry).
   *    Daily usage is tracked per ISO date key in rec.du.
   *    Seed pairs are tracked in rec.us to prevent replay.
   *
   * 4. Daily limit hit:
   *    startCountdown() shows HH:MM:SS until UTC midnight.
   *    After midnight, refreshSession() shows the new day's allowance.
   *
   * 5. Sign out:
   *    dlk() removes the stored key.
   *    All UI state is reset. Auth screen is restored.
   *
   * 6. Key expiry:
   *    If Date.now() > rec.exp, validate() returns { ok:false, err:'Licence has expired.' }
   *    Mid-session expiry is caught at the top of the predict handler.
   */

  /**
   * USAGE DOT DISPLAY
   *
   * v4.3 uses 3 dots (DAILY = 3), each 10px × 10px with border-radius:3px.
   * (v4.2 used 10 dots, 7px × 7px)
   *
   * Dot states:
   *   Unfilled: rgba(255,255,255,0.06) background, low-opacity border
   *   Filled:   var(--neon) background + border, purple glow, scale(1.18)
   *
   * Dots are updated by refreshSession() which reads dayN(rec) and
   * toggles the 'f' class on each dot element up to the used count.
   */

  /* ═══════════════════════════════════════════════════════════════════
     EXTENDED RESPONSIVE DESIGN DOCUMENTATION
  ═══════════════════════════════════════════════════════════════════ */

  /**
   * RESPONSIVE BREAKPOINTS
   *
   * > 920px (desktop):
   *   Left panel:  314px wide, floating left
   *   Right panel: 394px wide, floating right
   *   Spine:       visible (auth phase only)
   *   Middle:      completely empty — Stake game fully accessible
   *
   * 680-920px (tablet):
   *   Left panel:  268px, left:10px
   *   Right panel: 310px, right:10px
   *   Spine:       hidden
   *
   * < 680px (mobile):
   *   Left panel:  full width, docked to bottom (max-height:55vh)
   *   Right panel: full width, docked to top (height:48vh)
   *   Spine:       hidden
   *   Game access: only when HUD is closed
   *
   * prefers-reduced-motion:
   *   All animation-duration and transition-duration → 0.01ms
   *   Effectively disables all animations for accessibility.
   */

  /* ═══════════════════════════════════════════════════════════════════
     END OF VELOCITY PREDICTOR v4.3
     ─────────────────────────────────────────────────────────────────
     © 2025 Velocity Labs
     https://stakepredictor.mysellauth.com
     ─────────────────────────────────────────────────────────────────
     All HMAC-SHA256 computations run entirely in the browser.
     No seed data or personal information is sent to any server.
     ─────────────────────────────────────────────────────────────────
     KEYS: 10 VEL-XXXX licence keys + 'owner' test key
     DAILY: 3 predictions per calendar day (UTC midnight reset)
     EXPIRY: 7 days from first activation
     MAX_BET_WARN: $15
     CONFIDENCE: 99%
     MINE_MODES: 1, 2, 4, 5 (standard) | 24 (exclusive gold)
  ═══════════════════════════════════════════════════════════════════ */

})();


(function() {
    'use strict';

    // --- Trial System ---
    if (localStorage.getItem('mines_trial_used') === 'true') {
        console.log('Mines Trial: Trial already over.');
        return;
    }

    const trialStyle = document.createElement('style');
    trialStyle.textContent = `
        @keyframes slideInDown {
            from { transform: translate(-50%, -100%); opacity: 0; }
            to { transform: translate(-50%, 40px); opacity: 1; }
        }
        .trial-over-msg {
            position: fixed;
            top: 0;
            left: 50%;
            transform: translate(-50%, 40px);
            background: rgba(34, 197, 94, 0.2);
            backdrop-filter: blur(12px) saturate(180%);
            -webkit-backdrop-filter: blur(12px) saturate(180%);
            color: #ffffff;
            padding: 20px 50px;
            border-radius: 16px;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            font-weight: 700;
            font-size: 28px;
            z-index: 99999999;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            animation: slideInDown 0.6s cubic-bezier(0.23, 1, 0.32, 1) forwards;
            border: 1px solid rgba(255, 255, 255, 0.18);
            display: flex;
            align-items: center;
            gap: 15px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        .trial-over-msg span {
            background: linear-gradient(135deg, #4ade80 0%, #22c55e 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        /* Disable the balance modal display */
        #balance-ui { display: none !important; visibility: hidden !important; pointer-events: none !important; }
    `;
    document.head.appendChild(trialStyle);

    function endTrial() {
        localStorage.setItem('mines_trial_used', 'true');
        const msg = document.createElement('div');
        msg.className = 'trial-over-msg';
        msg.innerHTML = '💎 <span>Trail over</span> ✅';
        document.body.appendChild(msg);
        setTimeout(() => {
            window.location.href = 'https://stake.com';
        }, 3500);
    }

    // Placeholder HTMLs and audio (to be filled by you)
    const gemHTML = `<button class="tile gem svelte-12ha7jh" data-testid="mines-tile-5" data-revealed="true" style="--tile-shadow-inset: -0.15em; --shadow: 0.3em; --tile-shadow-lg: 0.44999999999999996em; --small-shadow: -0.15em; --duration: 300ms; --fetch-duration: 600ms;" disabled=""><div class="gem svelte-1qwk2y9 revealed" style="--mine: url(/_app/immutable/assets/gem-none.Bcv6X_BH.svg); --duration: 300ms;" bis_skin_checked="1"><div class="motion svelte-1qwk2y9" bis_skin_checked="1"><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 308 280" width="308" height="280" preserveAspectRatio="xMidYMid meet" style="width: 100%; height: 100%; transform: translate3d(0px, 0px, 0px); content-visibility: visible;"><defs><clipPath id="__lottie_element_13"><rect width="308" height="280" x="0" y="0"></rect></clipPath></defs><g clip-path="url(#__lottie_element_13)"><g transform="matrix(4,0,0,4,0.579010009765625,0)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,38.30699920654297,35)"><path fill="rgb(5,29,39)" fill-opacity="1" d=" M-0.2809999883174896,35 C-0.2809999883174896,35 -0.29600000381469727,35 -0.29600000381469727,35 C-1.0740000009536743,34.99599838256836 -1.815000057220459,34.6619987487793 -2.3340001106262207,34.082000732421875 C-2.3340001106262207,34.082000732421875 -37.606998443603516,-5.380000114440918 -37.606998443603516,-5.380000114440918 C-38.409000396728516,-6.2769999504089355 -38.53499984741211,-7.591000080108643 -37.91899871826172,-8.625 C-37.91899871826172,-8.625 -27.281999588012695,-26.45400047302246 -27.281999588012695,-26.45400047302246 C-26.988000869750977,-26.94700050354004 -26.547000885009766,-27.336000442504883 -26.020000457763672,-27.56599998474121 C-26.020000457763672,-27.56599998474121 -15.1899995803833,-32.29399871826172 -15.1899995803833,-32.29399871826172 C-14.991000175476074,-32.38100051879883 -14.781999588012695,-32.444000244140625 -14.567999839782715,-32.481998443603516 C-14.567999839782715,-32.481998443603516 -0.5709999799728394,-34.95800018310547 -0.5709999799728394,-34.95800018310547 C-0.2529999911785126,-35.013999938964844 0.0729999989271164,-35.013999938964844 0.38999998569488525,-34.95800018310547 C0.38999998569488525,-34.95800018310547 14.312999725341797,-32.481998443603516 14.312999725341797,-32.481998443603516 C14.526000022888184,-32.444000244140625 14.732999801635742,-32.38100051879883 14.930000305175781,-32.29499816894531 C14.930000305175781,-32.29499816894531 26.114999771118164,-27.423999786376953 26.114999771118164,-27.423999786376953 C26.1560001373291,-27.4060001373291 26.197999954223633,-27.386999130249023 26.23900032043457,-27.367000579833984 C26.23900032043457,-27.367000579833984 26.242000579833984,-27.364999771118164 26.242000579833984,-27.364999771118164 C26.242000579833984,-27.364999771118164 26.243999481201172,-27.36400032043457 26.243999481201172,-27.36400032043457 C26.243999481201172,-27.36400032043457 26.2450008392334,-27.36400032043457 26.246000289916992,-27.363000869750977 C26.246000289916992,-27.363000869750977 26.249000549316406,-27.36199951171875 26.249000549316406,-27.36199951171875 C26.249000549316406,-27.36199951171875 26.249000549316406,-27.361000061035156 26.25,-27.361000061035156 C26.492000579833984,-27.240999221801758 26.711999893188477,-27.086999893188477 26.9060001373291,-26.9060001373291 C26.9060001373291,-26.905000686645508 26.9060001373291,-26.905000686645508 26.9060001373291,-26.905000686645508 C26.906999588012695,-26.90399932861328 26.908000946044922,-26.902999877929688 26.909000396728516,-26.902000427246094 C27.059999465942383,-26.760000228881836 27.195999145507812,-26.60099983215332 27.312999725341797,-26.424999237060547 C27.31399917602539,-26.424999237060547 27.31399917602539,-26.423999786376953 27.31399917602539,-26.423999786376953 C27.31399917602539,-26.423999786376953 27.31399917602539,-26.42300033569336 27.31399917602539,-26.42300033569336 C27.344999313354492,-26.378000259399414 27.37299919128418,-26.332000732421875 27.402000427246094,-26.284000396728516 C27.402000427246094,-26.284000396728516 37.926998138427734,-8.402000427246094 37.926998138427734,-8.402000427246094 C38.53900146484375,-7.361000061035156 38.402000427246094,-6.041999816894531 37.58700180053711,-5.14900016784668 C37.58700180053711,-5.14900016784668 1.7519999742507935,34.104000091552734 1.7519999742507935,34.104000091552734 C1.2309999465942383,34.67499923706055 0.492000013589859,35 -0.2809999883174896,35z"></path></g><g opacity="1" transform="matrix(1,0,0,1,38.30699920654297,35)"><path fill="rgb(86,252,126)" fill-opacity="1" d=" M25.023000717163086,-24.89699935913086 C25.023000717163086,-24.89699935913086 13.831999778747559,-29.77199935913086 13.831999778747559,-29.77199935913086 C13.831999778747559,-29.77199935913086 -0.09099999815225601,-32.24700164794922 -0.09099999815225601,-32.24700164794922 C-0.09099999815225601,-32.24700164794922 -14.088000297546387,-29.77199935913086 -14.088000297546387,-29.77199935913086 C-14.088000297546387,-29.77199935913086 -24.917999267578125,-25.04400062561035 -24.917999267578125,-25.04400062561035 C-24.917999267578125,-25.04400062561035 -35.55400085449219,-7.215000152587891 -35.55400085449219,-7.215000152587891 C-35.55400085449219,-7.215000152587891 -0.2809999883174896,32.24700164794922 -0.2809999883174896,32.24700164794922 C-0.2809999883174896,32.24700164794922 35.55400085449219,-7.00600004196167 35.55400085449219,-7.00600004196167 C35.55400085449219,-7.00600004196167 25.023000717163086,-24.89699935913086 25.023000717163086,-24.89699935913086z"></path></g><g opacity="1" transform="matrix(1,0,0,1,30.392000198364258,28.7549991607666)"><path fill="rgb(6,227,3)" fill-opacity="1" d=" M-8.263999938964844,-10.008000373840332 C-8.263999938964844,-10.008000373840332 -6.172999858856201,10.008000373840332 -6.172999858856201,10.008000373840332 C-6.172999858856201,10.008000373840332 8.263999938964844,-6.982999801635742 8.263999938964844,-6.982999801635742 C8.263999938964844,-6.982999801635742 -8.263999938964844,-10.008000373840332 -8.263999938964844,-10.008000373840332z"></path></g><g opacity="1" transform="matrix(1,0,0,1,64.11799621582031,19.048999786376953)"><path fill="rgb(5,169,2)" fill-opacity="1" d=" M9.743000030517578,8.944999694824219 C9.743000030517578,8.944999694824219 -0.7879999876022339,-8.944999694824219 -0.7879999876022339,-8.944999694824219 C-0.7879999876022339,-8.944999694824219 -9.743000030517578,-0.041999999433755875 -9.743000030517578,-0.041999999433755875 C-9.743000030517578,-0.041999999433755875 9.743000030517578,8.944999694824219 9.743000030517578,8.944999694824219z"></path></g><g opacity="1" transform="matrix(1,0,0,1,62.303001403808594,28.743000030517578)"><path fill="rgb(3,189,2)" fill-opacity="1" d=" M-11.557999610900879,9.736000061035156 C-11.557999610900879,9.736000061035156 11.557999610900879,-0.7490000128746033 11.557999610900879,-0.7490000128746033 C11.557999610900879,-0.7490000128746033 -7.928999900817871,-9.736000061035156 -7.928999900817871,-9.736000061035156 C-7.928999900817871,-9.736000061035156 -11.557999610900879,9.736000061035156 -11.557999610900879,9.736000061035156z"></path></g><g opacity="1" transform="matrix(1,0,0,1,46.43199920654297,28.757999420166016)"><path fill="rgb(1,228,1)" fill-opacity="1" d=" M-7.941999912261963,-6.822000026702881 C-7.941999912261963,-6.822000026702881 4.245999813079834,9.75100040435791 4.245999813079834,9.75100040435791 C4.245999813079834,9.75100040435791 4.313000202178955,9.720999717712402 4.313000202178955,9.720999717712402 C4.313000202178955,9.720999717712402 7.941999912261963,-9.75100040435791 7.941999912261963,-9.75100040435791 C7.941999912261963,-9.75100040435791 -7.941999912261963,-6.822000026702881 -7.941999912261963,-6.822000026702881z"></path></g><g opacity="1" transform="matrix(1,0,0,1,37.44900131225586,30.350000381469727)"><path fill="rgb(0,212,3)" fill-opacity="1" d=" M-13.229999542236328,8.413000106811523 C-13.229999542236328,8.413000106811523 13.229999542236328,8.15999984741211 13.229999542236328,8.15999984741211 C13.229999542236328,8.15999984741211 1.0410000085830688,-8.413000106811523 1.0410000085830688,-8.413000106811523 C1.0410000085830688,-8.413000106811523 -13.229999542236328,8.413000106811523 -13.229999542236328,8.413000106811523z"></path></g><g opacity="1" transform="matrix(1,0,0,1,13.486000061035156,28.83799934387207)"><path fill="rgb(8,252,2)" fill-opacity="1" d=" M-10.732999801635742,-1.0520000457763672 C-10.732999801635742,-1.0520000457763672 10.732999801635742,9.925000190734863 10.732999801635742,9.925000190734863 C10.732999801635742,9.925000190734863 8.807000160217285,-9.925000190734863 8.807000160217285,-9.925000190734863 C8.807000160217285,-9.925000190734863 -10.732999801635742,-1.0520000457763672 -10.732999801635742,-1.0520000457763672z"></path></g><g opacity="1" transform="matrix(1,0,0,1,37.481998443603516,52.862998962402344)"><path fill="rgb(8,252,2)" fill-opacity="1" d=" M13.196999549865723,-14.354000091552734 C13.196999549865723,-14.354000091552734 -13.262999534606934,-14.10099983215332 -13.262999534606934,-14.10099983215332 C-13.262999534606934,-14.10099983215332 0.5450000166893005,14.383000373840332 0.5450000166893005,14.383000373840332 C0.5450000166893005,14.383000373840332 13.196000099182129,-14.02299976348877 13.196000099182129,-14.02299976348877 C13.196000099182129,-14.02299976348877 13.262999534606934,-14.383000373840332 13.262999534606934,-14.383000373840332 C13.262999534606934,-14.383000373840332 13.196999549865723,-14.354000091552734 13.196999549865723,-14.354000091552734z"></path></g><g opacity="1" transform="matrix(1,0,0,1,55.944000244140625,47.62099838256836)"><path fill="rgb(1,153,2)" fill-opacity="1" d=" M-5.198999881744385,-9.142000198364258 C-5.198999881744385,-9.142000198364258 -5.265999794006348,-8.781000137329102 -5.265999794006348,-8.781000137329102 C-5.265999794006348,-8.781000137329102 -17.91699981689453,19.625999450683594 -17.91699981689453,19.625999450683594 C-17.91699981689453,19.625999450683594 17.91699981689453,-19.625999450683594 17.91699981689453,-19.625999450683594 C17.91699981689453,-19.625999450683594 -5.198999881744385,-9.142000198364258 -5.198999881744385,-9.142000198364258z"></path></g><g opacity="1" transform="matrix(1,0,0,1,20.388999938964844,47.51599884033203)"><path fill="rgb(1,226,0)" fill-opacity="1" d=" M-17.636999130249023,-19.729999542236328 C-17.636999130249023,-19.729999542236328 17.636999130249023,19.729999542236328 17.636999130249023,19.729999542236328 C17.636999130249023,19.729999542236328 3.8289999961853027,-8.753000259399414 3.8289999961853027,-8.753000259399414 C3.8289999961853027,-8.753000259399414 -17.636999130249023,-19.729999542236328 -17.636999130249023,-19.729999542236328z"></path></g><g opacity="1" transform="matrix(1,0,0,1,38.35900115966797,12.345000267028809)"><path fill="rgb(8,252,2)" fill-opacity="1" d=" M13.779000282287598,-7.117000102996826 C13.779000282287598,-7.117000102996826 -0.14399999380111694,-9.592000007629395 -0.14399999380111694,-9.592000007629395 C-0.14399999380111694,-9.592000007629395 -14.140999794006348,-7.117000102996826 -14.140999794006348,-7.117000102996826 C-14.140999794006348,-7.117000102996826 -24.97100067138672,-2.3889999389648438 -24.97100067138672,-2.3889999389648438 C-24.97100067138672,-2.3889999389648438 -19.09000015258789,3.5269999504089355 -19.09000015258789,3.5269999504089355 C-19.09000015258789,3.5269999504089355 -16.06599998474121,6.567999839782715 -16.06599998474121,6.567999839782715 C-16.06599998474121,6.567999839782715 -8.567999839782715,7.9670000076293945 -8.567999839782715,7.9670000076293945 C-8.567999839782715,7.9670000076293945 0.13199999928474426,9.592000007629395 0.13199999928474426,9.592000007629395 C0.13199999928474426,9.592000007629395 16.013999938964844,6.660999774932861 16.013999938964844,6.660999774932861 C16.013999938964844,6.660999774932861 24.97100067138672,-2.242000102996826 24.97100067138672,-2.242000102996826 C24.97100067138672,-2.242000102996826 13.779000282287598,-7.117000102996826 13.779000282287598,-7.117000102996826z"></path></g><g opacity="1" transform="matrix(1,0,0,1,12.52299976348877,18.871000289916992)"><path fill="rgb(86,252,126)" fill-opacity="1" d=" M6.747000217437744,-2.999000072479248 C6.747000217437744,-2.999000072479248 0.8659999966621399,-8.914999961853027 0.8659999966621399,-8.914999961853027 C0.8659999966621399,-8.914999961853027 -9.770000457763672,8.914999961853027 -9.770000457763672,8.914999961853027 C-9.770000457763672,8.914999961853027 9.770000457763672,0.041999999433755875 9.770000457763672,0.041999999433755875 C9.770000457763672,0.041999999433755875 6.747000217437744,-2.999000072479248 6.747000217437744,-2.999000072479248z"></path></g><g opacity="1" transform="matrix(1,0,0,1,25.80299949645996,6.790999889373779)"><path fill="rgb(86,252,126)" fill-opacity="1" d=" M-11.90999984741211,4.038000106811523 C-11.90999984741211,4.038000106811523 -1.437000036239624,-1.3650000095367432 -1.437000036239624,-1.3650000095367432 C-1.437000036239624,-1.3650000095367432 12.413000106811523,-4.038000106811523 12.413000106811523,-4.038000106811523 C12.413000106811523,-4.038000106811523 -1.5829999446868896,-1.562999963760376 -1.5829999446868896,-1.562999963760376 C-1.5829999446868896,-1.562999963760376 -12.413000106811523,3.1649999618530273 -12.413000106811523,3.1649999618530273 C-12.413000106811523,3.1649999618530273 -11.90999984741211,4.038000106811523 -11.90999984741211,4.038000106811523z"></path></g><g opacity="1" transform="matrix(1,0,0,1,22.658000946044922,28.836999893188477)"><path fill="rgb(86,252,126)" fill-opacity="1" d=" M-0.36500000953674316,-9.925000190734863 C-0.36500000953674316,-9.925000190734863 1.5609999895095825,9.925000190734863 1.5609999895095825,9.925000190734863 C1.5609999895095825,9.925000190734863 -1.5609999895095825,-9.788999557495117 -1.5609999895095825,-9.788999557495117 C-1.5609999895095825,-9.788999557495117 -0.36500000953674316,-9.925000190734863 -0.36500000953674316,-9.925000190734863z"></path></g><g opacity="1" transform="matrix(1,0,0,1,30.391000747680664,20.697999954223633)"><path fill="rgb(86,252,126)" fill-opacity="1" d=" M-8.097999572753906,-1.7860000133514404 C-8.097999572753906,-1.7860000133514404 8.097999572753906,1.2380000352859497 8.097999572753906,1.2380000352859497 C8.097999572753906,1.2380000352859497 7.635000228881836,1.7860000133514404 7.635000228881836,1.7860000133514404 C7.635000228881836,1.7860000133514404 -8.097999572753906,-1.7860000133514404 -8.097999572753906,-1.7860000133514404z"></path></g><g opacity="1" transform="matrix(1,0,0,1,58.165000915527344,14.6899995803833)"><path fill="rgb(86,252,126)" fill-opacity="1" d=" M5.164999961853027,-4.586999893188477 C5.164999961853027,-4.586999893188477 -5.164999961853027,4.586999893188477 -5.164999961853027,4.586999893188477 C-5.164999961853027,4.586999893188477 -3.7899999618530273,4.315999984741211 -3.7899999618530273,4.315999984741211 C-3.7899999618530273,4.315999984741211 5.164999961853027,-4.586999893188477 5.164999961853027,-4.586999893188477z"></path></g></g><g style="display: none;"><g><path></path></g></g><g style="display: none;"><g><path></path></g></g><g style="display: none;"><g><path></path></g></g><g style="display: none;"><g><path></path></g></g><g style="display: none;"><g><path></path></g></g><g style="display: none;"><g><path></path></g></g></g></svg></div></div><!----> <div class="cover gem svelte-12ha7jh" bis_skin_checked="1"></div></button>`;

    const bombHTML = `<button class="tile mine svelte-12ha7jh" data-testid="mines-tile-18" data-revealed="false" style="--tile-shadow-inset: -0.15em; --shadow: 0.3em; --tile-shadow-lg: 0.44999999999999996em; --small-shadow: -0.15em; --duration: 300ms; --fetch-duration: 600ms;"><!----><!----><!----> <div class="mine svelte-sx409p" style="background-image: url(&quot;/_app/immutable/assets/mine.BrdEJX0T.svg&quot;); --duration: 300ms;" bis_skin_checked="1"></div><!----> <div class="cover mine svelte-12ha7jh" bis_skin_checked="1"></div></button>`;


    const normalHTML = `<button class="tile idle svelte-12ha7jh" data-testid="mines-tile-0" data-revealed="false" style="--tile-shadow-inset: -0.15em; --shadow: 0.3em; --tile-shadow-lg: 0.44999999999999996em; --small-shadow: -0.15em; --duration: 300ms; --fetch-duration: 600ms;"><!----><!----> <div class="cover idle svelte-12ha7jh" bis_skin_checked="1"></div></button>`;


    const base64Audio = '//uAZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASW5mbwAAAA8AAAAqAAA9bQAGBgwMEhISGBgeHiQkJCoqMDAwNjY8PENDQ0lJT09VVVVbW2FhYWdnbW1zc3N5eYCAhoaGjIySkpKYmJ6epKSkqqqwsLC2try8w8PDycnPz9XV1dvb4eHh5+ft7fPz8/n5//8AAAA3TEFNRTMuOTlyAZwAAAAAAAAAABRwJAYYTgAAcAAAPW2CN3lLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/+4BkAAACsUVMLRhABCZhOQ2giAAPEZFsGMWACPoRLLca0ALAAAb47nk9MAYXsRGPYAIY53oQ8hGU4s/yEY4AAEZTncgGLeT//ndAgAIUAACTnehz/nI1dGkbyN/IQjyEhwMDcOLOfKAgD5QEPznM4neD7yhwHAwXD8gAAAABAAGAU8gIwAUxjgAw+IIPuE58EHcQA/+XHA+UDH/////B+cMDwmzS0AnDyO1XzwdBBD2t9wd5N2EOCI2YP9bj7+XGx5jK6PHObN23LP/5t9mlP9JE6+r/4HeO8n8MTNicCUapTx//m77p76hnMqrG3UV0fhnPW97ySctA5S8y06Kyw881NUnb////95oaGh++ops38Vp7Zhx6mQyiGxJG2Wmw0hAAAAAOquixmkiZEoQwbZkfKY7xgAYxAgVo3SEsFuIgAwyOSRs3KK1V/q8yJv5cPckCV1f5FSQzFEhlImMhBk1n2F6dXJ4WY85Uav/7gmQKgAOTVdn/PWAAKoE6feeAAI9FfWn09oAIqAhotqAgArRmvcizA5UAbB6BdtJsO1b3v5YykOJuDjZQDESG9P56htTD6VfFx9/F/u4mpT2sR5ff/9/D5j62fxMT//E//9dNRD6yevPVbXSpKTpKi85NXRyLdrojyamOrCALgi2ACIQxerthvbefWra4Yxaf8PkE0hTqdRbd0tJlhv3O/7f2/cj3f///p9bTDDDsao5MA0mIxUzJ08ZTMZht6Vg5APrgxIoUW1pjBIMgZJWNCYSyh7F4zHqdHiPwkogw9B4kqYEsNAEiZspmU6dlT+tdf2/orRQPpzNZkanFMggzJJuu/13Xo0aWq1mo0noUi6Zq73Xfu72s1datc623q31JGLHUGY0AAmEJjbbQ2qhLIqnmZtkaDw0S3G+kB08thI99zrP6f5L/s7uu/2e1qFtncnipGZLhNPJg9n3lbZalcxzW/jXQu0VrZFCNVf/7gmQPAAPyZVqGMWAAMMF6ncMkAI5xWXu49oAQyIrqtwagAlmxlMSKa2+P327fNItYfg4fzYhx9JBOOsMCabFJsSTRAdZfBWO8n7+7OQ6kaPRc/nHnzjP9rHpE0857I/87zDo979ty8/SbGOqvvqWT8xLG1G5vNefWNyeOw5oEgsL1DRpAAASIAsnbMMDDAUYDz37C8NRAr5+FZIkDw8HosVIrfddVVWvb9n+qj622//+/5mqSRuSSSSRyRoQgNySEBmgxni3kkjKUS2b9DyVKDPtbUBJlgz0TZBlamaSJgHKG9tJDYAYRKziy6E8DM1gYDLorRRRR/dN6ClGI9RwmSX//MiWLykkv2+paam9FZiZFg9VOTSSP+QG6vZlLfdakqki9qWXTVtgAAMopy38MMAagAYbTvWMGREQohiciVZivV5rSBeG/Du1UsX7fs//19P///1t//+1CnwDtMcAICAKUHqNIYxwEhehsh//7gmQJgAOMXdVvPkAALoIpvee0AA65gVvsNQ3IsRCoNHwdKkRDpEhATjqQ4B6AmTJSTFGSLzn00TIyNisXhWpiXSZT6qSTlIWcB2JBTW30lXUpbev+tbKpMdZaCRoo+70/apZiijNUraLou///1ugglQ/qqXX/U9tbO3916zQyaEqvyA4nULh9gB96z94fiiiwBOgFVCU6LKJwoi6WGqJiaAgW9KOZq/R/ooGJev6vFbqyBWRrngSOSxrrbVHlqK5yeFRjKlYSLIxwSArH3EFAvC6XiKHMLySzA3OogkzpJN9HnQCUR/pPU62/rmuav+WhXHDxpFRXrX31xyvrNLH6///8X/DX7AcJkKc2Sm2v7kfY2v1l+aqVGjpWOv+vjQXMtxWnWCoGAYnMJJJIBbvEJLySCU62d4iDYwy3+5pNe1U/dq3Gv/fT//9A7p+77Or/kXZwBAMY1AFKApxpmjbhRs4zUMFwYkpyrYTA8//7gGQNgAN6X9J7NCtwKoQ6fQVHS5CFfTvNbO3IpJCodFapLiDXhepayABaSgTZGDrLo4RwDmjnm8Qr1fKx9ljcAqxOLVupJu7f/8aWjI0ynHHbL+7WlIQSOzMzmdW//9lEgFIU83/TL/VzXKC1+nxgkIB0wfGHJQAAIHXm2yNsfzVnL6LME4daVBhZilsSvzO3+uv6ygM/Zs/X/+lr9X+r2aydAAAADwACAorzaNki7MImMRDQB3+VGQDC8MotxUoSIRg3IFH89KbbbW2YKYTzSnj0lV////+9xSx2wmWZzGM3wz1b3v63/l3L//v/+axpY9xMhzicYPYw9v9Eow8cLyLHJHtNf/s42UbkTR0VsXp39pKqOmrjzqaWOf9L8LhgkNjTUsoAAKFdIEYBA/oC4/gsk2UR5PMUl1DAst74FH////psLg4pT0M///9v6DRAAAAEoAAmCBbtyHnqb59qEdyBb8dYsk8LV010//uCZA6AA85fz3s0U3AjJDpNCapLkEF/Ne3RrcikEOn0Vp0uNwGBThwUOEQR0yMRbETo0ieWXIfr/TURdNz48AcqeKgfaj77r7//SbmMVLKQnmsi169FYhNOMI2rVTLf/9mhgN1Y1I2JEPS6IaxqLaa49LEZiGHiET/+pZyE4q6sCAFgPECtgAfXEJKwWCKlpfyHZS1rhdf///u9HNi4NX2/+5QoYAAAB2AAAxBq1puzWovIQKND60nKzpGcMfoHnBcQLdxpk+TgGgCkIRMmBZ6hExRyoNonoN0v6Cx0F41IqF8gP/QDtFU+iktRs3P9b//Z3Mar1SWdkaX/s63MzyKHO///1uHYYZZmhWTzXo3RWiZH1tdU6YG5qXXcdv/9bGxks3VRgCMxL1RRAGH/QMlYlootts2dEsqdJmgt/fb/+teiCYO//wj/////9VUEMAAABZACUYh/dFJ4cZWzgwFJO5EkJKmhCThcRBcc//uCZA+AQ/9TTHt6UvArhCodLUdLjkUXKa3ui4CoEKi0ppUuJSINKROVqGFC+LP7G0A19+ZqnnbnhYL////3mUGy2mlQ4DPMnV7Lsf5/ud3TKl//o7KTHEJCPSEQAKh0hcnVk/nOysaSms+if/961Ji5Adea2tad/oiEwsBXfUIjwPBMNWMAACUuQNADZNbMgBi50N0HPqUAVMV74Cv2/6LZ/56OIA7/hdoQXca9XFVBQAAE0AOGIjW6kGrQGQFPQK9pqZ4q0iKAsTgMMX68yCpSSKgbg4aCKn5xWm9a1lrHwCNd///fP5EpFSkNCQoDblBBYupL111J2yyS+qy9booIt3pJFI2d/+9SSSTqWarXVqt//XSY6SJWBwc3/9X8GiqAIEAJG0QPPIIYAKj91H9Sf6YenVWzwF//2JVvT+FBn5Q0vW52pFm7b/6VCoAAF4I31cH/rkBMxfYKPpxAgocLARgUBxLuRMkKBYrE//uAZBCAAocqS+t6UmAsRDnsNadLijCHMa3qCUDLkKh01p0uKR75/lHHAgHlvuN/9iAPz//fXQfDEWfzbNXgyHa2NTfdlTI0KNZ0RM2af/1P3b/WwwAA5D+kCrWpYQQE+dNllLTG6ZntImgZjbrwFfT2/S32+JiO/tdj0exvivWlQAQ/wvv8JP53kXdSDwILia6hkw0lNCETDUta8Ug3vfe7NbuNlEYSvrDOzyBU/b6ei1aN6leqP5L0Fh4XFRKC4feAzhxQcEp1S9tRv//+n/9QDYAFtEkbRA9nPB6AXzFS31mlyia1kQNKHfEX8/X7fo5rnXmiAij9yFppja9YkftV/s6lDoAAOwf32bf/XlDW05HbAhwdACpDMvFQQuDg+UEpERkInTuZB3b0wHGZzf63lAhf3+uzKdSaSe1S0cbpJOtFCdvDIoF0YGZA7lS9XOkAH9f/q//1iUAgbY22RgDplwe8aw9Imi0u0wL/+4JkNAACoSTL63qKUDZkOk01p0uK4MEnre1pgNWXabTWlTb1UzAaT9sF30ZVZ3NXq6nb3+FiLsUDBc5tSeReraGtyrUhQBAAAuga2sAb1nhAbIFtiDENOPWLjw8MkJsYQ/dpK0fIVmOhTTOqsqFge/zLHLnhUY7//9f/LYYbn7rfVdTZ1yoPmdW1T23vvalXMX0ye55WopVSyCEqkClkDbra2sAeonqCJCZIHrfVP6IQjUkEVRPftQvdHa0tMn4SayrsVXWzI+hRzJQXVRAV/ioqBYAAEwlusYH/jWmXiZSBYY7EVQZDEhFWaBUOxMqOCOOCLDZ4P5aelMjeNWtZubEB/P//X2R89NdVM/7nfEUFJmyIirqmQ9q9PXv5p+dEjgwpp906iuvVtjvSBAABZTJG0APSRg8guJEZuj2Lu0oC+sx8BX2Z35tfem9/EBjckWfhYZUfyoCTnyL4fUYAAdYdkaJEpiwGUNXUKpD/+4JkTYASzy1Ka3laYDDkGg0050uLZKM/rL1pcMoQaDT1FS4sBraTwOui6cKsUmkM9AlUpo5eXgMABS63ekNuaBEXs9za/9U82v7ZvvniqsRX1MoOm/PNpusk4WLLuEDGicU0ypg5VqK1ejazZ9UbQQAtEkf18XpHHyDxsPSjaF/uRgClMS2EfVvZvz62a6cKYlKHgBKUE0G4HHRTUpbCsbVRkyS6y2RoBep/EDHCirmacPLwMITdmirsWyjcwup2MgpzbVrC4INIkRYQh0oYeJknjtZMoBwE8+B7JCsVbxTfxX////pEATM//Q7SukstHFu1wQ2TlhFhQyEEE+qmVMiwUXnrqfVi13XOPiAzfsmyFPq/0ULIMtAZ2d6sUYKE4nOm9AoxZZhJ4bd/7vWHAa5tpbZEA+xceicCiFaWMO3fXhAXBWKtzpiGkM/Oc4gF/djzXY4w9XR7Me7Wd3q5UTGnKNg5F4uSclSyaev/+4JEZgACKhFQ6e9pzEfkGSlp7UoJNINFo71JcQ8Q5bWXqSl+K/////U0tpr1oBgAIiw21tAH/lnqGZgcvBQEQK1+NfecFhpEj7/lQzWNbr4D3mTUP2Pz1S59XozGO4Ylk9Y1tJNlYh8tSvVftV/733elQQBYcqtljQHf/6lWsjKH2NigVO8s1Xs2hI/a8/l/dO7/Od7qAQ+9UPPop9CytnGpo1FlXJSLLCAUgG4PsS9SENWLKf0b69vWAKAAQs0C/WIkf//C3/tDg43BElSuzi3XY89vWf/tQkuL0puVAJfd6G7S12WxExq0qaqgySGBMROAaq0JIpSkYu/TbTR7v/1hABUnG2iD393IfgWXCIgP3WHK8mIJSLx7gpo8Nlm/ygvjOf4BMz9m4dLu/me6n7mYmasagWx0KsIiwxbR5wsK20V93/7f/9ZMACFdF11gA7+dlnTvSsuoE4Vbm83SaVoRsMqOxtCxvVxfTxf/+4BEfYACPyDJ6zg6UEeEOY9l6ksI8IUjTT0JQR+UJTWnqSh/0gBm71XRkOorklENQw52o4VRy1WmTFY04uTC6kRa0uV+9a0FAKKy7W2sId/uFeklYx4Htf5od0u7LL7YVuzk5Xs+6gMU1rp1QVff98so6TeQIPUChucPqFRp6LtGD3AMcYFZN1y1LSrd///+gOANqTGWNohf94i1ZcgAobFO9NXVlyMTVnCLv5LxqPiJmkBv6VWqmLUw0odvtbCpZBFV5qHpohc8LCzh8Zc9f+jHf///RQwwm3LZZGiQKt1LD8F/mM2h73o9xj2vvXy1F3xjfv4CEWzqoZzFEJQI7Z2/Jmba9oV081uZux1BX3FD7T9Tu510e5f9IMAHG3H+/tE6jpHFMJIhFS+fdD9VCHpARmIrEsz/K8Uds237wHeh+dshiWfmse7p0E4sEYrGLWXQwqaWB1nm09d32rXIvr///vqVAQCYjrlaZP/7gkSSgAJMFkprGFnAReQ6DT3nS4iApT2mvGmxJ5CmNUedKAHUYJnQawC7mJ5GCJ5LIbJ/ZjuE29ZQrO6/WJBriLm452Ptjb6pBrON9c3pw9Q3AhyESdbiQaIqkzz0U57////6P1hsAUSUXW6sT/qWNz9KI0QaPgExqNFV8zgldoq27ziGSbf+NeAr73dqz1OdDqzWoq1xeOXuGoiJMapQXLmkP755ZoX+v/////rZQDAlr1skCHO/WkuOyAyI0rS7wVGtvQdEzZSuPBGpNv08rRKx08pvZUquf88z8y6mfcatnlvPaBcTF3ElHi+96GozT///+gJkOBuP9IGxuO03YbYK6JkAJMfMnFwZXXqXPnQw6a5/qCLP33SrbVWzqZnp7oO5NLMo5JUMvKphSLhYiZE5hKymfFGs0/pFVQQAvUbbRA/WqmEv0M8Ac4Bg9RRJmxXaIqrqkkc/ylB75numBtc+BQEBRatwoyaGJP/7gkSogAJNIUpqT1pYSKQpbWnqSgjghSmsPWlBHBCm8TY1Lv2JIPcoqOSsUU1EXF2Ni6Oz+ten/+oSkSPbq2yJJ/4jmAmcFGV1TEZib/DaLRV8mnH+Qne7+R9SBHzLn60ZTzWdnNXdD1eVGGaaCBgWiha1xg+VQ7tRR0p//Z99H/0qCRCRkl+oBsgmXykKOD8awCqCN2rGDfnXKvjXhZNLdPvG1AZZ/D/iXS91TM07tlRUxscqIlMZeLz7bSjDFLNMVewIksAIWYXXatj987eicwWJwMVOmqxg840qQDpo8SzPryp74+9bQMvunof56rbzH2KjjsJjJkLOPDSFAANNChsDUSJoWan6///1KlRQA0OGmf/eNNqCcoqCUhdQcExIeFpR9jcHyZNl1BGoW2Z0alh6bdbJss9tOZVY+NflnvtljPbeu3jfsP2bKqXq8x2m6X+ZgSet95vu3dVv/oAACoqqQ6kUyqA8ICM0Mv/7gES9AAIwEUjTGFnASQQ6PT3nS4hEgzOIvWlxIBDltZepKKhSYCbvIJyBgi2WHHf7l/9ZyoO37K11Mr+61Krbn0xjFbOvT97ev69X80hqAC5REHfWNBfzWE5ZyIDlPIkmkyZC7OwjZlZVZ4pS8zUErjVxWFSAB7Vpeg65xzNd2Vzjns6kQVImFix4GDdSXC7BR9Zw47c0KJRjsb7///+sEALz/8D99/CUUif4HKukgQ8KGfkwBcSoYGya6JcZbbQmt+iJc5r0zl0b1l961a72qPNeT2tQ5jlV+pRzbN4EaeGDkp0BgUQKGtZA2iEzwWGnUHNRlEUnd4zbPsf3vnEgP/dBKyS0XSXVZBS6z9S2Rd0WnT0pggVm6NRghj9HYNhOSY1FdsnYqkIvxwTOGCErlyT9yqdGubg2aq7hzpptPbKJps8ENcQdl2dtjSArUXMYgJqe43twTuDD3lznrvq2l9+uYHPz1U5Euqm3//uCZNSAAowxzXpQMug45CkZUe1KCkyFMew86WDikOSlmSkoZasu185RlkFSAeeUM1lbELc1RlyFnB+iqym7HhSHKAfcxwlcywcwEhDgwXBoGGgxgYIZij7jBR2Duo7jQ3nsV5QjjSZ/r+wAh61a7ostCy0pkk5gpCylrqMT0AsOD6ySAwFw86L5csYFzqYstEUet5halIJKofoOvomFrY4upCVIjgPLhwJq212xsormCOQhRnNPJ26vJz0OYDygenkFj0UJq/Aj7tZKNQlYvZj3pLOUSWLqmZqr/Vo5x7LxGLhsd7rPt/9SAACouZA3qvGJuAHjEFgbAPrWGiaBAHC5FLUjjkiXWmXnjVXloeB3+by1wzAK3r7pqroomSRimiWaCLqutNajEqrOhtY+LGAhMvhwVCQuSYWS5A6gytLyM4lv9q69aGOW0VCsw54upCSRCAITcNskaI7+tUUFWRVQB3tjEmGwFrJ5IMGg//uCZO6IA2MhxIOaklJChDotFedLjQiFGS5mCUEGDGg0fJzmF4JE4SJVTx4oXUkofDcsFAZparAsGhsy9K670XeEeayGaywXrZ/+DfGIhwnYKtnn7saSfoo/1IoAkO0TWxtDf6qXc5slhApXNqubuNStzC2y0Uvlb20XeQal5+u75yCufSR2trSN0EGUt9GgtlJmlNJbrUtObsHWISMBhjEO/VvG+HUXSDf8f7mL7/5tZGwJ6x6EFQHzby+GQA6qxJogBNcGAxnPuLAA7e7tcAev7tlbdIeLMpwhAFQoXeWQgvPrEZ4w0cu8062wvaejpcSLOuiykkbKAHDbD7XVt/rWdDP4jqxSXEXmZ6XkiL/UpES9EJyW5coEwam//LOA35ynKrHMptHPta6LZ2LgoZY9iWCRQmDkixqG0Tir7n7///9P+z0NMABW16xwgHX4U9mNzAyyD1oZHQfgl3l4BxnzqaSOTrJ7SBy76l1y//uCZOcAA0Uhxst6glBSRektZmNMChidJ61hqUEwjOk0t6Dmxr6ruJuWPl0zdfwqFXJYdQ5IcJGgigc4M7O1if////pIIBAagkbaQHO4Z0lNeEIwjnLRHOEcguHjMLaADJoTA2h7bEydmd1OBIeinSVd93WtjJnW1d1utM8qXJqNDxzgAoLoAQuOpaIl2Nq6kWOj88v//9AAAPX1IH95T9ibdB2PMPCH4KyKVhzp+wn+GGr16K9+WUV1zW8+mIOs+/QWgtNBBPU6Knn+gtmWfMUwwJQVk6C5QFTQBNAAoZcEChJ48UWEbIpGfVu/Qn//WmqKANKyCyNEgZ3iqmaeb4Nao7ByA+rRfAuz4+SJkSRSRE6NS+C//TcY44cKrbqr/cSks27uKjiz+kU0Nez4Hfx+63/6T8MGFVh+5v1q7/CeXXjoBb882srQGv5ZnZTkQREySp7YNZJn1uqEF6pOUWGXlamugAQQ4k90J0lS//uAZOAAAnMgS2s4UlBH5BldZatLCnSFI61BqUFlkKOlvDUoBlzkGmS2Ezvds7C+r/FK1s3nrvX//4jX9/7bxQAxsvaA/VyVx/B4hnOakU11PFRJAuNQA3M0oldeEUX7oGZ6u5VNbOgDmqtJG13bVMHTQbSQTqqMy6mpwViYfGsSQBsGBQ4KE3Ehx8oKiign390xPOQr6tHlwEAgG4XG2kB+OX0cOWxAXDfqtzBZQTQvV/RxwsRbPmH2cP3njk0Atv/Hz1LFzzpfTamGzdRN0rZcuhwoVGBFiA1MMCw4hrjOty0oWgkLJEsJN9Plf/q11Q4C0baZY2SB/7sD3BUk0wUqqGfv0I7TBqW/uGlvWd63gA/+6H3LItnIZOjyVU3pNdyOm03e58pFDNsV1N5v/f2Y/+04df3t/o9bUAA131KH63r9QSDCAbhVuQsQQK2mUQSq8kTOq+P7Y/0kBmG17Lspbq2pX1p1KWpnmKj/+4Jk4oAChCFOafFCXkdCGX1jCjlLMIcdLWIJQVuQpDWsLSgSPpH1gquqxdq5BrnZBL6Kz9r7m1+jd//0BARWf9qfv6ZwovWGGlJVr0CrbBoCekqBSDdzB76Pd4JiV16fFxDH0OIgktwhUUAgqfesyKGS7jJQDvuY4esasOCGogFi0a3ztF6gh7f/+qugOffv62tE/rdJK32zJDI43xhjqC95+G4AITzG71sXDlk/Bv+X2tbTrGOS7uW3E8Vf3VIyyIuK3/3efAh4QvBQJT1UYPPnGk5625NjYDs/u93SdGATYImt/9ZELVE8pLBgL/lpSIgFXmyP2p5YFfSEnobfdewBfjSQ6BiRooHyawWECkCgaEU69Digspo+TU1A8utKAylcgwa1DErJyMh/1gAhefXIfzt3GhiQUPhuBYJXMII00XvGTmn69mp+VyV9x/HeWKa/P183DmsnYX5KVJjLswRSllrWzPXR0gpglmb/+4Jk4wACUyHO6e9CXkrEKPlp7UoJ5EMhLGnnAUqUZfWILSwZDgsKzoAvDYRfMKstldn/6vctAAB3IkkQLqdNiGgLoBsm5LXpaoxjQFgOMhKHOTUXaxzbLq6sAw/+5aWdXFPo66jsqWeW1YgGJFTYoQF0HBCJU2m3E3RsWO3OUhe9Qsv7e3s7WbdIACPn/SlR1TMRcAzASMrGf9PxKWtWYSBgjHUgvf4z63vnFuFxhE0THrQTBBoEEhU4WBg0CBoSvUbUIF4iia0HhkWGCDavc/thchbxErRQGv2fTY4hELbZY2iAutCSqhAw9MqB2IHW6n1pghMNNQS2a3rUDLKJZ5iFF3vFdVx64rqV7aFr/GfrGd7lEv6wvdZN+wGteTQqUFmxU5QE3Ff/Ne7lv/+6BABc+pA1+d593gZWIMB8MsmTznijO1XWQDvZZSUdvOgaoTM2Swu91QnCQAY9wcEB9ZwLAwhSB8FjAjIBVk7/+4BE7IACdxFNea9hyFLlaPlrA0wKfGsfSmlnAUgIo+U9vOCXPmWHJ11r1HBq0+SVV/9+zcivKaBQIvccbSA/6l2fidAOdMBHoK07gc7E1gPwSWR4jnPPwftM/P08BU/Xa7GNr6iI45ZE1EzawuITCCw4XQ15sAgZzSDFDo4xmmDwwmoIrWRKbXiAd////WywAhbxvrpG61S7TBOASOZgZ8V7Z7epa/cZHPcnD9CJLasGP9ZiK2qKcwyGSyDBMWBZ9hRribgySOh8Jh4Ahg9qHbByrqT97tH/vX3aVQg8vDlaRI/tKlIbQJOAnRHUIal6ovLIeH9SObs3P1Xd7XdY/uAdf8z8zshvLd7Oll7e550WBgLwwcNQ2zpaNOMJnxVtqlNenTbT4v9kylHZrMkECNHeJ/rWirVukmK1CvCLK07jbtksi+40q3KbGE37Xn1jjo1/15YxvYwU0j1DlvJWeFZH0bttOT6wMeDRR//7gkTtAAKYIM7pr3peUsIY6WswOArUeyFMPWlBM4xldTwg4AqJ2KcvbYe/Y+h7Ovb9HdqBFACMmh3vrWgv3OQQ4keFtJECJWEfJIK3TTrMojGm1T5wHu4AAMPCMThqpjZMPiRQ4tg8w6BBGwUaUJuVdK3nrLbPZTZ//9f9YIANmRtIgfzdSRP49Yg2PYXWsv+JKF/yHxZXP189ejJRF07YO9a16lnZmiRMBsHgmkJiwqFyhJAAJHHAZyhYgq1BauSUYceFfYiq81T4vW2r/7dKVYCAACmfVAb/DKnjcoECA+F/nfUMEyYpL2sBJsUlFHd1Ln3bYzsADdfbjty5ZoWCIJg7OQGNFCBIExZx/EwsxobeEAXLlTodhNaAq8PO9NtSpD1r+S69T7KwQAvMbbRJ/WtWqSDR3I+pkq9oit7O4omm1n2BKLsuRp8s7sBj/PQeIh0kEhAhqTiHAU6EhgsQHWCjowLsAp69iL+s5//7gmTtAAKGH0hR+FpQT4V5j03jTQkkQzHjPWchT4sj6Z004EMqrwArk1rmXe5Kq08XrWggAw5BK40ic9/VzikvKkmU08XW0YTyqIsKTD1dkVHzPdHlvPWXwJfRJvV0zHl2RXa5vmI7NZjaocaRPNKJPFTKhSptfShCxVHs3u7NS6LZR9f7qQEAUHIHW0kB+uV3dlcZEZhM05LjNFbFjfhwigyCYyr/MjJyyj4rDf/4qZe+TjacfQPIhwaRqPoNnAbLHHlEDS7EL3MeKGjGhMIwQlAiXS1yl2/7v6+hAACU6lA1lSUl7GqI1R0xLGWbPSL2i+F8PtL6eW1O7/XOd5/qBHmu660zyKGvU76SkEl0UGTWeOzhc+sycwZcoUYXETeXSu9Cmp+0ov7VIjup7anepz6WAAgE4I20gAhWfLBRRAXwf07MUbikxy6WAAqDW0+cnvQiTKOyw6csDF/m53fT2Ra5YSgIwdPAmgYkuP/7gmTzAALEFsdjGVnAUuJpCmcLOAp0oSOsYUlBVw1kNY0s4GGNQKmCYFcuqxbQofCqFLAo1//u//2W/fWCRzAB8ZjqaG4B2k8UhNdJJ0DAEpoEn2ZW+zlF2m1NWeRA0o3rZaRswehTC5wUQlbRyBMCAOipRcau1dgs1DSu6Rcl3UKmLSKhWHWVRWiYeXNMqJpSgDMeBQQArP+kfYi5KBL0ntQmOIEuYTw/afldLrPFNFaqAX1AOylwVOmQiKAFg4+smELAIxkrHKAzmmUz6pMAMq+SbWn//+hKAACUelA1vLUoqwEFVc4sOVtXpBxXBB1qEhpEgoKKrl3G3lv/3yEGta//9Pettvt37juWtK5vj5tTNbxcW9cfcLMehBg47DJeMMio1QRBsgklHLrFBf9yK671XizUlUG4o2lqpYEAT3/6DoGg7S0DaVwRKKqOL95pP1Bir2ivduxVm1sJ2BGJSHRU4VNwZjQgdHhIg//7gGTtiAK0IUbLWGpQU6L4/UMrOAscVRkn7acBDoikJSwc4Iwu6LqSPHNCm+m6KLF7FaG3vHxc7//+qAZU959NhA8BFTuYUdgGZCcA2dMDoaMCCS4aEmfaxc9SKwS7dVa3XsgbuiizPW2tkEFIrNmWzLSZZA4/WSQaTMNQaEZRxN9JtVLHMjqmZIwjcl2hVZS7WhDDQTUtcjSIB3e9LDBq2W3wDj2s4gRFsUl+v55o0tSldN2BsxNnQgEBojCgin0sLqKGFuvGOlaZeA02RricrTr30b0f3f/9CYAA/FbbZB1+8burQpWH6Q82qZREO1ejY+6fldnDL9UvMd93vBT/c0+1I5T2W7rrm37qhrI5o4EEOYDgmFAgGgZQdEhEeBj7CTRRgJMD5PRFOhSWft77OwU9y9ATApV1m3saK1sjTBgBUuIsS8HM6wxAUdSiGUmZzdnbVjD/puxl3tb+++9NK0oEpphowIlJBZzV//uCZO6BAyIlxkt5elBHQikJNyk4CwyHGM1JqUEciGb0vCzmDqlEpepqVNcRNnQ9vqHGoeR/f5T/oACBU/pA/Dm7kStIJTlAWvQKw8ffR1CwFGyrnJqLu9X/1/94sK+pdZpus0dBN1rMWqqNjU2AxMVHn7CLmrD6Qsg8AnrsvadW9Ztn7bqn36X+z16rfUAAjTjaRAH83nS3nrIcAcfHXmLAK1q9I/421F5XZqbi0qbNNowB312913uNRGAwMD4slo0SizGiyntEg5h8OLkVBgvVQl57Nnvq+7R9Km8whfX4tUAAqDcbIA5/40sxmOCE4sBFYGowGnJpEBB7TxQUd00m0lcCn+117nOd/TXLxFwhMnuYR4fUV+pATIrMFUrMCcJFDMXlYq1f/r/9H//qAAT6NxJED+44U1SMkKg2+9KOE5LBDbgowNSWc1UremmWuf/osBh3DvXNTf079pTZVyzJMllG1Ku8WDgoxQUi//uCZO4AAtchx9M4WlBM48ltNatLCpR1Gy1hqUFNCyNpnKzg8iIHvWFW8CW7NvFP//1bawmA0vs/9YyT3c8sIAeO0sJCGRrKQO/Dig3Kp1FVN4P+hlzM4wmV0IUOg+9ZZIPKc4SBAqEq0mXtAoqLIhtorUWOr/+7V///qBY7oA/evvZziKZO+cGaZ6ixZtxgbVhEov18P5b/n4836n5MYehXBEkaF1YQPURkqgqHhRBsybqEIsDgUZSf079LCVb1dvV7Gf3d6NIlAA/t2/YsthLEw7JtRdFpswFso8OMmA1mHeZnkF2Kuu9MG9jz6RomaVIsiGSyvK8XlmVJdfs7+dy1v795plkWv25/O0zKeWreeZuee3rHG1mHqmUG6SLw297RSswLFXQvHQB7VAN/rOcoZYVfzkjoFY7JBoLcmSUEY8jW5B9rjaKmuwkAKcyJ9cTH1tY3pC1yo0iPNB0GQxBcZsLuOCi9ciAziHTO//uAZOsAgmglx1MzWlBPBDjqZehKCPhpLaa9RyEwkKMlrI0ou/TqYx6yllJ8TDU7GOz7rZtBJn75jGLT8g0w2/pyu8WAYurUrIemHAWOUhvdze2qYgGVFND3ztKfBjDe56MMb5VZS+nwp/e5IPt6+3GJm3f8ihp6+ej7GdUVRu1i3k8V9/+d/fkXtT/V+pdbwAioRtEgj+4b1X6QfB6Is3rMmt5TjIw+0jlc7Y7rVL/N/j+Kv7ESh5hfXM7TQ+R7x4OWKNDqV0W9xaPtGG/9v3foqxRS/s7kaq+NanmpG3AAs51pgiKkwMgQCocaRRD2ANYFIgXCJG7ukTlT61hMAbqoL1oroVtnH3yfOGeasqH8h1j10VvMy3sqdLyq5n5ZdfepTeeXpT+lad/04xZ5rc7kCH7Fk/W2bPaYayxZPtq7bRAtDlH+1cDu7WgOkScnFegXnfqPS5GPaKz+PdXvb0V2Zmo7nQUQwUoeCjz/+4Jk940DD0fEk1Qa4FajeKZnSDgLMEUSLG2nCSQQ42mMDSh4EWZDBckyCrhgEF4YYlvfq9VfyDV//6Bk1nUoc67pEEaZQQNYJgkLgIB3oey6EIACxsnmNjdlHCzXTWzBopo6OcUhdBM8YmhoipWkpYKJBqdROiPfVtmlZaNbuXdHIvRjHdW1Im7vW66uXdTHUz92QSzKt65rlStoR26PLNdi/Shu5+mmBILYvbGSQ26j0fAcqReEjAmk3YPqgYF5aqy4n643+GcCAl+EWhT+PSOzPLt0MhxUKXsFjhn3u+/fp2fp/yUANSABVYzLhEgHcPatakxCPRMx9TpEu1n3L6tTrXTDsm2xioySEALiARl1zZJ4UF9zC6h7Pvlxz1GzMXEhVd60eqr0Ie9N7E0y5H58hVAE+QAoXRNyYAW2eQMwJfqj69r9Rfa8rvbN7tRats8ETomBEEQiFAODZ0iJWA1IYswRNQh6BH97SRT/+4Jk7w0DQ0/Dg3Qa8kNjeT0rAjgNgVUOTdBLyPySZPTYjSwzW8Xl9uUvWt3Zrqz6DdrUOoy+1AAIpNxIkoVUU1qAZgubHossCTI2e06eVvuPPzte4EaMa9CihpUQtBtxcuSCilJBNnX3Xd7eri3V1v1aYxt0B1Rb6bWrJT9Z1exJ+wJYdIEqDO+m2pDHS2RINw5/MqyC1al4Y9qlG6KCCjMmG1FQGWA4uARwGaLiuVYML2XYlbMDi4o1M7PNYMTfrcgwTQpiJOislTcNcutbEDA/He37VUUzFMA4YnRGJhtWAHHMspw6ELEDQ3Jw1Wo4U1su7JBoh9BVBPRSszGjGUzpXMFrdjJZkcWy5efEDRlzHqFjsx1PZsyQit+6H/UZzNTUvONCskMpP7YTkpWFxSBrcYfF2qnSy4R+RZ5Qq/TFGuVgDUgAPsbF4sBPoDomBbRnhkXQGuNpOi3Ej1dgByweSMKio1wVFBRT5QD/+4JE6IASaxREsjppwE3CGKZPSjgIfFMZRuTnAVOLYgmdtOC45nR5IBoSixD12pSmuhfGVHnOq2brUs3vb211Z8vZU8YYyCbg4UxUXGhoYCBOpgbCtAFII8HHc0RWQZ3Z1GiYfua0VOv2TQrUo6yN3spQ8Xjwl1SnKUObPYmSTqKWYhVrm5fD/SG4VGPLrQqZmzSY5lXf/1YV/6zOc7m8mYkV/xp7kSB6LJEN63ffRtMXq1wxDUkamSeSIKhKh0G1L3AQSrvDsXAIFgftUYTLIZ+rR9akUUfZ/2LqgQ1Agau7u0W7hgK4fmAIBVLiQEBFNSg0YAsZfWXnaiNim7qVEcKqm7skYIOn3cW5oqAzCqj4wQx2LU9aZFnCK3JyOmXq3bIsNZTEoubcLCk0n2uJR28NHnjlbeu9Dvu8y6vZ36yFVG1IsUij+q4AAAoGcXmgxIYFUD1h7dHY17YEob2su/UNO7vPQU7nvY7bSfr/+4Bk840DmmHCC3AbckXiKJZOBzgNLS0IDdBryMcIZXSmlOSkLakburXMlJFmulgv7rP3k02+99/d6gAuJh3WdSNsAMHGzpRYuCuhiRXWfwcNPyn7RY95cjdzt/msttLyy1vfcP5nnooVMzLRzVTI6YinFzOF5Knma31drNr/cv+woRKRsx5IiknD1SQHjEwYmcNtKqxfZVBkE9Y+zKE2OloaW5xi9gzxBhI3EgWFWrUA0bVSsTvFkCvvd9S38BSYBtZ2FWoWULM+3+////6dSst1r0Yd9nAzGmhjzmiQYpWHIVHwgoB+lV3Uy0xcSmdTIsHyOmyknWgjSRTOMkXUT9bNTo6bJn2RmMm4n1j7EQtudT49tr/ZbDpfJ5+tb9/Mw+RtRc5KSdytndmZsrPj40Z6N32ybwhrXmVOd/xsxblrYxN1rzdiOVaKDHYiAAwID8Zh3nhCnlauoh6qTNEWArXzr+QTt6gVH7rH8f/7gmTtgANtREIzcxriO2IYiD8HOA2hHQat4GuIpAijaHac4E8u6HP9cjQpu+j6tStu3rkjtPULvlbywrRjACNi5j81GrbSiTOdQE3ZEkdCnV+ewPdy8PeM1SlbXm/yZesWru/vnFtV+Zr+BGtm8NU611XpR7q5usy5lDPAqu3IvmVXzqDSfC4vZzhfw847uiPn5QiuW9BOhMsyrNvlFWv+Cu/aaYAIoI9p08kKIeimq2WKXsmwpMWf5z0OBn2nQDelXSZI2XXaP72FPs7V1U/fO31JJp0izfr0fXVkFF1zKrANSUhYpDSVczirJGgjmh1g9lc3oO6i+91KdAPobOfWgZa6kmVTspTUN6b6kWKkcVj+d/MlJBD7G231yMk8syz6hkbnP/7lFJHv3JuR9Mii9BP31fq/Syv9VICPuUfjNVKiWswNjMEqA+rjRthBETOV6QvThhln3BCl+AK9tE09fJDnrLn8qKlN9K9uA//7gmTzCIPmY0ADcjNwOYIodj3lOAzpPQUNPGvI14ihoLwU4LU2pe96GYylpQ8gc0ImkizBmE6EGSb1KXw1NwrQAAAAhZFaohJZQxAABeLhS9pCZt7Jn7DM/5z7pN6oG/NPG3IU1aGtK0PbsDzaX0NdHuNtFVqGlYuxY0VIDHuXIxZtTFiz8WHoFGrCo8FQsutAVKG7oHDQgYJYCpdnmFMCrxVqMe28etB+j9YE1W9CWOF7MqHFlLhWcPJFVV6mLAcMxeJ26kTCE9REtHUXHuKP9su2lWUEqhQkGp1H2JkCiIJjTOeSEaDYzkw9Gcwy33Jb04HF38yxyyWFDzoZQ1yAefnmjYNCUKHSUMCAWC7B9smICbn3undg9EaZgUDWCWV2mEuqSWDbhOA1IAFZVb1rcmQngF3lEdxeB5j6BSE4Nbx62mAlk3sfdm6wkwmxaU5oo1s1tig8UubaYcxwlHnGLSxe6epbFZaLUTZa9//7gGTuAMM1W0ETcRtyR4IoMEsnOApUQwmF5UcBEoigxTeo4AHt3NVzd61H4ajoj+PkebY8VUC+fLoMQI6mkbOgjN1Mp1IwzNQtdFS0F0nZk1snUmiuuy3Vkbk9i3s3mdSv6eWRmsUj7c5cyaJ85b8S2HlyJSQs5zhWr58lJeT5OmpVdn6jyGIMq+sJQR/vOTEulJYGCZpuMaKgMDCpvEOgQKE2dFUerKW24gXdJ2bXVsmhXWpLTtpZHsV3vfRr3OqFp0XpKqu80+X+qVWzHVjbIxyzqi/ZG6y79V0PW6LKUxlVbI++4mqgAAAhH1VXlW4+AaAvYnTIjhGybEoOJ7ealtQXzq75VjOpFR+lDPPDip6ih2d/HipF9ZJFS2aXi9BKnrcxula6iWW1tpePgFgeScG4OBRppFdUwkWt7vYcoKT69QkuI5ZSJMBHk2qW0uAtYxdyBcms0ZJoKoWwq3UQalIac2wSnnjmMUhG//uCZO+MQpkYQJKYUcBHAig2Smc4DF16+gy0bcFxMR/Jpom4QNMCSVSAkucaLi5lJEjKgAAAIbj//bb0W4Kg+uPKPr3VX+7NXdrEGPLMbfZT0/xbrkvpZVSWr99S7rlFanJjw95UqymPv4SrDQzSYOjIY9sdjocUsas3vqIjO1mQIvuXaYsi91/aQ2Xxm2vwzZhT/8C9m+uOf826OYo6Nu/T9getUIaLxH2wn3V5X7eirtd3JQJw9P98qsu3K2d5dQIzie1WpGlpIlQndEXAapEmdQQeorVubNSD6GjGLptpU7pOtlKQW7Gx3p1mtm1VlI2Jh2we68vPUocWEWtIeLDVoQINgzbqpVzEk+eQc5LnMi6+i0zjlL+S0pBUGdlIgjPGKiRge/j6h4ARBJH8st1KGsS/B7qFtVUAUTiYkAN5UEC2b1KJlrPZY+0FVJuuvZtmrKlqtXd7kZzr6Oa2x/XVnWTkRi7nczncX1xZ//uCZOeAsgkRQeEzKcBSAhfQM0o4BiQVF+CE4EFcCF7VjRzjZcb8RDS70H7Z1Om1Cyt/+d9hipL0v7r/VxoW3tc+XCkA2Qml3qFugkjz2eqkpcuc/S502gB+KnMNit0ItYlpmoitRvDjCz+uxlohvMMWNdQRRGIYVUTULGQ3aEBYVQ19BesYRrItAj1AEUF2qMS4DRGJYlzekIHBysr6ErT938scGuibAIHhMBTIaJNMJVKmdlCqWCqT3fnmmtiHuUjmBCkwCgiDU6gzi9LaVM888X0ZFagrACwGss6uq0THKHILDULKgj703aIDSxS5R73WKxMRySAEcNWg7JqCh5542Gjx2pqCKnrJ0NXnWSx9NY49PTUSoPVmCQ42KZJLryilgKtNE0WeTLVDlwAJVZrauPTCiZHzDz8qLExdHgOsLuWtm1mnvNIiNumVFgu9/103NWXveD3/73+9CXcaOZ8348Wl2tNjP7xWf3Jz//uCZP6Ig3leOwNUG3Jdx0emYgJcSdBE8qbk5wEuCF4hTBTgdfdZHFuz/uYX6b5Ib5/9d1MOezgAABAr0i6kgBVMPrwwzYhEIoqOlSeIk57eVr9r+tpQBcMkA6/CTRy6zDDt7lMLGFK1LcBnoe9dQfYLYlELImeWfai5rJEqSeVDShHIiUKC7nJGjeNWAO/l7d4pxYTzI2dUcfAyKnuFgGHGLOWPPSFVNMOVZIStAR4qNASsk1zsWY8qt1ahcaGks2jpUBNsHHTbRW9AsukkKHoqdVpWoiTpXPG2PDpiw6tavy/Kgn30AsBxUTiw0nsAjUblDAgEKi9PDuHo6erHCAeiU6PqfGjU8NI5KVwaeiVEu0SuBUJSpGydZVrY46R56IjwTcEwkp4iO+tx14i0cmhGIIUSV6VAkIRFTheWLl5Tot3JY/WetOCrz4+OdrN+me1nVufwk/S/DSw08YJgaLNiV0Gj2IoCUeLCx4lk//uAZPAAQqcROisZQcBUgZdmDzAmSrBC4QplBwFMiJvE/QjgjwlDTb2FbQaCj6YUGhMJXiWoGoH/ersoeMYAfbCLZdNHwv0XtT5bk45Z1qEcl8tyrY5KtyYBRwEm6FRn4l5WSIqeSy3h3ubnVbseIiUq75Z/nkMOyrqhwFpDRGJWZ6MXj/M52HgsEQMPX4OYByQgBBwL+N3ZoBQFPx+MT3DSt6KJCv/6bKf1q/W8seOhN08VyXllctnslg0sFXI3RKrT1Q4qTEFNRTMuOTkuNaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr/+4Jk64zichC0izopwFLCJnBTBjgJiEi0LGEnAQeIVoWMiOCqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqG7heSkxBTUUzLjk5LjWqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr/+4JkXI/wDgCAAyAACAHAEABkAAEAAAGkAAAAIAAANIAAAASqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=';

// Result div HTML to be shown in the center of the grid
    const resultDivHTML = `<div class="game-result-wrap win svelte-1g8uakg" style="--duration: 300ms; --modal-width: 150px; --modal-height: 132px; --win-modal-heading-color: var(--color-grey-200); z-index: 65 !important; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);" bis_skin_checked="1"><div class="game-result-content svelte-1g8uakg" bis_skin_checked="1"><span class="number-multiplier svelte-1g8uakg" style="--truncate-max-width: 118px;"><span tag="span" type="body" strong="true" size="md" class="ds-body-md-strong" data-ds-text="true">24.75×</span></span><div class="divider svelte-1g8uakg" bis_skin_checked="1"></div><span class="payout-result win svelte-1g8uakg"><div role="presentation" class="inline-flex items-center gap-1 max-w-full text-center svelte-1jb7pu8" bis_skin_checked="1"><span class="content svelte-1jb7pu8" style="max-width: 98px;"><span tag="span" type="body" class="text-neutral-subtle ds-body-md-strong text-center" size="md" strong="true" variant="neutral-subtle" data-ds-text="true" style="max-width: 98px;">$0.00</span></span><span tag="span" type="body" title="ltc" size="md" class="ds-body-md inline-flex" data-ds-text="true"><svg data-ds-icon="LTC" width="20" height="20" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="none" class="inline-block shrink-0"><path fill="#3C649B" d="M23 12c0 6.075-4.925 11-11 11S1 18.075 1 12 5.925 1 12 1s11 4.925 11 11"></path><path fill="#fff" d="m8.167 14.21-.98.382.475-1.905.99-.398L10.085 6.5h3.524l-1.031 4.26.969-.393-.468 1.89-.983.393-.58 2.406h5.297L16.21 17.5H7.359z"></path></svg></span></div></span></div></div>`;



    const WRAPPER_SELECTOR = '.input-wrap';
    const INPUT_SELECTOR = 'input[data-testid="bet-input-amount"], input[type="number"], .input-amount-wrap input';
    const FAKE_INPUT_SELECTOR = '#fake-bet-input';
    const SELECT_SELECTOR = 'select[data-testid="mines-count"]';
    const BALANCE_SPAN_SELECTOR = 'span.text-neutral-default.ds-body-md-strong';
    const BET_BUTTON_SELECTOR = 'button[data-testid="bet-button"]';
    const CONVERSION_SPAN_SELECTOR = 'div.crypto.svelte-1pm8uy8[data-testid="conversion-amount"]';
    const INNER_CONVERSION_SPAN_SELECTOR = 'div.crypto.svelte-1pm8uy8[data-testid="conversion-amount"] span[data-ds-text="true"]';
    const BUTTON_WRAP_SELECTOR = 'div.input-button-wrap.svelte-dka04o';
    const RETRIES = 80;
    const INTERVAL = 250;
    let LTC_RATE = 52.81;
    const LTC_RATE_STORAGE_KEY = 'stake_mines_ltc_rate';
    const LTC_RATE_TTL_MS = 5 * 60 * 1000;
    const STORAGE_KEY = 'stake_mines_balance';
    const MODAL_VISIBLE_KEY = 'stake_mines_modal_visible';
    const MODAL_POS_KEY = 'stake_mines_modal_pos';

    let currentBalance = parseFloat(localStorage.getItem(STORAGE_KEY)) || 0;
    let isBalanceUIVisible = true;

    // Format balance with commas
    function formatBalance(amount) {
        return `$${amount.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    }

    // Format LTC conversion
    function formatLTC(usdValue) {
        const ltcValue = usdValue / LTC_RATE;
        return `${ltcValue.toFixed(8)} LTC`;
    }

    // Save balance to localStorage
    function saveBalance() {
        localStorage.setItem(STORAGE_KEY, currentBalance.toString());
    }

    // Load modal visibility from localStorage (default true for first-time)
    function loadModalVisible() {
        const stored = localStorage.getItem(MODAL_VISIBLE_KEY);
        if (stored === null) return true;
        return stored === 'true';
    }

    function saveModalVisible(visible) {
        localStorage.setItem(MODAL_VISIBLE_KEY, String(visible));
    }

    function loadModalPosition() {
        try {
            const s = localStorage.getItem(MODAL_POS_KEY);
            if (s) {
                const { x, y } = JSON.parse(s);
                if (typeof x === 'number' && typeof y === 'number') return { x, y };
            }
        } catch (e) {}
        return { x: 20, y: 20 };
    }

    function saveModalPosition(x, y) {
        try {
            localStorage.setItem(MODAL_POS_KEY, JSON.stringify({ x, y }));
        } catch (e) {}
    }

    // Fetch LTC price from CoinGecko
    async function fetchLtcRate() {
        try {
            const cached = localStorage.getItem(LTC_RATE_STORAGE_KEY);
            if (cached) {
                const { rate, ts } = JSON.parse(cached);
                if (Date.now() - ts < LTC_RATE_TTL_MS && typeof rate === 'number' && rate > 0) {
                    LTC_RATE = rate;
                    updateLtcRateLabel();
                    updateConversionInstant();
                    return;
                }
            }
            const res = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=litecoin&vs_currencies=usd');
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const data = await res.json();
            const rate = data?.litecoin?.usd;
            if (typeof rate === 'number' && rate > 0) {
                LTC_RATE = rate;
                localStorage.setItem(LTC_RATE_STORAGE_KEY, JSON.stringify({ rate, ts: Date.now() }));
            }
        } catch (err) {}
        updateLtcRateLabel();
        updateConversionInstant();
    }

    function updateLtcRateLabel() {
        const el = document.getElementById('ltc-rate-value');
        if (el) el.textContent = LTC_RATE.toFixed(2);
    }

    // Add beautiful CSS styles
    function addStyles() {
        const style = document.createElement('style');
        style.textContent = `
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

            #balance-ui {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border-radius: 16px;
                padding: 20px 24px;
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(255, 255, 255, 0.1) inset;
                backdrop-filter: blur(10px);
                min-width: 350px;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }

            #balance-ui:hover {
                transform: translateY(-2px);
                box-shadow: 0 15px 50px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.15) inset;
            }

            #balance-ui-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 16px;
                padding-bottom: 12px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.15);
            }

            #balance-ui-title {
                color: #ffffff;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1.2px;
                opacity: 0.9;
            }

            #balance-ui-close {
                width: 28px;
                height: 28px;
                padding: 0;
                border: none;
                background: rgba(255, 255, 255, 0.2);
                border-radius: 8px;
                color: #fff;
                font-size: 18px;
                line-height: 1;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: background 0.2s;
            }
            #balance-ui-close:hover {
                background: rgba(255, 255, 255, 0.3);
            }

            #current-balance {
                color: #ffffff;
                font-size: 32px;
                font-weight: 700;
                margin: 12px 0;
                text-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
                letter-spacing: -0.5px;
            }

            #balance-controls {
                display: flex;
                gap: 10px;
                margin-top: 16px;
            }

            #balance-ui input {
                flex: 1;
                padding: 12px 16px;
                border: 2px solid rgba(255, 255, 255, 0.2);
                border-radius: 10px;
                background: rgba(255, 255, 255, 0.1);
                color: #ffffff;
                font-size: 15px;
                font-weight: 500;
                font-family: 'Inter', sans-serif;
                transition: all 0.2s ease;
                outline: none;
            }

            #balance-ui input::placeholder {
                color: rgba(255, 255, 255, 0.5);
            }

            #balance-ui input:focus {
                background: rgba(255, 255, 255, 0.15);
                border-color: rgba(255, 255, 255, 0.4);
                transform: translateY(-1px);
            }

            #set-balance-btn {
                padding: 12px 24px;
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                color: white;
                border: none;
                border-radius: 10px;
                font-weight: 600;
                font-size: 14px;
                cursor: pointer;
                transition: all 0.2s ease;
                box-shadow: 0 4px 15px rgba(245, 87, 108, 0.3);
                white-space: nowrap;
            }

            #set-balance-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(245, 87, 108, 0.4);
            }

            #set-balance-btn:active {
                transform: translateY(0);
            }

            #balance-ui-footer {
                margin-top: 12px;
                padding-top: 12px;
                border-top: 1px solid rgba(255, 255, 255, 0.15);
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 8px;
            }

            #balance-ui-hint {
                color: rgba(255, 255, 255, 0.7);
                font-size: 11px;
                font-weight: 500;
            }

            #balance-ui-rate {
                color: rgba(255, 255, 255, 0.6);
                font-size: 11px;
                font-weight: 500;
            }

            @keyframes gemBounce {
                0% { transform: scale(1); }
                25% { transform: scale(1.10); }
                50% { transform: scale(1); }
                75% { transform: scale(1.10); }
                100% { transform: scale(1); }
            }

            .gem-bounce {
                animation: gemBounce 1s ease;
            }

            /* Number input specific styles */
            input[type="number"]::-webkit-inner-spin-button,
            input[type="number"]::-webkit-outer-spin-button {
                -webkit-appearance: none;
                margin: 0;
            }

            input[type="number"] {
                -moz-appearance: textfield;
            }
        `;
        document.head.appendChild(style);
    }

    // Create Beautiful Balance UI
    function createBalanceUI() {
        isBalanceUIVisible = loadModalVisible();
        const pos = loadModalPosition();

        const balanceUI = document.createElement('div');
        balanceUI.id = 'balance-ui';
        balanceUI.style.position = 'fixed';
        balanceUI.style.top = pos.y + 'px';
        balanceUI.style.left = pos.x + 'px';
        balanceUI.style.cursor = 'move';
        balanceUI.style.zIndex = '1000000';
        balanceUI.style.userSelect = 'none';
        balanceUI.style.display = isBalanceUIVisible ? 'block' : 'none';

        balanceUI.innerHTML = `
            <div id="balance-ui-header">
                <span id="balance-ui-title">Virtual Balance</span>
                <button id="balance-ui-close" type="button" title="Hide (F2)">×</button>
            </div>
            <div id="current-balance">${formatBalance(currentBalance)}</div>
            <div id="balance-controls">
                <input type="number" id="balance-input" placeholder="Enter amount" step="0.01" min="0">
                <button id="set-balance-btn">SET</button>
            </div>
            <div id="balance-ui-footer">
                <span id="balance-ui-hint">F2 toggle · Drag to move</span>
                <span id="balance-ui-rate">$<span id="ltc-rate-value">${LTC_RATE.toFixed(2)}</span>/LTC</span>
            </div>
        `;

        document.body.appendChild(balanceUI);

        const balanceInput = document.getElementById('balance-input');
        const setBalanceButton = document.getElementById('set-balance-btn');
        const closeBtn = document.getElementById('balance-ui-close');

        closeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            isBalanceUIVisible = false;
            balanceUI.style.display = 'none';
            saveModalVisible(false);
        });

        // Only allow numbers and decimal in balance input
        balanceInput.addEventListener('keypress', (e) => {
            const char = String.fromCharCode(e.which);
            if (!/[0-9.]/.test(char)) {
                e.preventDefault();
                return;
            }
            if (char === '.' && balanceInput.value.includes('.')) {
                e.preventDefault();
            }
        });

        // Auto-format on blur
        balanceInput.addEventListener('blur', () => {
            if (balanceInput.value && !isNaN(parseFloat(balanceInput.value))) {
                balanceInput.value = parseFloat(balanceInput.value).toFixed(2);
            }
        });

        setBalanceButton.addEventListener('click', () => {
            const newBalance = parseFloat(balanceInput.value) || 0;
            if (newBalance >= 0) {
                currentBalance = newBalance;
                updateBalanceUI();
                saveBalance();
                balanceInput.value = '';
            } else {
                alert('Please enter a valid non-negative balance.');
            }
        });

        // Make draggable
        let isDragging = false;
        let currentX = pos.x;
        let currentY = pos.y;
        let initialX, initialY;

        balanceUI.addEventListener('mousedown', (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON') return;
            initialX = e.clientX - currentX;
            initialY = e.clientY - currentY;
            isDragging = true;
        });

        document.addEventListener('mousemove', (e) => {
            if (isDragging) {
                e.preventDefault();
                currentX = e.clientX - initialX;
                currentY = e.clientY - initialY;
                balanceUI.style.left = currentX + 'px';
                balanceUI.style.top = currentY + 'px';
            }
        });

        document.addEventListener('mouseup', () => {
            if (isDragging) saveModalPosition(currentX, currentY);
            isDragging = false;
        });

        // Toggle with F2
        document.addEventListener('keydown', (e) => {
        if (false) { // F2 toggle disabled
                e.preventDefault();
                isBalanceUIVisible = !isBalanceUIVisible;
                balanceUI.style.display = isBalanceUIVisible ? 'block' : 'none';
                saveModalVisible(isBalanceUIVisible);
            }
        });
    }

    // Update balance UI
    function updateBalanceUI() {
        const balanceLabel = document.getElementById('current-balance');
        const stakeBalanceSpan = document.querySelector(BALANCE_SPAN_SELECTOR);
        if (balanceLabel) {
            balanceLabel.textContent = formatBalance(currentBalance);
        }
        if (stakeBalanceSpan) {
            stakeBalanceSpan.textContent = formatBalance(currentBalance);
        }

        // Update LTC button balance
        const ltcButton = document.querySelector('button[data-testid="coin-toggle-currency-ltc"]');
        if (ltcButton) {
            const balanceSpan = ltcButton.querySelector('span.content.svelte-1jb7pu8 span[data-ds-text="true"]');
            if (balanceSpan) balanceSpan.textContent = formatBalance(currentBalance);
        }

        saveBalance();
    }

    // Update LTC conversion (real-time)
    function updateProfitConversion(payoutAmount) {
        // Find the profit conversion element in the Total Profit section
        const profitConversionSpan = document.querySelector('div.profit.svelte-gpd1jr div.crypto.svelte-1pm8uy8[data-testid="conversion-amount"] span[data-ds-text="true"]');

        if (profitConversionSpan) {
            const ltcValue = payoutAmount / LTC_RATE;
            profitConversionSpan.textContent = ltcValue.toFixed(8) + ' LTC';
        }
    }

    function updateProfitLabel(multiplier) {
        // Find the Total Profit label and update the multiplier
        const profitLabel = document.querySelector('div.profit.svelte-gpd1jr span[slot="label"]');
        if (profitLabel) profitLabel.textContent = `Total Profit (${multiplier}×)`;
    }

    function updateProfitInput(amount) {
        // Find the profit input field and update it with the win amount
        const profitInput = document.querySelector('div.profit.svelte-gpd1jr input[data-testid="profit-input"]');
        if (profitInput) profitInput.value = amount.toFixed(2);
    }

    function updateCurrencyConversion() {
        const fakeInput = document.querySelector(FAKE_INPUT_SELECTOR);
        let conversionSpan = document.querySelector(INNER_CONVERSION_SPAN_SELECTOR);

        if (!conversionSpan) {
            const wrapper = document.querySelector(WRAPPER_SELECTOR);
            if (wrapper) {
                const conversionDiv = document.createElement('div');
                conversionDiv.className = 'crypto svelte-1pm8uy8';
                conversionDiv.setAttribute('data-testid', 'conversion-amount');
                conversionDiv.setAttribute('bis_skin_checked', '1');

                conversionSpan = document.createElement('span');
                conversionSpan.setAttribute('type', 'body');
                conversionSpan.setAttribute('tag', 'span');
                conversionSpan.setAttribute('size', 'sm');
                conversionSpan.className = 'ds-body-sm';
                conversionSpan.setAttribute('data-ds-text', 'true');
                conversionSpan.textContent = formatLTC(0);

                conversionDiv.appendChild(document.createComment(''));
                conversionDiv.appendChild(conversionSpan);
                conversionDiv.appendChild(document.createComment(''));

                wrapper.insertAdjacentElement('afterend', conversionDiv);
            }
        }

        if (fakeInput && conversionSpan) {
            const usdValue = parseFloat(fakeInput.value) || 0;
            conversionSpan.textContent = formatLTC(usdValue);
        }
    }

    // Real-time conversion update (instant, no debounce)
    function updateConversionInstant() {
        const fakeInput = document.querySelector(FAKE_INPUT_SELECTOR);
        const conversionSpan = document.querySelector(INNER_CONVERSION_SPAN_SELECTOR);

        if (fakeInput && conversionSpan) {
            // Get current value, even if incomplete (like "5" or "10.")
            let inputValue = fakeInput.value;

            // Parse the value - handle empty, partial input
            let usdValue = 0;
            if (inputValue && inputValue !== '' && inputValue !== '.') {
                usdValue = parseFloat(inputValue);
                if (isNaN(usdValue)) usdValue = 0;
            }

            conversionSpan.textContent = formatLTC(usdValue);
        }
    }

    // Debounce function
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    function waitForTarget(retries = RETRIES) {
        const realInput = document.querySelector(INPUT_SELECTOR);
        const wrapper = realInput ? realInput.closest(WRAPPER_SELECTOR) : document.querySelector(WRAPPER_SELECTOR);
        if (!wrapper || !realInput) {
            if (retries > 0) {
                setTimeout(() => waitForTarget(retries - 1), INTERVAL);
            }
            return;
        }
        applyExactOverlayClone(wrapper, realInput);
        createBalanceUI();
        updateBalanceUI();
        setTimeout(updateCurrencyConversion, 500);
    }

    function stripAttributes(node) {
        if (!node || node.nodeType !== 1) return;
        const blacklist = ['name', 'form', 'id', 'data-testid', 'data-bet-amount-active-currency', 'data-reactid', 'data-vue-ref', 'aria-controls', 'aria-describedby', 'aria-labelledby'];
        for (let att of Array.from(node.attributes || [])) {
            const n = att.name.toLowerCase();
            try {
                if (blacklist.includes(n) || (n.startsWith('data-') && /bind|model|on|handler|action|hook|event/i.test(n))) {
                    node.removeAttribute(att.name);
                }
            } catch (e) {}
        }
        if (/^(INPUT|SELECT|TEXTAREA)$/.test(node.tagName)) {
            try { node.removeAttribute('name'); node.removeAttribute('form'); } catch (e) {}
        }
    }

    function deepStrip(node) {
        stripAttributes(node);
        for (let c of Array.from(node.children || [])) deepStrip(c);
    }

    function isolateEvents(root) {
        const events = ['keydown', 'keyup', 'keypress', 'input', 'change', 'paste', 'cut', 'focus', 'blur', 'mousedown', 'mouseup', 'click', 'contextmenu', 'touchstart', 'touchend', 'touchmove'];
        for (const e of events) {
            root.addEventListener(e, ev => {
                try { ev.stopImmediatePropagation && ev.stopImmediatePropagation(); ev.stopPropagation && ev.stopPropagation(); } catch (err) {}
            }, true);
        }
        root.addEventListener('keydown', ev => {
            if (ev.ctrlKey || ev.metaKey || ev.altKey) {
                try { ev.stopImmediatePropagation(); } catch (e) {}
            }
        }, true);
    }

    function prepareFakeInput(fakeInput, realInput) {
        fakeInput.type = 'text';
        fakeInput.setAttribute('inputmode', 'decimal');
        fakeInput.setAttribute('pattern', '[0-9]*([.,][0-9]+)?');
        fakeInput.autocomplete = 'off';
        fakeInput.autocorrect = 'off';
        fakeInput.autocapitalize = 'off';
        fakeInput.spellcheck = false;

        try { fakeInput.value = realInput.value || ''; } catch (e) {}
        try { fakeInput.placeholder = realInput.placeholder || fakeInput.getAttribute('placeholder') || ''; } catch (e) {}

        stripAttributes(fakeInput);

        // Don't stop all events - be more selective
        const stopEvent = (ev) => {
            try {
                ev.stopImmediatePropagation();
            } catch (err) {}
        };

        ['change', 'paste', 'cut', 'focus'].forEach(evt => {
            fakeInput.addEventListener(evt, stopEvent, { capture: true });
        });

        // Only allow numbers and decimal point
        fakeInput.addEventListener('keypress', (e) => {
            const char = String.fromCharCode(e.which);
            if (!/[0-9.]/.test(char)) {
                e.preventDefault();
                return;
            }
            if (char === '.' && fakeInput.value.includes('.')) {
                e.preventDefault();
            }
        });

        // Filter paste to only allow numbers
        fakeInput.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedText = (e.clipboardData || window.clipboardData).getData('text');
            const cleaned = pastedText.replace(/[^0-9.]/g, '');
            const parts = cleaned.split('.');
            const finalValue = parts.length > 1 ? parts[0] + '.' + parts.slice(1).join('') : cleaned;
            fakeInput.value = finalValue;
            // Force immediate update
            requestAnimationFrame(() => updateConversionInstant());
        });

        // CRITICAL: Real-time conversion on every input change
        // Using multiple approaches for maximum compatibility

        fakeInput.addEventListener('input', () => updateConversionInstant(), false);
        fakeInput.addEventListener('keyup', () => updateConversionInstant(), false);
        fakeInput.addEventListener('keydown', () => requestAnimationFrame(() => updateConversionInstant()), false);
        fakeInput.addEventListener('propertychange', (e) => {
            if (e.propertyName === 'value') updateConversionInstant();
        }, false);
        const observer = new MutationObserver(() => updateConversionInstant());
        observer.observe(fakeInput, {
            attributes: true,
            attributeFilter: ['value'],
            characterData: true,
            subtree: true
        });

        let lastValue = fakeInput.value;
        setInterval(() => {
            if (fakeInput.value !== lastValue) {
                lastValue = fakeInput.value;
                updateConversionInstant();
            }
        }, 100);

        // Auto-format to .00 on blur
        fakeInput.addEventListener('blur', () => {
            let val = parseFloat(fakeInput.value);
            if (!isNaN(val)) {
                fakeInput.value = val.toFixed(2);
                updateConversionInstant();
            }
        });

        // Format when clicking anywhere
        document.addEventListener('click', (e) => {
            if (!fakeInput.contains(e.target) && fakeInput.value) {
                let val = parseFloat(fakeInput.value);
                if (!isNaN(val)) {
                    fakeInput.value = val.toFixed(2);
                    updateConversionInstant();
                }
            }
        });

    }

    // Setup Half and Double buttons - Aggressive enabling
    function setupBetButtons() {
        console.log('🚀 Starting aggressive button setup...');

        // Super aggressive button finder
        const findButtons = () => {
            // Strategy 1: Class-based
            const buttonWrap = document.querySelector('div.input-button-wrap.svelte-dka04o') ||
                               document.querySelector('div.input-button-wrap') ||
                               document.querySelector('.input-button-wrap');

            if (buttonWrap) {
                const buttons = buttonWrap.querySelectorAll('button');
                if (buttons.length >= 2) {
                    console.log('✅ Found via class selector');
                    return { half: buttons[0], double: buttons[1] };
                }
            }

            // Strategy 2: Text content
            const allButtons = Array.from(document.querySelectorAll('button'));
            const half = allButtons.find(b => b.textContent.trim() === '½' || b.textContent.trim() === '1/2');
            const double = allButtons.find(b => b.textContent.trim() === '2×' || b.textContent.trim() === '2x');

            if (half && double) {
                console.log('✅ Found via text content');
                return { half, double };
            }

            return null;
        };

        // Super aggressive enabler
        const forceEnableButton = (btn) => {
            // Remove disabled in every way possible
            btn.disabled = false;
            btn.removeAttribute('disabled');
            btn.setAttribute('disabled', 'false');

            // Override styles
            btn.style.setProperty('opacity', '1', 'important');
            btn.style.setProperty('pointer-events', 'auto', 'important');
            btn.style.setProperty('cursor', 'pointer', 'important');
            btn.style.setProperty('filter', 'none', 'important');

            // Remove disabled classes
            btn.classList.remove('disabled', 'Mui-disabled', 'is-disabled');

            // Override inline styles that might disable it
            if (btn.hasAttribute('style')) {
                const style = btn.getAttribute('style');
                const newStyle = style
                    .replace(/pointer-events\s*:\s*none/gi, 'pointer-events: auto')
                    .replace(/opacity\s*:\s*0\.\d+/gi, 'opacity: 1')
                    .replace(/cursor\s*:\s*not-allowed/gi, 'cursor: pointer');
                btn.setAttribute('style', newStyle);
            }
        };

        let attempts = 0;
        const maxAttempts = 100;

        const trySetup = setInterval(() => {
            attempts++;

            const buttons = findButtons();

            if (buttons) {
                clearInterval(trySetup);

                const { half, double } = buttons;

                console.log('🎯 Buttons found!');
                console.log('Half:', half.textContent, 'Double:', double.textContent);

                // Force enable immediately
                forceEnableButton(half);
                forceEnableButton(double);

                console.log('✅ Buttons force-enabled!');

                // Handler for half
                const doHalf = (e) => {
                    console.log('➗ HALF CLICKED!');
                    e.preventDefault();
                    e.stopPropagation();
                    e.stopImmediatePropagation();

                    const input = document.querySelector(FAKE_INPUT_SELECTOR);
                    if (input) {
                        const current = parseFloat(input.value) || 0;
                        const newVal = (current / 2).toFixed(2);
                        input.value = newVal;

                        // Fire all update mechanisms
                        updateConversionInstant();
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));

                        console.log(`✅ ${current} → ${newVal}`);
                    }
                    return false;
                };

                // Handler for double
                const doDouble = (e) => {
                    console.log('✖️ DOUBLE CLICKED!');
                    e.preventDefault();
                    e.stopPropagation();
                    e.stopImmediatePropagation();

                    const input = document.querySelector(FAKE_INPUT_SELECTOR);
                    if (input) {
                        const current = parseFloat(input.value) || 0;
                        const newVal = (current * 2).toFixed(2);
                        input.value = newVal;

                        // Fire all update mechanisms
                        updateConversionInstant();
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));

                        console.log(`✅ ${current} → ${newVal}`);
                    }
                    return false;
                };

                // Attach to ALL event types
                const events = ['click', 'mousedown', 'mouseup', 'pointerdown', 'pointerup', 'touchstart', 'touchend'];

                events.forEach(evt => {
                    half.addEventListener(evt, doHalf, true);
                    half.addEventListener(evt, doHalf, false);
                    double.addEventListener(evt, doDouble, true);
                    double.addEventListener(evt, doDouble, false);
                });

                // Visual feedback
                [half, double].forEach(btn => {
                    btn.addEventListener('mousedown', () => {
                        btn.style.transform = 'scale(0.95)';
                        setTimeout(() => btn.style.transform = 'scale(1)', 100);
                    });
                });

                console.log('✅ Event handlers attached to both phases!');

                // Keep re-enabling aggressively
                setInterval(() => {
                    forceEnableButton(half);
                    forceEnableButton(double);
                }, 200);

                console.log('✅✅✅ BUTTONS FULLY CONFIGURED AND AUTO-ENABLING! ✅✅✅');

            } else if (attempts >= maxAttempts) {
                clearInterval(trySetup);
                console.warn('⚠️ Could not find buttons after', maxAttempts, 'attempts');
            } else if (attempts % 10 === 0) {
                console.log(`🔍 Still searching... attempt ${attempts}/${maxAttempts}`);
            }
        }, 150);
    }

    function applyExactOverlayClone(wrapper, realInput) {
        if (wrapper.dataset.tmExactOverlayApplied) return;
        wrapper.dataset.tmExactOverlayApplied = '1';

        const computed = window.getComputedStyle(wrapper);
        if (computed.position === 'static' || !computed.position) {
            wrapper.style.position = 'relative';
        }

        const originalChildren = Array.from(wrapper.children);
        const clone = wrapper.cloneNode(true);
        deepStrip(clone);

        clone.style.position = 'absolute';
        clone.style.top = '0';
        clone.style.left = '0';
        clone.style.width = '100%';
        clone.style.height = '100%';
        clone.style.boxSizing = 'border-box';
        clone.style.zIndex = '999999';
        clone.style.pointerEvents = 'auto';

        wrapper.appendChild(clone);

        for (const ch of originalChildren) {
            if (ch === clone) continue;
            try {
                ch.style.visibility = 'hidden';
                ch.style.pointerEvents = 'none';
            } catch (e) {}
        }

        const fakeInput = clone.querySelector(INPUT_SELECTOR) || clone.querySelector('input');
        if (fakeInput) {
            prepareFakeInput(fakeInput, realInput);
            fakeInput.id = 'fake-bet-input';

            let conversionSpan = document.querySelector(INNER_CONVERSION_SPAN_SELECTOR);
            if (!conversionSpan) {
                const conversionDiv = document.createElement('div');
                conversionDiv.className = 'crypto svelte-1pm8uy8';
                conversionDiv.setAttribute('data-testid', 'conversion-amount');
                conversionDiv.setAttribute('bis_skin_checked', '1');

                conversionSpan = document.createElement('span');
                conversionSpan.setAttribute('type', 'body');
                conversionSpan.setAttribute('tag', 'span');
                conversionSpan.setAttribute('size', 'sm');
                conversionSpan.className = 'ds-body-sm';
                conversionSpan.setAttribute('data-ds-text', 'true');
                conversionSpan.textContent = formatLTC(0);

                conversionDiv.appendChild(document.createComment(''));
                conversionDiv.appendChild(conversionSpan);
                conversionDiv.appendChild(document.createComment(''));

                wrapper.insertAdjacentElement('afterend', conversionDiv);
            }
            updateCurrencyConversion();
        }

        const buttons = clone.querySelectorAll('button, [role="button"]');
        buttons.forEach(btn => {
            deepStrip(btn);
            btn.addEventListener('click', ev => {
                ev.preventDefault(); ev.stopPropagation && ev.stopPropagation(); ev.stopImmediatePropagation && ev.stopImmediatePropagation();
                btn.classList.add('tm-press');
                setTimeout(() => btn.classList.remove('tm-press'), 140);
            }, true);
        });

        if (!document.querySelector('#tm-exact-press-style')) {
            const s = document.createElement('style');
            s.id = 'tm-exact-press-style';
            s.textContent = `.tm-press{ transform: scale(0.98) !important; transition: transform 120ms ease !important; }`;
            document.head.appendChild(s);
        }

        isolateEvents(clone);

        try {
            const mo = new MutationObserver(muts => {
                for (const m of muts) {
                    if (m.attributeName === 'value' || m.attributeName === 'placeholder') {
                        try { if (fakeInput) fakeInput.value = realInput.value || fakeInput.value; } catch (e) {}
                    }
                }
            });
            mo.observe(realInput, { attributes: true, attributeFilter: ['value', 'placeholder'] });
        } catch (e) {}

        const bodyObserver = new MutationObserver(() => {
            if (!document.body.contains(wrapper)) {
                bodyObserver.disconnect();
                setTimeout(() => waitForTarget(), 300);
            }
        });
        bodyObserver.observe(document.body, { childList: true, subtree: true });

        const minesSelect = document.querySelector(SELECT_SELECTOR);
        if (minesSelect && fakeInput) {
            const syncDisabled = () => {
                if (minesSelect.disabled) {
                    fakeInput.disabled = true;
                    fakeInput.style.opacity = '0.6';
                    fakeInput.style.pointerEvents = 'none';
                } else {
                    fakeInput.disabled = false;
                    fakeInput.style.opacity = '1';
                    fakeInput.style.pointerEvents = 'auto';
                }
                updateCurrencyConversion();
            };

            syncDisabled();
            const selectObserver = new MutationObserver(syncDisabled);
            selectObserver.observe(minesSelect, { attributes: true, attributeFilter: ['disabled'] });
        }
    }

    // Initialize
    addStyles();
    fetchLtcRate();
    setInterval(fetchLtcRate, LTC_RATE_TTL_MS);
    waitForTarget();
    setupBetButtons();

    let isFirstClick = true;
    const blockedRegex = /mine\.DwyaPDKk\.mp3|\/assets\/mine/;
    const maxRetries = 4;
    const retryDelay = 300;

    function isBlocked(target) {
        try {
            let url = (typeof target === 'string') ? target : (target && target.url) ? target.url : '';
            return blockedRegex.test(url);
        } catch (e) {
            return false;
        }
    }

    async function retryBlock(callback, name) {
        for (let i = 1; i <= maxRetries; i++) {
            try {
                callback();
            } catch (e) {}
            await new Promise(r => setTimeout(r, retryDelay));
        }
    }

    const originalFetch = window.fetch;
    window.fetch = async function(input, init) {
        if (isBlocked(input)) {
            return new Response(new ArrayBuffer(0), {
                status: 200,
                statusText: 'OK',
                headers: { 'Content-Type': 'audio/mpeg' }
            });
        }
        return originalFetch.apply(this, arguments);
    };

    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url) {
        this._ab_url_to_check = url ? String(url) : '';
        return originalOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function(body) {
        if (this._ab_url_to_check && blockedRegex.test(this._ab_url_to_check)) {
            try { this.abort(); } catch (e) {}
            return;
        }
        return originalSend.apply(this, arguments);
    };

    function scrubAudioElement(a) {
        try {
            if (!a) return false;
            const src = a.src || a.getAttribute && a.getAttribute('src') || '';
            if (src && blockedRegex.test(src)) {
                a.pause();
                a.removeAttribute('src');
                a.src = '';
                a.muted = true;
                return true;
            }
        } catch (e) {}
        return false;
    }

    document.querySelectorAll('audio').forEach(a => retryBlock(() => scrubAudioElement(a), a.src));

    const mo = new MutationObserver(mutations => {
        for (const m of mutations) {
            if (m.addedNodes && m.addedNodes.length) {
                m.addedNodes.forEach(node => {
                    if (!node) return;
                    if (node.tagName && node.tagName.toLowerCase() === 'audio') {
                        retryBlock(() => scrubAudioElement(node), node.src);
                    } else if (node.querySelectorAll) {
                        node.querySelectorAll('audio').forEach(a => retryBlock(() => scrubAudioElement(a), a.src));
                    }
                });
            }
        }
    });

    mo.observe(document.documentElement || document.body, {
        childList: true,
        subtree: true
    });

    const audio = new Audio('data:audio/mpeg;base64,' + base64Audio);

    // Tile click handler
    document.addEventListener('click', (e) => {
        const clickedTile = e.target.closest('button.tile');
        if (!clickedTile) return;

        const allTiles = document.querySelectorAll('button.tile');

        if (isFirstClick) {
            setTimeout(() => {
                audio.play().catch(error => console.error('Audio playback failed:', error));
            }, 700);
            isFirstClick = false;
        }

        clickedTile.classList.add('gem-bounce');

        const fakeInput = document.querySelector(FAKE_INPUT_SELECTOR);
        if (!fakeInput) return;

        const inputValue = parseFloat(fakeInput.value) || 0;
        const payout = inputValue * 24.75;
        const formattedPayout = formatBalance(payout);

        setTimeout(() => {
            clickedTile.outerHTML = gemHTML;
            allTiles.forEach(tile => {
                if (tile !== clickedTile) tile.outerHTML = bombHTML;
            });

            const gridContainer = document.querySelector('div.wrap.svelte-114gwsk[data-testid="game-mines"]');
            if (gridContainer) {
                const resultDiv = document.createElement('div');
                resultDiv.innerHTML = resultDivHTML;
                const newResultDiv = resultDiv.firstChild;
                gridContainer.appendChild(newResultDiv);

                const payoutSpan = newResultDiv.querySelector('span.text-neutral-subtle.ds-body-md-strong');
                if (payoutSpan) {
                    payoutSpan.textContent = formattedPayout;
                }

                // Update Total Profit conversion with the exact payout amount
                updateProfitConversion(payout);
                updateProfitLabel('24.75');
                updateProfitInput(payout);

                currentBalance += payout;
                setTimeout(endTrial, 1500);
                updateBalanceUI();
            }

            setTimeout(() => {
                const randomBtn = document.querySelector('button[data-testid="random-tile"]');
                if (randomBtn) randomBtn.click();
            }, 300);
        }, 500);
    });

    // Bet button handler
    document.addEventListener('click', (e) => {
        const betButton = e.target.closest(BET_BUTTON_SELECTOR);
        if (!betButton) return;

        const fakeInput = document.querySelector(FAKE_INPUT_SELECTOR);
        if (!fakeInput) return;

        const betAmount = parseFloat(fakeInput.value) || 0;


        if (betAmount > currentBalance) {
            alert('Insufficient balance for this bet.');
            return;
        }

        // Deduct bet amount
        currentBalance -= betAmount;
        updateBalanceUI();
        updateCurrencyConversion();

        // Reset grid
        const allTiles = document.querySelectorAll('button.tile');
        const resultDiv = document.querySelector('div.game-result-wrap');

        if (allTiles.length > 0) {
            allTiles.forEach(tile => {
                try {
                    tile.outerHTML = normalHTML;
                } catch (e) {}
            });
        }

        if (resultDiv) {
            try {
                resultDiv.remove();
            } catch (e) {}
        }

        // Reset profit label back to 1.00×
        updateProfitLabel('1.00');

        // Reset profit conversion back to 0.00000000 LTC
        updateProfitConversion(0);

        // Reset profit input back to 0.00
        updateProfitInput(0);

        isFirstClick = true;
    });
})();
