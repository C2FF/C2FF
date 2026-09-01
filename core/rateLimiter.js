// ============================================================
// C2FF - core/rateLimiter.js : controleur de delai adaptatif
// Regle : si la cible repond 429 (rate limit) ou timeout, on DOUBLe
// le gap avant la requete suivante. Jamais de reduction brutale : le
// gap redescend d'un cran (x0.75) toutes les 8 reponses propres.
// Zero dependance, Promise. Utilise par les wrappers HTTP des modes
// avances (voir docs/core.md avant de modifier un wrapper).
// ============================================================
'use strict';

const MIN_GAP = 250;        // plancher : jamais plus vite que le moteur de base
const MAX_GAP = 30000;      // plafond : au-dela, la cible est en dur, on ralentit fort
const COOL_STREAK = 8;      // reponses propres consecutives avant de redescendre

function create(opts) {
  const base = Math.max(MIN_GAP, (opts && opts.baseGapMs) || 1000);
  const st = {
    gapMs: base,
    base,
    cleanStreak: 0,
    doublings: 0,
    lastReason: '',
  };

  // record() : a appeler APRES chaque requete avec le code HTTP
  // (0 = timeout/erreur reseau) et un flag timedOut explicite.
  function record(code, timedOut) {
    if (code === 429 || timedOut) {
      st.gapMs = Math.min(MAX_GAP, st.gapMs * 2);
      st.doublings++;
      st.cleanStreak = 0;
      st.lastReason = timedOut ? 'timeout' : '429';
      return st.gapMs;
    }
    st.cleanStreak++;
    if (st.cleanStreak >= COOL_STREAK && st.gapMs > base) {
      st.gapMs = Math.max(base, Math.round(st.gapMs * 0.75));
      st.cleanStreak = 0;
      st.lastReason = 'cooldown';
    }
    return st.gapMs;
  }

  // wait() : promise qui dort le gap courant (a awaiter ENTRE les requetes)
  function wait() {
    return new Promise(r => setTimeout(r, st.gapMs));
  }

  // requete() : helper complet - attend le gap, lance fn (Promise), enregistre
  // le resultat. fn doit resoudre { code, timedOut? } (voir docs/core.md).
  async function request(fn) {
    await wait();
    const r = await fn();
    record(r && r.code, !!(r && r.timedOut));
    return r;
  }

  function state() { return { gapMs: st.gapMs, base: st.base, doublings: st.doublings, lastReason: st.lastReason }; }
  function reset() { st.gapMs = st.base; st.cleanStreak = 0; st.doublings = 0; st.lastReason = ''; }

  return { wait, record, request, state, reset };
}

module.exports = { create, MIN_GAP, MAX_GAP };