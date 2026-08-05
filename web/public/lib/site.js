/* Shared page behaviour: the theme toggle, the scroll reveals, and the stat
   count-up. Loaded with `defer` on every page, so it runs once the document is
   parsed and never blocks the first paint.
 *
 * The flash-of-wrong-theme guard is deliberately NOT here — it has to run
 * before the first paint, so it stays as the four-line inline script in each
 * <head>, which is also where the `js` class is set. Everything below is
 * progressive: with this file blocked, the pages still render complete and
 * readable, only static. */

/* ---- theme ---- */
const root = document.documentElement;
const themeBtn = document.getElementById('theme');
if (themeBtn) {
  const currentTheme = () =>
    root.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light');
  const syncTheme = () => themeBtn.setAttribute('aria-pressed', String(currentTheme() === 'dark'));
  syncTheme();
  themeBtn.addEventListener('click', () => {
    const next = currentTheme() === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    syncTheme();
    try { localStorage.setItem('arena-theme', next); }
    catch (e) { console.warn('theme: preference not persisted —', e.message); }
  });
}

const stillMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ---- scroll reveals ----
   The CSS hides [data-reveal] only under html.js, so this is the only thing
   that can un-hide it. If IntersectionObserver is missing, show everything
   immediately rather than leaving the page blank below the fold. */
const revealable = document.querySelectorAll('[data-reveal]');
if (revealable.length) {
  const revealAll = () => revealable.forEach((el) => el.classList.add('shown'));
  if (stillMotion || typeof IntersectionObserver !== 'function') {
    revealAll();
  } else {
    /* Fail-safe. Everything below is progressive enhancement over content that
       starts at opacity 0, which means any condition that stops the observer
       from running leaves a blank page — and there is at least one such
       condition in normal use: Chrome suspends IntersectionObserver entirely
       in a background tab, so a link opened in one and never focused delivers
       nothing. A working observer always delivers an initial batch for every
       observed element, so "nothing delivered" is a reliable signal that it is
       not working. When that happens, show the page. Losing an animation is a
       cost; losing the article is not one this site can pay. */
    let delivered = false;
    setTimeout(() => { if (!delivered) revealAll(); }, 1500);

    const io = new IntersectionObserver((entries) => {
      delivered = true;
      entries.forEach((en) => {
        /* Reveal on entry — and also reveal anything already ABOVE the
           viewport. A reload restores scroll position and a #hash link lands
           mid-page, so on first observation some targets are already scrolled
           past; those never intersect again and would stay invisible for the
           rest of the session. IO delivers an initial entry for every observed
           element, intersecting or not, which is where this catches them. */
        if (!en.isIntersecting && en.boundingClientRect.bottom > 0) return;
        en.target.classList.add('shown');
        io.unobserve(en.target);
      });
    /* threshold MUST stay at 0. A ratio threshold is a share of the element's
       own height, so a tall target — the rounds ledger is ~5000px against a
       ~950px viewport — can never reach 12% no matter how far you scroll, and
       the whole page silently stays at opacity 0. Trigger on first contact and
       let rootMargin do the "not quite yet" work instead. */
    }, { threshold: 0, rootMargin: '0px 0px -40px 0px' });
    revealable.forEach((el) => io.observe(el));
  }
}

/* ---- stat count-up ----
   The final value is already in the markup, so this only ever replaces a
   correct number with the same correct number. Under reduced motion it does
   not run at all, which leaves the static markup exactly as authored. */
if (!stillMotion) {
  document.querySelectorAll('[data-count]').forEach((el) => {
    const target = parseInt(el.getAttribute('data-count'), 10);
    if (!Number.isFinite(target)) return;
    const pad = parseInt(el.getAttribute('data-pad') || '0', 10);
    const delay = parseInt(el.getAttribute('data-cdelay') || '0', 10);
    const fmt = (n) => String(n).padStart(pad, '0');
    el.textContent = fmt(0);
    setTimeout(() => {
      const t0 = performance.now();
      const dur = 900;
      const tick = (now) => {
        const p = Math.min(1, (now - t0) / dur);
        el.textContent = fmt(Math.round(target * (1 - Math.pow(1 - p, 3))));
        if (p < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    }, delay);
  });
}
