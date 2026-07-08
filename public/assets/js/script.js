/* ═══════════════════════════════════════════
   DIREKTORAT PSDA BERKELANJUTAN — script.js
   ═══════════════════════════════════════════ */

// ── NAV SCROLL ──
const nav = document.querySelector('nav');
window.addEventListener('scroll', () => {
  nav?.classList.toggle('scrolled', window.scrollY > 40);
});

// ── HAMBURGER / DRAWER ──
const hamburger = document.getElementById('hamburger');
const navDrawer = document.getElementById('navDrawer');

hamburger?.addEventListener('click', () => {
  hamburger.classList.toggle('open');
  navDrawer?.classList.toggle('open');
  document.body.style.overflow = navDrawer?.classList.contains('open') ? 'hidden' : '';
});

navDrawer?.addEventListener('click', (e) => {
  if (e.target === navDrawer) closeDrawer();
});

function closeDrawer() {
  hamburger?.classList.remove('open');
  navDrawer?.classList.remove('open');
  document.body.style.overflow = '';
}

// ── ANIMATE ON SCROLL ──
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
    }
  });
}, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

document.querySelectorAll('.fade-up').forEach(el => observer.observe(el));

// ── COUNTER ANIMATION ──
function animateCounter(el) {
  const target = parseFloat(el.dataset.target);
  const suffix = el.dataset.suffix || '';
  const prefix = el.dataset.prefix || '';
  const duration = 2000;
  const start = performance.now();

  function update(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(eased * target);
    el.textContent = prefix + current.toLocaleString('id-ID') + suffix;
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

const counterObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting && !entry.target.dataset.animated) {
      entry.target.dataset.animated = 'true';
      animateCounter(entry.target);
    }
  });
}, { threshold: 0.5 });

document.querySelectorAll('[data-target]').forEach(el => counterObserver.observe(el));

// ── LIGHTBOX ──
function openLightbox(src) {
  const lb = document.getElementById('lightbox');
  const img = document.getElementById('lightboxImg');
  if (lb && img) { img.src = src; lb.classList.add('active'); document.body.style.overflow = 'hidden'; }
}
function closeLightbox() {
  const lb = document.getElementById('lightbox');
  lb?.classList.remove('active');
  document.body.style.overflow = '';
}
document.getElementById('lightbox')?.addEventListener('click', (e) => {
  if (e.target.id === 'lightbox') closeLightbox();
});

// ── RPPLH TABS ──
function switchRpplhTab(tabName) {
  document.querySelectorAll('.rpplh-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabName));
  document.querySelectorAll('.rpplh-panel').forEach(p => p.classList.toggle('active', p.id === tabName));
}
document.querySelectorAll('.rpplh-tab').forEach(tab => {
  tab.addEventListener('click', () => switchRpplhTab(tab.dataset.tab));
});

// ── MULTI-STEP FORM ──
function initMultiStep(formId) {
  const form = document.getElementById(formId);
  if (!form) return;

  const panes = form.querySelectorAll('.form-pane');
  const indicators = form.querySelectorAll('.form-step-indicator');
  let current = 0;
  let isInitialLoad = true;

  function showPane(idx) {
    panes.forEach((p, i) => p.classList.toggle('active', i === idx));
    indicators.forEach((ind, i) => {
      ind.classList.toggle('active', i === idx);
      ind.classList.toggle('done', i < idx);
    });
    // Only scroll on user interaction, not on initial page load
    if (!isInitialLoad) {
      form.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    current = idx;
    isInitialLoad = false;
  }

  form.querySelectorAll('.btn-next').forEach(btn => {
    btn.addEventListener('click', () => {
      if (validatePane(panes[current])) showPane(current + 1);
    });
  });
  form.querySelectorAll('.btn-back').forEach(btn => {
    btn.addEventListener('click', () => showPane(current - 1));
  });

  const submitBtn = form.querySelector('.btn-submit');
  submitBtn?.addEventListener('click', (e) => {
    // Only validate the current pane before allowing custom submit logic to run
    if (!validatePane(panes[current])) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  });

  showPane(0);
}

function validatePane(pane) {
  if (!pane) return true;
  let valid = true;
  pane.querySelectorAll('[required]').forEach(el => {
    if (!el.value.trim()) {
      el.style.borderColor = '#e05c5c';
      el.addEventListener('input', () => el.style.borderColor = '', { once: true });
      valid = false;
    }
  });
  return valid;
}

// Init all forms
['formBimtek', 'formKonsultasi'].forEach(id => initMultiStep(id));
initMultiStep('formKepuasan');
initMultiStep('formAntikorupsi');
initMultiStep('formWhistle');

// ── FILE UPLOAD ──
document.querySelectorAll('.upload-area').forEach(area => {
  const input = area.querySelector('input[type="file"]');
  const list = area.querySelector('.upload-list');

  ['dragenter', 'dragover'].forEach(ev => {
    area.addEventListener(ev, (e) => { e.preventDefault(); area.classList.add('dragover'); });
  });
  ['dragleave', 'drop'].forEach(ev => {
    area.addEventListener(ev, () => area.classList.remove('dragover'));
  });
  area.addEventListener('drop', (e) => {
    e.preventDefault();
    if (input) { input.files = e.dataTransfer.files; renderFiles(e.dataTransfer.files, list); }
  });
  input?.addEventListener('change', () => renderFiles(input.files, list));
});

function renderFiles(files, list) {
  if (!list) return;
  list.innerHTML = '';
  Array.from(files).forEach(file => {
    const item = document.createElement('div');
    item.className = 'upload-file-item';
    item.innerHTML = `<span>📄</span><span>${file.name}</span><span style="margin-left:auto;color:var(--green-300);font-size:0.75rem;">${(file.size/1024).toFixed(1)} KB</span>`;
    list.appendChild(item);
  });
}

// ── RADIO LABEL HIGHLIGHT ──
document.querySelectorAll('.radio-label').forEach(label => {
  const radio = label.querySelector('input[type="radio"]');
  radio?.addEventListener('change', () => {
    const group = label.closest('.radio-group');
    group?.querySelectorAll('.radio-label').forEach(l => l.classList.remove('selected'));
    label.classList.add('selected');
  });
});

// ── STAR RATING ──
document.querySelectorAll('.star-rating').forEach(container => {
  const stars = container.querySelectorAll('.star');
  stars.forEach((star, idx) => {
    star.addEventListener('mouseenter', () => {
      stars.forEach((s, i) => s.classList.toggle('active', i <= idx));
    });
    star.addEventListener('mouseleave', () => {
      const active = container.dataset.value || -1;
      stars.forEach((s, i) => s.classList.toggle('active', i <= active));
    });
    star.addEventListener('click', () => {
      container.dataset.value = idx;
      stars.forEach((s, i) => s.classList.toggle('active', i <= idx));
    });
  });
});

// ── SCALE OPTIONS ──
document.querySelectorAll('.scale-options').forEach(group => {
  group.querySelectorAll('.scale-opt').forEach(opt => {
    opt.addEventListener('click', () => {
      group.querySelectorAll('.scale-opt').forEach(o => o.classList.remove('active'));
      opt.classList.add('active');
    });
  });
});

// ── CHOICE OPTIONS ──
document.querySelectorAll('.question-group').forEach(group => {
  group.querySelectorAll('.choice-opt').forEach(opt => {
    opt.addEventListener('click', () => {
      if (opt.querySelector('input[type="checkbox"]')) return;
      group.querySelectorAll('.choice-opt').forEach(o => {
        o.classList.remove('active');
        const inp = o.querySelector('input[type="radio"]');
        if (inp) inp.checked = false;
      });
      opt.classList.add('active');
      const inp = opt.querySelector('input[type="radio"]');
      if (inp) inp.checked = true;
    });
  });
});

// ── ANONYMOUS TOGGLE ──
const anonToggle = document.getElementById('anonToggle');
const anonSwitch = document.getElementById('anonSwitch');
const identityFields = document.getElementById('identityFields');

anonToggle?.addEventListener('click', () => {
  anonSwitch?.classList.toggle('on');
  const isOn = anonSwitch?.classList.contains('on');
  if (identityFields) identityFields.style.display = isOn ? 'none' : 'block';
});

// ── FILTER BUTTONS ──
document.querySelectorAll('.filter-bar').forEach(bar => {
  bar.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      bar.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      // Simple show/hide by category (can be extended)
      const filter = btn.dataset.filter;
      if (!filter || filter === 'all') {
        document.querySelectorAll('[data-category]').forEach(card => card.style.display = '');
      } else {
        document.querySelectorAll('[data-category]').forEach(card => {
          card.style.display = card.dataset.category === filter ? '' : 'none';
        });
      }
    });
  });
});

// ── CLOSE ESC ──
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { closeLightbox(); closeDrawer(); }
});


// Theme Toggle Logic
const themeToggle = document.getElementById('themeToggle');
const themeIcon = document.getElementById('themeIcon');

function setTheme(isDark) {
  if (isDark) {
    document.documentElement.removeAttribute('data-theme');
    if(themeIcon) themeIcon.textContent = '☀️';
    localStorage.setItem('theme', 'dark');
  } else {
    document.documentElement.setAttribute('data-theme', 'light');
    if(themeIcon) themeIcon.textContent = '🌙';
    localStorage.setItem('theme', 'light');
  }
}

if (themeToggle) {
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'light') {
    setTheme(false);
  } else if (savedTheme === 'dark') {
    setTheme(true);
  } else {
    // Default to light mode
    setTheme(false);
  }

  themeToggle.addEventListener('click', () => {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    setTheme(isLight);
  });
}
