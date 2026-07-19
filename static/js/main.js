/* Fora AI - core frontend interactions */

// ---------- Service worker registration (offline support + installability) ----------
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/service-worker.js').catch((err) => {
      console.warn('Service worker registration failed:', err);
    });
  });
}

// ---------- Toasts ----------
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type] || icons.info}</span><span>${message}</span><span class="toast-close">&times;</span>`;
  container.appendChild(toast);

  const remove = () => {
    toast.classList.add('hide');
    setTimeout(() => toast.remove(), 250);
  };
  toast.querySelector('.toast-close').addEventListener('click', remove);
  setTimeout(remove, 5000);
}

document.addEventListener('DOMContentLoaded', () => {
  // Render Django messages as toasts
  document.querySelectorAll('[data-django-message]').forEach((el) => {
    showToast(el.dataset.message, el.dataset.tag);
  });

  // ---------- Sidebar toggle (mobile) ----------
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.querySelector('.sidebar-overlay');
  const toggleBtn = document.querySelector('[data-sidebar-toggle]');
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      overlay?.classList.toggle('open');
    });
    overlay?.addEventListener('click', () => {
      sidebar.classList.remove('open');
      overlay.classList.remove('open');
    });
  }

  // ---------- Navbar toggle (mobile, public pages) ----------
  const navToggle = document.getElementById('navToggle');
  const navMenu = document.getElementById('navMenu');
  const navScrim = document.getElementById('navScrim');
  if (navToggle && navMenu) {
    const closeNav = () => {
      navMenu.classList.remove('open');
      navScrim?.classList.remove('open');
      navToggle.setAttribute('aria-expanded', 'false');
    };
    const openNav = () => {
      navMenu.classList.add('open');
      navScrim?.classList.add('open');
      navToggle.setAttribute('aria-expanded', 'true');
    };
    navToggle.addEventListener('click', () => {
      const isOpen = navMenu.classList.contains('open');
      isOpen ? closeNav() : openNav();
    });
    navScrim?.addEventListener('click', closeNav);
    navMenu.querySelectorAll('a').forEach((a) => a.addEventListener('click', closeNav));
    window.addEventListener('resize', () => {
      if (window.innerWidth > 860) closeNav();
    });
  }

  // ---------- Tab switching (scan input methods) ----------
  document.querySelectorAll('[data-tabs]').forEach((tabGroup) => {
    const buttons = tabGroup.querySelectorAll('[data-tab-btn]');
    const panels = tabGroup.querySelectorAll('[data-tab-panel]');
    buttons.forEach((btn) => {
      btn.addEventListener('click', () => {
        buttons.forEach((b) => b.classList.remove('active'));
        panels.forEach((p) => (p.style.display = 'none'));
        btn.classList.add('active');
        const target = tabGroup.querySelector(`[data-tab-panel="${btn.dataset.tabBtn}"]`);
        if (target) target.style.display = 'block';
      });
    });
  });

  // ---------- Drag & drop file upload ----------
  document.querySelectorAll('[data-dropzone]').forEach((zone) => {
    const input = zone.querySelector('input[type="file"]');
    const label = zone.querySelector('[data-dropzone-label]');

    const updateLabel = (files) => {
      if (files && files.length && label) {
        label.textContent = files.length === 1 ? files[0].name : `${files.length} files selected`;
      }
    };

    zone.addEventListener('click', () => input?.click());
    input?.addEventListener('change', () => updateLabel(input.files));

    ['dragenter', 'dragover'].forEach((evt) =>
      zone.addEventListener(evt, (e) => {
        e.preventDefault();
        zone.classList.add('drag-active');
      })
    );
    ['dragleave', 'drop'].forEach((evt) =>
      zone.addEventListener(evt, (e) => {
        e.preventDefault();
        zone.classList.remove('drag-active');
      })
    );
    zone.addEventListener('drop', (e) => {
      if (e.dataTransfer.files.length && input) {
        input.files = e.dataTransfer.files;
        updateLabel(input.files);
      }
    });
  });

  // ---------- Loading overlay on scan form submit ----------
  document.querySelectorAll('[data-scan-form]').forEach((form) => {
    form.addEventListener('submit', () => {
      const overlay = document.getElementById('loading-overlay');
      if (overlay) overlay.classList.remove('hidden');
    });
  });

  // ---------- Copy-to-clipboard for code examples ----------
  document.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = document.querySelector(btn.dataset.copy);
      if (!target) return;
      navigator.clipboard.writeText(target.innerText).then(() => {
        const original = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => (btn.textContent = original), 1500);
      });
    });
  });

  // ---------- Skeleton loading (reveal real content once it's ready) ----------
  // Pattern: [data-skeleton-loader="x"] is the shimmer placeholder, shown by
  // default. [data-skeleton-target="x"] is the real content, marked
  // .sk-hidden in the template. We swap them once the page has settled.
  const skeletonTargets = document.querySelectorAll('[data-skeleton-target]');
  if (skeletonTargets.length) {
    const reveal = () => {
      skeletonTargets.forEach((target) => {
        const key = target.dataset.skeletonTarget;
        const loader = document.querySelector(`[data-skeleton-loader="${key}"]`);
        target.classList.remove('sk-hidden');
        loader?.classList.add('sk-hidden');
      });
    };
    // Small delay so the shimmer reads as an intentional loading state
    // rather than a flicker, but never make the user wait for it.
    const minDelay = () => setTimeout(reveal, 260);
    if (document.readyState === 'complete') {
      minDelay();
    } else {
      window.addEventListener('load', minDelay);
    }
    // Safety net: guarantee content appears even if 'load' is delayed
    // (slow fonts/analytics scripts) or main.js re-runs unexpectedly.
    setTimeout(reveal, 1200);
  }

  // ---------- Top nav-progress bar (page navigation) ----------
  const navProgress = document.getElementById('nav-progress');
  if (navProgress) {
    document.addEventListener('click', (e) => {
      const link = e.target.closest('a[href]');
      if (!link) return;
      const url = new URL(link.href, window.location.href);
      const isSamePage = url.pathname === window.location.pathname && url.hash;
      if (
        isSamePage ||
        link.target === '_blank' ||
        link.hasAttribute('download') ||
        url.origin !== window.location.origin ||
        e.metaKey || e.ctrlKey || e.shiftKey
      ) {
        return;
      }
      navProgress.classList.add('nav-active');
    });
    window.addEventListener('pageshow', () => navProgress.classList.remove('nav-active'));
  }

  // ---------- Accordion (issue cards) ----------
  document.querySelectorAll('[data-accordion-toggle]').forEach((toggle) => {
    toggle.addEventListener('click', () => {
      const panel = toggle.closest('[data-accordion]').querySelector('[data-accordion-panel]');
      const isOpen = panel.style.maxHeight;
      document.querySelectorAll('[data-accordion-panel]').forEach((p) => (p.style.maxHeight = null));
      if (!isOpen) panel.style.maxHeight = panel.scrollHeight + 'px';
    });
  });
});
