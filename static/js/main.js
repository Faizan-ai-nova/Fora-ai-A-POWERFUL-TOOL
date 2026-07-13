/* Fora AI - core frontend interactions */

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
