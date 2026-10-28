/* CyberGuard AI — app.js */

// ── Reveal Animation ──────────────────────────────────────────────────────
const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('active');
        }
    });
}, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });

document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));

// ── Sidebar / Hamburger ───────────────────────────────────────────────────
const sidebar = document.getElementById('sidebar');
const hamburger = document.getElementById('hamburger');
const overlay = document.getElementById('mobile-overlay');

function openSidebar() {
    sidebar.classList.add('open');
    hamburger.classList.add('open');
    overlay.classList.add('visible');
    hamburger.setAttribute('aria-expanded', 'true');
}

function closeSidebar() {
    sidebar.classList.remove('open');
    hamburger.classList.remove('open');
    overlay.classList.remove('visible');
    hamburger.setAttribute('aria-expanded', 'false');
}

if (hamburger) {
    hamburger.addEventListener('click', () => {
        sidebar.classList.contains('open') ? closeSidebar() : openSidebar();
    });
}

if (overlay) {
    overlay.addEventListener('click', closeSidebar);
}

// ── Hero Clock ────────────────────────────────────────────────────────────
function updateClock() {
    const el = document.getElementById('clock-time');
    if (!el) return;
    const now = new Date();
    let h = now.getHours();
    const m = now.getMinutes().toString().padStart(2, '0');
    const ampm = h >= 12 ? 'PM' : 'AM';
    h = h % 12 || 12;
    el.textContent = `${h}:${m} ${ampm}`;
}
updateClock();
setInterval(updateClock, 60000);

// ── Risk Level Helpers ────────────────────────────────────────────────────
function riskLabel(level) {
    const labels = { baixo: 'Baixo Risco', medio: 'Risco Médio', alto: 'Alto Risco' };
    return labels[level] || level;
}

// ── Build Result HTML (shared by URL + Message pages) ────────────────────
function buildResultHTML(opts) {
    const { title, target, risk_level, indicators, explanation } = opts;

    const targetHTML = target
        ? `<p class="result-target">${escapeHTML(target)}</p>`
        : '';

    const indicatorsHTML = indicators && indicators.length > 0
        ? `<ul class="indicator-list">
              ${indicators.map(ind => `
                <li class="indicator-item sev-${ind.severity}">
                  <span class="indicator-dot"></span>
                  <span>${escapeHTML(ind.description)}</span>
                </li>
              `).join('')}
           </ul>`
        : `<p class="no-indicators">Nenhum indicador suspeito encontrado.</p>`;

    const recsHTML = explanation.recommendations && explanation.recommendations.length > 0
        ? `<ul class="recommendations-list">
              ${explanation.recommendations.map(r => `<li>${escapeHTML(r)}</li>`).join('')}
           </ul>`
        : '';

    return `
      <div class="result-container">
        <div class="result-header reveal">
          <div>
            <h2 class="font-serif">${escapeHTML(title)}</h2>
            ${targetHTML}
          </div>
          <div class="result-risk">
            <span class="risk-label">Nível de Risco</span>
            <span class="risk-value risk-${risk_level}">${riskLabel(risk_level)}</span>
          </div>
        </div>

        <div class="result-body">
          <div class="result-card reveal">
            <h3>Indicadores encontrados</h3>
            ${indicatorsHTML}
          </div>

          <div class="result-card reveal" style="--delay:.1s">
            <h3>Análise com IA</h3>
            <p class="explanation-text">${escapeHTML(explanation.explanation || '')}</p>
            ${recsHTML}
            <p class="disclaimer-text">${escapeHTML(explanation.disclaimer || '')}</p>
          </div>
        </div>
      </div>
    `;
}

// ── Generic Analysis Runner ───────────────────────────────────────────────
async function runAnalysis(endpoint, payload, btnId, resultId, renderFn) {
    const btn = document.getElementById(btnId);
    const resultArea = document.getElementById(resultId);

    setLoading(btn, true);
    resultArea.hidden = true;

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (!res.ok) {
            showError(resultArea, data.error || 'Ocorreu um erro desconhecido.');
            return;
        }

        resultArea.innerHTML = renderFn(data);
        resultArea.hidden = false;
        resultArea.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Trigger reveal on newly inserted elements
        requestAnimationFrame(() => {
            document.querySelectorAll('#' + resultId + ' .reveal').forEach(el => {
                revealObserver.observe(el);
                el.classList.add('active');
            });
        });

    } catch (err) {
        showError(resultArea, 'Erro de ligação ao servidor. Verifica se o Flask está a correr.');
    } finally {
        setLoading(btn, false);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────
function setLoading(btn, loading) {
    if (!btn) return;
    btn.disabled = loading;
    btn.classList.toggle('loading', loading);
    const textEl = btn.querySelector('.btn-text');
    const loaderEl = btn.querySelector('.btn-loader');
    if (textEl) textEl.hidden = loading;
    if (loaderEl) loaderEl.hidden = !loading;
}

function showError(container, message) {
    container.innerHTML = `<div class="error-box">⚠ ${escapeHTML(message)}</div>`;
    container.hidden = false;
}

function escapeHTML(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
