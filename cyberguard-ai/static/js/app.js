// ══════════════════════════════════════════════════
//  CyberGuard AI — JavaScript principal
// ══════════════════════════════════════════════════

// ── Utilitários ──────────────────────────────────

function getRiskLabel(level) {
    return { low: 'Baixo Risco', medium: 'Requer Atenção', high: 'Risco Elevado' }[level] || level;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
}

function showLoading(btn) {
    btn.disabled = true;
    btn._origHtml = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span> A analisar...';
}

function hideLoading(btn, html) {
    btn.disabled = false;
    btn.innerHTML = html || btn._origHtml || 'Analisar';
}

function showError(msg) {
    const el = document.getElementById('error-msg');
    if (!el) return;
    el.textContent = msg;
    el.style.display = 'block';
}

function clearError() {
    const el = document.getElementById('error-msg');
    if (el) el.style.display = 'none';
}

// ── Análise de URL ────────────────────────────────

async function analyzeUrl() {
    const urlInput = document.getElementById('url-input');
    const btn = document.getElementById('analyze-btn');
    const url = urlInput.value.trim();

    if (!url) { showError('Por favor, insere um URL para analisar.'); return; }

    showLoading(btn);
    clearError();

    try {
        const response = await fetch('/api/analyze/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await response.json();

        if (!response.ok) { showError(data.error || 'Erro ao analisar o URL.'); return; }
        if (typeof showUrlResult === 'function') showUrlResult(data);
    } catch {
        showError('Não foi possível ligar ao servidor. Verifica se o Flask está a correr.');
    } finally {
        hideLoading(btn, '<i class="bx bx-search-alt"></i> Analisar URL');
    }
}

// ── Análise de Mensagem ───────────────────────────

async function analyzeMessage() {
    const msgInput = document.getElementById('message-input');
    const btn = document.getElementById('analyze-msg-btn');
    const message = msgInput.value.trim();

    if (!message) { showError('Por favor, insere uma mensagem para analisar.'); return; }

    showLoading(btn);
    clearError();

    try {
        const response = await fetch('/api/analyze/message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });
        const data = await response.json();

        if (!response.ok) { showError(data.error || 'Erro ao analisar a mensagem.'); return; }
        if (typeof showMessageResult === 'function') showMessageResult(data);
    } catch {
        showError('Não foi possível ligar ao servidor.');
    } finally {
        hideLoading(btn, '<i class="bx bx-search-alt"></i> Analisar Mensagem');
    }
}

// ── Sidebar (mobile) ──────────────────────────────

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('overlay');
    sidebar.classList.toggle('open');
    overlay.classList.toggle('show');
}

// ── Enter para submeter ───────────────────────────

document.addEventListener('DOMContentLoaded', function () {
    const urlInput = document.getElementById('url-input');
    if (urlInput) {
        urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') analyzeUrl(); });
    }
});
