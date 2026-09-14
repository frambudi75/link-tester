/**
 * LinkTester - Technical Controller & Data Renderer
 */

document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scan-form');
    const urlInput = document.getElementById('url-input');
    const btnSubmit = document.getElementById('btn-submit');
    const scanProgress = document.getElementById('scan-progress');
    const progressStatus = document.getElementById('progress-status');
    const resultsArea = document.getElementById('results-area');
    const historyTbody = document.getElementById('history-tbody');

    // Load initial scan history
    loadScanHistory();

    // Quick sample tags click
    document.querySelectorAll('.sample-tag').forEach(tag => {
        tag.addEventListener('click', () => {
            urlInput.value = tag.getAttribute('data-url');
            urlInput.focus();
        });
    });

    // Form submit handler
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();

        if (!url) {
            alert('Masukkan URL yang valid untuk dianalisis.');
            urlInput.focus();
            return;
        }

        // Set UI loading state
        btnSubmit.disabled = true;
        btnSubmit.textContent = 'Memproses...';
        progressStatus.textContent = 'Menghubungi target, menganalisis pola URL dan data WHOIS...';
        scanProgress.classList.add('active');
        resultsArea.classList.remove('visible');

        try {
            const response = await fetch('api/scan.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url }),
            });

            const data = await response.json();

            if (!data.success) {
                throw new Error(data.error || 'Terjadi kegagalan saat menganalisis URL.');
            }

            renderResults(data);
            loadScanHistory();

        } catch (err) {
            alert('Kesalahan Pemindaian: ' + err.message);
        } finally {
            scanProgress.classList.remove('active');
            btnSubmit.disabled = false;
            btnSubmit.innerHTML = `
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg> Mulai Analisis
            `;
        }
    });

    function renderResults(data) {
        // Verdict banner elements
        const banner = document.getElementById('verdict-banner');
        const scoreVal = document.getElementById('score-val');
        const verdictTitle = document.getElementById('verdict-title');
        const verdictPill = document.getElementById('verdict-pill');
        const verdictDesc = document.getElementById('verdict-desc');

        scoreVal.textContent = data.risk_score;

        if (data.verdict === 'dangerous') {
            banner.className = 'verdict-banner verdict-dangerous';
            verdictPill.className = 'badge-pill pill-dangerous';
            verdictPill.textContent = 'DANGEROUS';
            verdictTitle.textContent = 'Status: Terindikasi Berbahaya (Malicious)';
            verdictDesc.textContent = 'URL ini memiliki skor risiko tinggi dan terindikasi kuat sebagai situs phishing, penipuan, atau penyebar malware.';
        } else if (data.verdict === 'suspicious') {
            banner.className = 'verdict-banner verdict-suspicious';
            verdictPill.className = 'badge-pill pill-suspicious';
            verdictPill.textContent = 'SUSPICIOUS';
            verdictTitle.textContent = 'Status: Mencurigakan (Waspada)';
            verdictDesc.textContent = 'Ditemukan anomali pada struktur URL, ekstensi domain, atau umur registrasi domain. Disarankan untuk tidak memasukkan data kredensial.';
        } else {
            banner.className = 'verdict-banner verdict-safe';
            verdictPill.className = 'badge-pill pill-safe';
            verdictPill.textContent = 'SAFE';
            verdictTitle.textContent = 'Status: Tidak Ditemukan Ancaman (Clean)';
            verdictDesc.textContent = 'Tautan ini tidak memicu indikator berbahaya pada pemeriksaan heuristik, reputasi, maupun domain.';
        }

        // Technical meta
        document.getElementById('res-original-url').textContent = data.original_url;
        document.getElementById('res-final-url').textContent = data.final_url;
        document.getElementById('res-domain').textContent = data.domain || '-';
        document.getElementById('res-subdomain').textContent = data.subdomain || '(none)';
        document.getElementById('res-ip').textContent = data.ip_address || 'Tidak terdeteksi';
        document.getElementById('res-age').textContent = data.domain_age_days !== null ? `${data.domain_age_days} hari` : 'Tidak diketahui';
        document.getElementById('res-redirect').textContent = data.is_redirected ? `Ya (${data.redirect_count} hops)` : 'Langsung (0 hop)';
        document.getElementById('res-exec-time').textContent = `${data.execution_time_ms} ms ${data.cached ? '(Cached)' : ''}`;

        // Checks Matrix Table
        const checksTbody = document.getElementById('checks-tbody');
        checksTbody.innerHTML = '';

        if (!data.findings || data.findings.length === 0) {
            checksTbody.innerHTML = `
                <tr>
                    <td><span class="severity-pill sev-info">PASSED</span></td>
                    <td style="font-family: var(--font-mono); color: var(--color-safe);">ALL_CHECKS_PASSED</td>
                    <td>heuristic</td>
                    <td style="color: var(--text-secondary);">Semua evaluasi aturan keamanan berada dalam batas aman.</td>
                </tr>
            `;
        } else {
            data.findings.forEach(f => {
                const tr = document.createElement('tr');
                const sevClass = `sev-${f.severity || 'low'}`;
                tr.innerHTML = `
                    <td><span class="severity-pill ${sevClass}">${f.severity || 'info'}</span></td>
                    <td style="font-family: var(--font-mono); font-weight: 600; color: #fff;">${escapeHtml(f.rule_name)}</td>
                    <td style="color: var(--text-muted); font-size: 12px;">${escapeHtml(f.category)}</td>
                    <td style="color: var(--text-secondary);">${escapeHtml(f.description)}</td>
                `;
                checksTbody.appendChild(tr);
            });
        }

        // Advice Panel
        const adviceList = document.getElementById('advice-list');
        adviceList.innerHTML = '';
        (data.recommendations || []).forEach(tip => {
            const li = document.createElement('li');
            li.textContent = tip;
            adviceList.appendChild(li);
        });

        resultsArea.classList.add('visible');
        resultsArea.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    async function loadScanHistory() {
        try {
            const res = await fetch('api/history.php?limit=8');
            const data = await res.json();

            if (!data.success || !data.history || data.history.length === 0) {
                historyTbody.innerHTML = `
                    <tr>
                        <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 16px;">
                            Belum ada riwayat pemindaian tersimpan di database.
                        </td>
                    </tr>
                `;
                return;
            }

            historyTbody.innerHTML = '';
            data.history.forEach(row => {
                const tr = document.createElement('tr');
                let pillClass = 'pill-safe';
                if (row.verdict === 'dangerous') pillClass = 'pill-dangerous';
                else if (row.verdict === 'suspicious') pillClass = 'pill-suspicious';

                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); font-weight: 500; color: #fff;">${escapeHtml(row.domain)}</td>
                    <td><span class="badge-pill ${pillClass}">${row.verdict}</span></td>
                    <td style="font-family: var(--font-mono);">${row.risk_score} / 100</td>
                    <td style="color: var(--text-muted); font-size: 12px;">${row.is_redirected ? 'Redirect' : 'Direct'}</td>
                    <td style="color: var(--text-muted); font-family: var(--font-mono); font-size: 11px;">${row.created_at}</td>
                `;
                historyTbody.appendChild(tr);
            });
        } catch (e) {
            console.warn('Gagal memuat riwayat:', e);
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
});
