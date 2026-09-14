/**
 * LinkTester v2.0 - Controller, Renderer, & Dashboard
 */

document.addEventListener('DOMContentLoaded', () => {
    // === DOM Elements ===
    const scanForm = document.getElementById('scan-form');
    const urlInput = document.getElementById('url-input');
    const btnSubmit = document.getElementById('btn-submit');
    const scanProgress = document.getElementById('scan-progress');
    const progressStatus = document.getElementById('progress-status');
    const resultsArea = document.getElementById('results-area');
    const historyTbody = document.getElementById('history-tbody');

    let lastScanId = null;
    let verdictChart = null;
    let trendChart = null;

    // === Theme Toggle ===
    const themeToggle = document.getElementById('theme-toggle');
    const iconSun = document.getElementById('icon-sun');
    const iconMoon = document.getElementById('icon-moon');

    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('linktester-theme', theme);
        if (theme === 'light') {
            iconSun.style.display = 'none';
            iconMoon.style.display = 'block';
        } else {
            iconSun.style.display = 'block';
            iconMoon.style.display = 'none';
        }
    }

    const savedTheme = localStorage.getItem('linktester-theme') || 'dark';
    setTheme(savedTheme);

    themeToggle.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        setTheme(current === 'dark' ? 'light' : 'dark');
    });

    // === Tab Navigation ===
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.getAttribute('data-tab');
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(tc => tc.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('tab-' + target).classList.add('active');

            if (target === 'dashboard') loadDashboard();
        });
    });

    // === Initial Load ===
    loadScanHistory();

    // === Quick Sample Tags ===
    document.querySelectorAll('.sample-tag').forEach(tag => {
        tag.addEventListener('click', () => {
            urlInput.value = tag.getAttribute('data-url');
            urlInput.focus();
        });
    });

    // === Scan Form Submit ===
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();

        if (!url) {
            alert('Masukkan URL yang valid untuk dianalisis.');
            urlInput.focus();
            return;
        }

        btnSubmit.disabled = true;
        btnSubmit.textContent = 'Memproses...';
        progressStatus.textContent = 'Menjalankan analisis multi-lapis: heuristik, SSL, konten, DNS, WHOIS...';
        scanProgress.classList.add('active');
        const freshScan = document.getElementById('fresh-scan');
        const isFresh = freshScan ? freshScan.checked : false;

        try {
            const response = await fetch('api/scan.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, fresh: isFresh }),
            });

            if (response.status === 429) {
                const errData = await response.json();
                throw new Error(errData.error || 'Rate limit tercapai.');
            }

            const data = await response.json();

            if (!data.success) {
                throw new Error(data.error || 'Terjadi kegagalan saat menganalisis URL.');
            }

            lastScanId = data.scan_id;
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

    // === Render Scan Results ===
    function renderResults(data) {
        const banner = document.getElementById('verdict-banner');
        const scoreVal = document.getElementById('score-val');
        const verdictTitle = document.getElementById('verdict-title');
        const verdictPill = document.getElementById('verdict-pill');
        const verdictDesc = document.getElementById('verdict-desc');

        scoreVal.textContent = data.risk_score;

        // 5-Tier Verdict Mapping
        const v = (data.verdict || 'clean').toLowerCase();
        let bannerClass = 'verdict-clean';
        let pillClass = 'pill-clean';
        let pillText = data.verdict_label || 'CLEAN';
        let titleText = 'Status: Bersih & Terverifikasi (Clean)';
        let descText = 'Tautan ini tidak memicu indikator ancaman bahaya pada evaluasi multi-lapis.';

        if (v === 'critical' || v === 'dangerous') {
            bannerClass = 'verdict-critical';
            pillClass = 'pill-critical';
            pillText = 'CRITICAL';
            titleText = 'Status: Bahaya Kritis (Critical Threat)';
            descText = 'Tautan ini terverifikasi aktif sebagai malware, phishing, atau penipuan siber. JANGAN BUKA!';
        } else if (v === 'high_risk') {
            bannerClass = 'verdict-high_risk';
            pillClass = 'pill-high_risk';
            pillText = 'HIGH RISK';
            titleText = 'Status: Risiko Tinggi (High Risk)';
            descText = 'Ditemukan kombinasi anomali berisiko tinggi seperti cloaking, punycode spoofing, atau form pencurian akun.';
        } else if (v === 'medium_risk' || v === 'suspicious') {
            bannerClass = 'verdict-medium_risk';
            pillClass = 'pill-medium_risk';
            pillText = 'MEDIUM RISK';
            titleText = 'Status: Risiko Sedang / Waspada (Medium Risk)';
            descText = 'Ditemukan beberapa kejanggalan pada nama domain, umur registrasi baru, atau pengalihan rute.';
        } else if (v === 'low_risk') {
            bannerClass = 'verdict-low_risk';
            pillClass = 'pill-low_risk';
            pillText = 'LOW RISK';
            titleText = 'Status: Risiko Rendah (Low Risk)';
            descText = 'Tautan relatif aman dengan sedikit anomali minor.';
        }

        banner.className = `verdict-banner ${bannerClass}`;
        verdictPill.className = `badge-pill ${pillClass}`;
        verdictPill.textContent = pillText;
        verdictTitle.textContent = titleText;
        verdictDesc.textContent = descText;

        // URL details
        document.getElementById('res-original-url').textContent = data.original_url;
        document.getElementById('res-final-url').textContent = data.final_url;

        // Visual Redirect Chain Flow Stepper (NEW)
        const flowPanel = document.getElementById('redirect-flow-panel');
        const flowStepper = document.getElementById('redirect-flow-stepper');
        const flowBadge = document.getElementById('redirect-flow-badge');

        if (data.redirect_chain && data.redirect_chain.length > 1) {
            flowPanel.style.display = 'block';
            flowBadge.textContent = `${data.redirect_chain.length - 1} HOPS`;
            flowStepper.innerHTML = '';

            data.redirect_chain.forEach((hop, idx) => {
                const isLast = idx === data.redirect_chain.length - 1;
                const hopObj = typeof hop === 'object' ? hop : { url: hop, hop: idx };
                const statusCode = hopObj.status_code || (isLast ? 200 : 302);
                const is200 = statusCode >= 200 && statusCode < 300;
                const isRedir = statusCode >= 300 && statusCode < 400;
                const dotClass = is200 ? 'status-200' : (isRedir ? 'status-301' : 'status-danger');

                const hopEl = document.createElement('div');
                hopEl.className = 'hop-item';
                hopEl.innerHTML = `
                    <div class="hop-timeline">
                        <div class="hop-dot ${dotClass}">${statusCode}</div>
                        ${!isLast ? '<div class="hop-line"></div>' : ''}
                    </div>
                    <div class="hop-card">
                        <div class="hop-header">
                            <span class="hop-url">${escapeHtml(hopObj.url || hopObj.hostname || '')}</span>
                            <div class="hop-meta-tags">
                                <span class="hop-badge badge-code">HTTP ${statusCode}</span>
                                ${hopObj.response_time_ms ? `<span class="hop-badge badge-time">${hopObj.response_time_ms} ms</span>` : ''}
                                ${hopObj.domain_changed ? '<span class="hop-badge badge-domain-change">⚠ CROSS-DOMAIN</span>' : ''}
                                ${hopObj.ip ? `<span class="hop-badge badge-time">${escapeHtml(hopObj.ip)}</span>` : ''}
                            </div>
                        </div>
                    </div>
                `;
                flowStepper.appendChild(hopEl);
            });
        } else {
            flowPanel.style.display = 'none';
        }

        // Domain info
        const elDomain = document.getElementById('res-domain');
        const elSubdomain = document.getElementById('res-subdomain');
        const elIp = document.getElementById('res-ip');
        const elAge = document.getElementById('res-age');
        const elRedirect = document.getElementById('res-redirect');
        const elExecTime = document.getElementById('res-exec-time');

        if (elDomain) elDomain.textContent = data.domain || '-';
        if (elSubdomain) elSubdomain.textContent = data.subdomain || '(none)';
        if (elIp) elIp.textContent = data.ip_address || 'Tidak terdeteksi';
        if (elAge) elAge.textContent = data.domain_age_days !== null ? `${data.domain_age_days} hari` : 'Tidak diketahui';
        if (elRedirect) elRedirect.textContent = data.is_redirected ? `Ya (${data.redirect_count} hops)` : 'Langsung (0 hop)';
        if (elExecTime) elExecTime.textContent = `${data.execution_time_ms} ms ${data.cached ? '(Cached)' : ''}`;

        // SSL Info
        const ssl = data.ssl_info || {};
        const elSslStatus = document.getElementById('res-ssl-status');
        const elSslIssuer = document.getElementById('res-ssl-issuer');
        const elSslExpires = document.getElementById('res-ssl-expires');

        if (elSslStatus && ssl.is_https !== undefined) {
            if (!ssl.is_https) {
                elSslStatus.innerHTML = '<span style="color:var(--text-muted);">HTTP (Tanpa SSL)</span>';
            } else if (ssl.ssl_valid === true) {
                elSslStatus.innerHTML = '<span style="color:var(--color-safe);">✓ Valid</span>';
            } else if (ssl.ssl_valid === false) {
                elSslStatus.innerHTML = '<span style="color:var(--color-danger);">✗ Tidak Valid</span>';
            } else {
                elSslStatus.textContent = '-';
            }
        }
        if (elSslIssuer) elSslIssuer.textContent = ssl.ssl_issuer || '-';
        if (elSslExpires) {
            if (ssl.ssl_expires) {
                const daysText = ssl.ssl_days_left !== null ? ` (${ssl.ssl_days_left} hari lagi)` : '';
                elSslExpires.textContent = ssl.ssl_expires + daysText;
            } else {
                elSslExpires.textContent = '-';
            }
        }

        // DNS Info
        const dns = data.dns_info || {};
        const spfEl = document.getElementById('res-dns-spf');
        const dmarcEl = document.getElementById('res-dns-dmarc');
        const mxEl = document.getElementById('res-dns-mx');

        if (spfEl && dns.has_spf !== undefined && dns.has_spf !== null) {
            spfEl.innerHTML = dns.has_spf
                ? '<span style="color:var(--color-safe);">✓ Terdeteksi</span>'
                : '<span style="color:var(--color-warning);">✗ Tidak ada</span>';
        }
        if (dmarcEl && dns.has_dmarc !== undefined && dns.has_dmarc !== null) {
            dmarcEl.innerHTML = dns.has_dmarc
                ? '<span style="color:var(--color-safe);">✓ Terdeteksi</span>'
                : '<span style="color:var(--color-warning);">✗ Tidak ada</span>';
        }
        if (mxEl && dns.has_mx !== undefined && dns.has_mx !== null) {
            mxEl.innerHTML = dns.has_mx
                ? `<span style="color:var(--color-safe);">✓ ${dns.mx_records ? dns.mx_records.length : ''} record</span>`
                : '<span style="color:var(--text-muted);">✗ Tidak ada</span>';
        }

        // Content Analysis
        const content = data.content_info || {};
        const contentPanel = document.getElementById('content-panel');
        const contentBadges = document.getElementById('content-badges');

        if (contentPanel && contentBadges) {
            const hasContent = content.has_login_form !== undefined || content.has_hidden_iframe !== undefined;
            if (hasContent) {
                contentPanel.style.display = 'block';
                contentBadges.innerHTML = '';

                const checks = [
                    { key: 'has_password_field', label: 'Form Login / Password', danger: true },
                    { key: 'has_hidden_iframe', label: 'Hidden iFrame', danger: true },
                    { key: 'has_crypto_miner', label: 'Crypto Miner', danger: true },
                    { key: 'has_obfuscated_js', label: 'Obfuscated JS', danger: true },
                    { key: 'has_auto_download', label: 'Auto Download', danger: true },
                ];

                checks.forEach(c => {
                    if (content[c.key] !== undefined) {
                        const badge = document.createElement('span');
                        const isActive = content[c.key];
                        badge.className = `content-badge ${isActive ? 'badge-warn' : 'badge-ok'}`;
                        badge.textContent = `${isActive ? '⚠' : '✓'} ${c.label}`;
                        contentBadges.appendChild(badge);
                    }
                });
            } else {
                contentPanel.style.display = 'none';
            }
        }

        // Screenshot (Safe & Resilient against missing elements)
        const screenshotPanel = document.getElementById('screenshot-panel');
        const screenshotContainer = document.querySelector('.screenshot-container');

        if (screenshotPanel) {
            if (data.screenshot_url && data.verdict !== 'dangerous' && data.verdict !== 'critical') {
                screenshotPanel.style.display = 'block';
                if (screenshotContainer) {
                    screenshotContainer.innerHTML = `
                        <img id="screenshot-img" src="${escapeHtml(data.screenshot_url)}" alt="Screenshot halaman target" loading="lazy" onerror="this.style.display='none'; if(this.nextElementSibling) this.nextElementSibling.style.display='block';">
                        <div class="screenshot-fallback" style="display:none; padding:24px; text-align:center; color:var(--text-muted); font-size:12px;">Preview tidak tersedia untuk URL ini.</div>
                    `;
                }
            } else {
                screenshotPanel.style.display = 'none';
            }
        }

        // Checks Matrix Table
        const checksTbody = document.getElementById('checks-tbody');
        if (checksTbody) {
            checksTbody.innerHTML = '';

            if (!data.findings || data.findings.length === 0) {
                checksTbody.innerHTML = `
                    <tr>
                        <td><span class="severity-pill sev-info">CLEAN</span></td>
                        <td style="font-family: var(--font-mono); color: var(--color-safe);">ALL_CHECKS_PASSED</td>
                        <td>heuristic</td>
                        <td style="color: var(--text-secondary);">Semua evaluasi aturan keamanan berada dalam batas aman.</td>
                    </tr>
                `;
            } else {
                data.findings.forEach(f => {
                    const tr = document.createElement('tr');
                    const sev = (f.severity || 'low').toLowerCase();
                    const sevClass = `sev-${sev}`;
                    const title = f.title || f.rule_name || f.signal || 'Security Finding';
                    const signalCode = f.signal || f.rule_name || '';
                    const desc = (f.explanation && f.explanation.detail) ? f.explanation.detail : (f.description || '');
                    const weightBadge = f.weight ? `<span style="font-family:var(--font-mono); font-size:10px; margin-left:6px; padding:1px 5px; background:rgba(255,255,255,0.06); border-radius:3px;">+${f.weight} pts</span>` : '';

                    tr.innerHTML = `
                        <td><span class="severity-pill ${sevClass}">${sev.toUpperCase()}</span></td>
                        <td>
                            <div style="font-weight: 600;">${escapeHtml(title)} ${weightBadge}</div>
                            <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${escapeHtml(signalCode)}</div>
                        </td>
                        <td style="color: var(--text-muted); font-size: 12px; text-transform:capitalize;">${escapeHtml(f.category || 'signal')}</td>
                        <td style="color: var(--text-secondary); line-height: 1.5;">${escapeHtml(desc)}</td>
                    `;
                    checksTbody.appendChild(tr);
                });
            }
        }

        // Advice Panel
        const adviceList = document.getElementById('advice-list');
        adviceList.innerHTML = '';
        (data.recommendations || []).forEach(tip => {
            const li = document.createElement('li');
            li.textContent = tip;
            adviceList.appendChild(li);
        });

        // Investigation Terminal View Generation (NEW)
        const terminalContent = document.getElementById('investigation-terminal-content');
        if (terminalContent) {
            terminalContent.textContent = buildInvestigationReport(data);
        }

        resultsArea.classList.add('visible');
        resultsArea.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // === Investigation Terminal Report Generator ===
    function buildInvestigationReport(data) {
        const score = data.risk_score || 0;
        const filled = Math.round((score / 100) * 16);
        const empty = 16 - filled;
        const meter = '█'.repeat(filled) + '░'.repeat(empty);
        const label = data.verdict_label || data.verdict?.toUpperCase() || 'UNKNOWN';

        let lines = [];
        lines.push('╔' + '═'.repeat(60) + '╗');
        lines.push('║  LINKTESTER // URL THREAT INTELLIGENCE & FORENSIC REPORT   ║');
        lines.push('╠' + '═'.repeat(60) + '╣');
        lines.push('║');
        lines.push(`║  Risk Score: [${meter}] ${score}/100`);
        lines.push(`║  Verdict   : ${label}`);
        lines.push('║');
        lines.push('║  ─── TARGET URL ───');
        lines.push(`║  ├── Original : ${data.original_url}`);
        lines.push(`║  └── Final    : ${data.final_url}`);
        lines.push('║');
        lines.push('║  ─── DOMAIN INTELLIGENCE ───');
        const age = data.domain_age_days !== null ? `${data.domain_age_days} days` : 'Unknown';
        lines.push(`║  ├── Apex Domain : ${data.domain || '-'}`);
        lines.push(`║  ├── Subdomain   : ${data.subdomain || '(none)'}`);
        lines.push(`║  ├── Domain Age  : ${age}`);
        lines.push(`║  ├── Host IP     : ${data.ip_address || 'Unresolved'}`);
        lines.push('║');
        lines.push('║  ─── REDIRECT FORENSICS ───');
        const chain = data.redirect_chain || [];
        if (chain.length > 1) {
            lines.push(`║  ├── Total Hops  : ${data.redirect_count || chain.length - 1}`);
            chain.forEach((hop, idx) => {
                const isLast = idx === chain.length - 1;
                const prefix = isLast ? '└──' : '├──';
                if (typeof hop === 'object') {
                    const code = hop.status_code ? `[HTTP ${hop.status_code}]` : '';
                    const changed = hop.domain_changed ? ' ⚠ CROSS-DOMAIN' : '';
                    const time = hop.response_time_ms ? ` (${hop.response_time_ms}ms)` : '';
                    lines.push(`║  ${prefix} Hop ${idx} ${code} ${hop.url || hop.hostname}${time}${changed}`);
                } else {
                    lines.push(`║  ${prefix} Hop ${idx} : ${hop}`);
                }
            });
        } else {
            lines.push(`║  └── Direct Connection (0 Hops, No Redirect)`);
        }
        lines.push('║');
        lines.push('║  ─── SECURITY SIGNALS & EVIDENCE ───');
        const findings = data.findings || [];
        if (findings.length > 0) {
            findings.forEach((f, idx) => {
                const isLast = idx === findings.length - 1;
                const prefix = isLast ? '└──' : '├──';
                const sev = (f.severity || 'low').toUpperCase();
                const icon = (sev === 'CRITICAL' || sev === 'HIGH') ? '⚠' : (sev === 'INFO' ? 'ℹ' : '●');
                const title = f.title || f.rule_name || f.signal || 'Signal';
                const weight = f.weight ? ` (+${f.weight} pts)` : '';
                lines.push(`║  ${prefix} [${icon} ${sev}] ${title}${weight}`);
                if (f.explanation && f.explanation.detail) {
                    lines.push(`║  │   Detail: ${f.explanation.detail}`);
                }
            });
        } else {
            lines.push('║  └── ✓ No Threat Signals Detected (Clean Record)');
        }
        lines.push('║');
        lines.push('║  ─── ADVISORY & RECOMMENDATIONS ───');
        const recs = data.recommendations || [];
        recs.forEach((r, idx) => {
            const isLast = idx === recs.length - 1;
            const prefix = isLast ? '└──' : '├──';
            lines.push(`║  ${prefix} ${r}`);
        });
        lines.push('║');
        lines.push('╚' + '═'.repeat(60) + '╝');

        return lines.join('\n');
    }

    // === View Mode Toggle (Standard vs Investigation Mode) ===
    const standardViewContainer = document.getElementById('standard-view-container');
    const investigationTerminalWrap = document.getElementById('investigation-terminal-wrap');
    const viewModeStandard = document.getElementById('view-mode-standard');
    const viewModeInvestigation = document.getElementById('view-mode-investigation');

    if (viewModeStandard && viewModeInvestigation) {
        viewModeStandard.addEventListener('click', () => {
            viewModeStandard.classList.add('active');
            viewModeInvestigation.classList.remove('active');
            if (standardViewContainer) standardViewContainer.style.display = 'block';
            if (investigationTerminalWrap) investigationTerminalWrap.style.display = 'none';
        });

        viewModeInvestigation.addEventListener('click', () => {
            viewModeInvestigation.classList.add('active');
            viewModeStandard.classList.remove('active');
            if (standardViewContainer) standardViewContainer.style.display = 'none';
            if (investigationTerminalWrap) investigationTerminalWrap.style.display = 'block';
        });
    }

    // Copy terminal report button
    const btnCopyTerminal = document.getElementById('btn-copy-terminal');
    if (btnCopyTerminal) {
        btnCopyTerminal.addEventListener('click', () => {
            const content = document.getElementById('investigation-terminal-content');
            if (content && content.textContent) {
                navigator.clipboard.writeText(content.textContent).then(() => {
                    const originalText = btnCopyTerminal.innerHTML;
                    btnCopyTerminal.textContent = '✓ Tersalin!';
                    setTimeout(() => { btnCopyTerminal.innerHTML = originalText; }, 2000);
                });
            }
        });
    }

    // === Export Buttons ===
    document.getElementById('btn-export-json').addEventListener('click', () => {
        if (!lastScanId) return alert('Belum ada hasil scan untuk di-export.');
        window.open(`api/export.php?scan_id=${lastScanId}&format=json`, '_blank');
    });

    document.getElementById('btn-export-pdf').addEventListener('click', () => {
        if (!lastScanId) return alert('Belum ada hasil scan untuk di-export.');
        window.open(`api/export.php?scan_id=${lastScanId}&format=pdf`, '_blank');
    });

    function getPillClass(verdict) {
        const v = (verdict || 'clean').toLowerCase();
        if (v === 'critical' || v === 'dangerous') return 'pill-critical';
        if (v === 'high_risk') return 'pill-high_risk';
        if (v === 'medium_risk' || v === 'suspicious') return 'pill-medium_risk';
        if (v === 'low_risk') return 'pill-low_risk';
        return 'pill-clean';
    }

    // === Scan History ===
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
                const pillClass = getPillClass(row.verdict);

                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); font-weight: 500;">${escapeHtml(row.domain)}</td>
                    <td><span class="badge-pill ${pillClass}">${row.verdict.toUpperCase()}</span></td>
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

    // === Bulk Scan ===
    const bulkForm = document.getElementById('bulk-form');
    const bulkUrls = document.getElementById('bulk-urls');
    const bulkCount = document.getElementById('bulk-count');
    const btnBulkSubmit = document.getElementById('btn-bulk-submit');
    const bulkProgress = document.getElementById('bulk-progress');
    const bulkResults = document.getElementById('bulk-results');
    const bulkTbody = document.getElementById('bulk-tbody');
    const bulkSummary = document.getElementById('bulk-summary');

    bulkUrls.addEventListener('input', () => {
        const lines = bulkUrls.value.split('\n').filter(l => l.trim() !== '');
        bulkCount.textContent = `${lines.length} / 10 URL`;
    });

    bulkForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const lines = bulkUrls.value.split('\n').map(l => l.trim()).filter(l => l !== '');

        if (lines.length === 0) {
            alert('Masukkan minimal 1 URL.');
            return;
        }
        if (lines.length > 10) {
            alert('Maksimal 10 URL per batch.');
            return;
        }

        btnBulkSubmit.disabled = true;
        btnBulkSubmit.textContent = 'Memproses...';
        bulkProgress.classList.add('active');
        document.getElementById('bulk-progress-status').textContent = `Memproses ${lines.length} URL...`;

        try {
            const response = await fetch('api/bulk-scan.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls: lines }),
            });

            const data = await response.json();

            if (!data.success) {
                throw new Error(data.error || 'Bulk scan gagal.');
            }

            renderBulkResults(data.results);
        } catch (err) {
            alert('Kesalahan Bulk Scan: ' + err.message);
        } finally {
            bulkProgress.classList.remove('active');
            btnBulkSubmit.disabled = false;
            btnBulkSubmit.innerHTML = `
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect></svg>
                Scan Semua
            `;
        }
    });

    function renderBulkResults(results) {
        bulkResults.style.display = 'block';
        bulkTbody.innerHTML = '';

        let cleanCount = 0, warnCount = 0, critCount = 0, errors = 0;

        results.forEach((r, idx) => {
            const tr = document.createElement('tr');
            if (!r.success) {
                errors++;
                tr.innerHTML = `
                    <td style="font-family:var(--font-mono);">${idx + 1}</td>
                    <td style="font-family:var(--font-mono); font-size:12px;">${escapeHtml(r.url)}</td>
                    <td colspan="5" style="color:var(--color-danger);">Error: ${escapeHtml(r.error)}</td>
                `;
            } else {
                const pillClass = getPillClass(r.verdict);
                if (pillClass === 'pill-critical' || pillClass === 'pill-high_risk') critCount++;
                else if (pillClass === 'pill-medium_risk') warnCount++;
                else cleanCount++;

                tr.innerHTML = `
                    <td style="font-family:var(--font-mono);">${idx + 1}</td>
                    <td style="font-family:var(--font-mono); font-size:12px; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(r.url)}</td>
                    <td style="font-family:var(--font-mono); font-weight:500;">${escapeHtml(r.domain || '-')}</td>
                    <td><span class="badge-pill ${pillClass}">${(r.verdict_label || r.verdict).toUpperCase()}</span></td>
                    <td style="font-family:var(--font-mono);">${r.risk_score}</td>
                    <td style="font-size:12px; color:var(--text-muted);">${r.is_redirected ? `Redirect (${r.redirect_count})` : 'Direct'}</td>
                    <td style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">${r.execution_time_ms}ms</td>
                `;
            }
            bulkTbody.appendChild(tr);
        });

        bulkSummary.textContent = `Clean/Low: ${cleanCount} | Medium: ${warnCount} | High/Critical: ${critCount} | Errors: ${errors}`;
    }

    // === Dashboard ===
    async function loadDashboard() {
        try {
            const res = await fetch('api/stats.php');
            const data = await res.json();

            if (!data.success) {
                document.getElementById('stat-total').textContent = 'N/A';
                return;
            }

            const s = data.stats;

            document.getElementById('stat-total').textContent = s.total_scans;
            document.getElementById('stat-today').textContent = s.today_scans;
            document.getElementById('stat-avg').textContent = s.avg_risk_score;
            document.getElementById('stat-detection').textContent = s.detection_rate + '%';

            // Verdict Distribution Chart (Doughnut)
            renderVerdictChart(s.verdict_distribution);

            // Daily Trend Chart (Line)
            renderTrendChart(s.daily_trend);

            // Top Domains Table
            renderTopDomains(s.top_domains);
        } catch (e) {
            console.warn('Gagal memuat dashboard:', e);
        }
    }

    function renderVerdictChart(distribution) {
        const ctx = document.getElementById('chart-verdict');
        if (!ctx) return;

        if (verdictChart) verdictChart.destroy();

        const labels = distribution.map(d => d.verdict.charAt(0).toUpperCase() + d.verdict.slice(1));
        const values = distribution.map(d => d.count);
        const colors = distribution.map(d => {
            if (d.verdict === 'safe') return '#10b981';
            if (d.verdict === 'suspicious') return '#f59e0b';
            return '#ef4444';
        });

        const isDark = document.documentElement.getAttribute('data-theme') !== 'light';

        verdictChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{
                    data: values,
                    backgroundColor: colors,
                    borderWidth: 0,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: isDark ? '#9ca3af' : '#4b5563', font: { family: "'Inter', sans-serif", size: 12 } }
                    }
                }
            }
        });
    }

    function renderTrendChart(trend) {
        const ctx = document.getElementById('chart-trend');
        if (!ctx) return;

        if (trendChart) trendChart.destroy();

        const labels = trend.map(t => {
            const d = new Date(t.date);
            return d.toLocaleDateString('id-ID', { day: 'numeric', month: 'short' });
        });
        const values = trend.map(t => t.count);

        const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
        const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
        const textColor = isDark ? '#9ca3af' : '#4b5563';

        trendChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Jumlah Scan',
                    data: values,
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 4,
                    pointBackgroundColor: '#2563eb',
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        ticks: { color: textColor, font: { size: 11 } },
                        grid: { color: gridColor }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: textColor, font: { size: 11 }, stepSize: 1 },
                        grid: { color: gridColor }
                    }
                }
            }
        });
    }

    function renderTopDomains(domains) {
        const tbody = document.getElementById('top-domains-tbody');
        if (!tbody) return;

        if (!domains || domains.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:14px;">Belum ada data.</td></tr>';
            return;
        }

        tbody.innerHTML = '';
        domains.forEach((d, idx) => {
            const tr = document.createElement('tr');
            let pillClass = 'pill-safe';
            if (d.last_verdict === 'dangerous') pillClass = 'pill-dangerous';
            else if (d.last_verdict === 'suspicious') pillClass = 'pill-suspicious';

            tr.innerHTML = `
                <td style="font-family:var(--font-mono); color:var(--text-muted);">${idx + 1}</td>
                <td style="font-family:var(--font-mono); font-weight:500;">${escapeHtml(d.domain)}</td>
                <td style="font-family:var(--font-mono);">${d.count}x</td>
                <td><span class="badge-pill ${pillClass}">${d.last_verdict}</span></td>
            `;
            tbody.appendChild(tr);
        });
    }

    // === Utilities ===
    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
});
