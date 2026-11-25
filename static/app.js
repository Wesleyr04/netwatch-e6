document.addEventListener("DOMContentLoaded", () => {
    // Registro e atualização imediata do Service Worker PWA (v5)
    if ("serviceWorker" in navigator) {
        navigator.serviceWorker.register("/sw.js").then((reg) => {
            reg.update();
        }).catch((err) => {
            console.warn("Falha ao registrar Service Worker PWA:", err);
        });
    }

    // Wrapper fetch anti-cache com query bust ?_t=${Date.now()} e cache: 'no-store'
    async function apiFetch(url, options = {}) {
        const sep = url.includes("?") ? "&" : "?";
        const bustedUrl = `${url}${sep}_t=${Date.now()}`;
        const fetchOpts = {
            cache: "no-store",
            ...options,
            headers: {
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                ...(options.headers || {})
            }
        };
        return fetch(bustedUrl, fetchOpts);
    }

    // Estado atual de rede
    let currentNetwork = {
        ip: null,
        gateway: null,
        network_cidr: null,
        is_connected: false
    };

    let currentBaselineLocked = false;
    let currentModalIp = null;
    let currentModalTrusted = 0;
    let scanPollTimer = null;
    let activeTabId = "tab-overview";

    // Gerenciamento de Abas
    const tabs = document.querySelectorAll(".tab-btn");
    const contents = document.querySelectorAll(".tab-content");

    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            contents.forEach(c => c.classList.remove("active"));
            tab.classList.add("active");
            activeTabId = tab.dataset.tab;
            document.getElementById(activeTabId).classList.add("active");
            if (activeTabId === "tab-devices") {
                loadDevices();
            } else if (activeTabId === "tab-soc") {
                loadSocOverview();
            } else if (activeTabId === "tab-overview") {
                loadDashboard();
            } else if (activeTabId === "tab-services") {
                loadServices();
            } else if (activeTabId === "tab-reports") {
                loadEvents();
            }
        });
    });

    // Elementos principais
    const globalBadge = document.getElementById("global-badge");
    const wifiWarningBanner = document.getElementById("wifi-warning-banner");
    const wifiWarningText = document.getElementById("wifi-warning-text");
    const devicesSubnetSubtitle = document.getElementById("devices-subnet-subtitle");
    const recentChangesList = document.getElementById("recent-changes-list");

    const connPill = document.getElementById("conn-pill");
    const connDetails = document.getElementById("conn-details");
    const latGw = document.getElementById("lat-gw");
    const latWan = document.getElementById("lat-wan");
    const latDns = document.getElementById("lat-dns");

    const netIface = document.getElementById("net-iface");
    const netIp = document.getElementById("net-ip");
    const netMac = document.getElementById("net-mac");
    const netMask = document.getElementById("net-mask");
    const netGw = document.getElementById("net-gw");
    const netDns = document.getElementById("net-dns");

    const devCount = document.getElementById("dev-count");
    const srvCount = document.getElementById("srv-count");
    const socTabBadge = document.getElementById("soc-tab-badge");
    const devicesTbody = document.getElementById("devices-tbody");
    const servicesTbody = document.getElementById("services-tbody");
    const eventsTbody = document.getElementById("events-tbody");
    const historyChart = document.getElementById("history-chart");

    const btnScan = document.getElementById("btn-scan");
    const scanText = document.getElementById("scan-text");
    const btnClearOffline = document.getElementById("btn-clear-offline");
    const scanProgress = document.getElementById("scan-progress");
    const btnRefreshAll = document.getElementById("btn-refresh-all");
    const btnVerifyServices = document.getElementById("btn-verify-services");

    // Elementos SOC
    const socPosturePill = document.getElementById("soc-posture-pill");
    const socSubnetLabel = document.getElementById("soc-subnet-label");
    const socGwMac = document.getElementById("soc-gw-mac");
    const socCntCritical = document.getElementById("soc-cnt-critical");
    const socCntHigh = document.getElementById("soc-cnt-high");
    const socCntMedium = document.getElementById("soc-cnt-medium");
    const socSensorsGrid = document.getElementById("soc-sensors-grid");
    const socBaselineDesc = document.getElementById("soc-baseline-desc");
    const btnSocBaselineToggle = document.getElementById("btn-soc-baseline-toggle");
    const socAlertsList = document.getElementById("soc-alerts-list");

    // Modal Adicionar Serviço
    const modal = document.getElementById("service-modal");
    const btnOpenModal = document.getElementById("btn-open-modal");
    const btnCloseModal = document.getElementById("btn-close-modal");
    const btnCancelModal = document.getElementById("btn-cancel-modal");
    const formAddService = document.getElementById("form-add-service");

    btnOpenModal.addEventListener("click", () => modal.classList.remove("hidden"));
    btnCloseModal.addEventListener("click", () => modal.classList.add("hidden"));
    btnCancelModal.addEventListener("click", () => modal.classList.add("hidden"));

    // Modal Relatório Individual do Dispositivo
    const deviceModal = document.getElementById("device-report-modal");
    const btnCloseDeviceModal = document.getElementById("btn-close-device-modal");
    const btnCloseDeviceFooter = document.getElementById("btn-close-device-footer");
    const dmTrustBtn = document.getElementById("dm-trust-btn");
    const dmCustomNameInput = document.getElementById("dm-custom-name-input");
    const dmSaveNameBtn = document.getElementById("dm-save-name-btn");

    function closeDeviceModal() {
        deviceModal.classList.add("hidden");
        currentModalIp = null;
    }

    if (btnCloseDeviceModal) btnCloseDeviceModal.addEventListener("click", closeDeviceModal);
    if (btnCloseDeviceFooter) btnCloseDeviceFooter.addEventListener("click", closeDeviceModal);
    if (deviceModal) {
        deviceModal.addEventListener("click", (e) => {
            if (e.target === deviceModal) closeDeviceModal();
        });
    }

    function updateSocNavBadge(openCount, posture) {
        if (!socTabBadge) return;
        const cnt = parseInt(openCount || 0, 10);
        if (cnt <= 0) {
            socTabBadge.classList.add("hidden");
            socTabBadge.textContent = "0";
            return;
        }
        socTabBadge.classList.remove("hidden");
        socTabBadge.textContent = cnt;
        socTabBadge.className = "soc-nav-badge";
        if (posture === "CRITICO") {
            socTabBadge.classList.add("soc-nav-crit");
        } else {
            socTabBadge.classList.add("soc-nav-warn");
        }
    }

    function formatDurationShort(sec) {
        const s = Math.max(0, parseInt(sec || 0, 10));
        if (s < 60) return `${s}s`;
        const mins = Math.floor(s / 60);
        const remS = s % 60;
        if (mins < 60) return `${mins}m ${String(remS).padStart(2, "0")}s`;
        const hrs = Math.floor(mins / 60);
        const remM = mins % 60;
        return `${hrs}h ${String(remM).padStart(2, "0")}m`;
    }

    function setScanButtonState(scanning, wifiConnected = true) {
        if (scanning) {
            btnScan.disabled = true;
            if (scanText) scanText.textContent = "Escaneando...";
            scanProgress.classList.remove("hidden");
        } else {
            btnScan.disabled = !wifiConnected;
            if (scanText) scanText.textContent = "Escanear Rede";
            scanProgress.classList.add("hidden");
        }
    }

    function updateModalTrustUI(isTrusted) {
        currentModalTrusted = isTrusted ? 1 : 0;
        const trustBadge = document.getElementById("dm-trust-badge");
        if (currentModalTrusted === 1) {
            trustBadge.textContent = "CONFIÁVEL (BASELINE)";
            trustBadge.className = "role-badge role-trusted";
            dmTrustBtn.textContent = "Remover Confiança";
            dmTrustBtn.className = "btn btn-danger-sm";
        } else {
            if (currentBaselineLocked) {
                trustBadge.textContent = "NÃO AUTORIZADO";
                trustBadge.className = "role-badge role-untrusted";
            } else {
                trustBadge.classList.add("hidden");
            }
            dmTrustBtn.textContent = "✓ Marcar como Confiável";
            dmTrustBtn.className = "btn btn-primary btn-sm";
        }
    }

    // Botão Alternar Confiança no Modal do Dispositivo
    if (dmTrustBtn) {
        dmTrustBtn.addEventListener("click", async () => {
            if (!currentModalIp) return;
            dmTrustBtn.disabled = true;
            const nextTrust = currentModalTrusted === 1 ? 0 : 1;
            try {
                const res = await apiFetch(`/api/devices/${encodeURIComponent(currentModalIp)}/trust`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ is_trusted: nextTrust })
                });
                if (res.ok) {
                    const data = await res.json();
                    updateModalTrustUI(data.is_trusted);
                    await openDeviceReportModal(currentModalIp);
                    await loadDevices();
                    await loadSocOverview();
                }
            } finally {
                dmTrustBtn.disabled = false;
            }
        });
    }

    // Botão Salvar Apelido do Dispositivo no Modal
    if (dmSaveNameBtn) {
        dmSaveNameBtn.addEventListener("click", async () => {
            if (!currentModalIp) return;
            dmSaveNameBtn.disabled = true;
            try {
                const customName = dmCustomNameInput.value.trim();
                const res = await apiFetch(`/api/devices/${encodeURIComponent(currentModalIp)}/trust`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        is_trusted: currentModalTrusted,
                        custom_name: customName
                    })
                });
                if (res.ok) {
                    await openDeviceReportModal(currentModalIp);
                    await loadDevices();
                }
            } finally {
                dmSaveNameBtn.disabled = false;
            }
        });
    }

    // Abrir Modal de Relatório Individual por IP (GET /api/devices/<ip>)
    async function openDeviceReportModal(ip) {
        if (!ip) return;
        currentModalIp = ip;
        deviceModal.classList.remove("hidden");

        document.getElementById("dm-ip").textContent = ip;
        document.getElementById("dm-hostname").textContent = "Carregando relatório detalhado...";
        document.getElementById("btn-export-device-md").href = `/api/report/device/${encodeURIComponent(ip)}/markdown`;

        try {
            const res = await apiFetch(`/api/devices/${encodeURIComponent(ip)}`);
            if (!res.ok) {
                document.getElementById("dm-hostname").textContent = "Erro ao carregar dados deste dispositivo.";
                return;
            }
            const rep = await res.json();

            currentBaselineLocked = Boolean(rep.baseline_locked);
            document.getElementById("dm-ip").textContent = rep.ip;
            const titleHost = rep.custom_name ? `${rep.custom_name} (${rep.hostname})` : (rep.hostname || "Dispositivo na LAN");
            document.getElementById("dm-hostname").textContent = titleHost;
            document.getElementById("dm-device-type").textContent = rep.device_type || "Dispositivo na LAN";
            document.getElementById("dm-vendor").textContent = rep.vendor || "Desconhecido";
            document.getElementById("dm-mac").textContent = rep.mac || "N/A";

            if (dmCustomNameInput) {
                dmCustomNameInput.value = rep.custom_name || "";
            }
            updateModalTrustUI(rep.is_trusted);

            const stPill = document.getElementById("dm-status-pill");
            stPill.textContent = rep.status;
            stPill.className = `pill ${rep.status === "ONLINE" ? "pill-operacional" : "pill-falha"}`;

            // Bloco 1: Tempo & Disponibilidade
            document.getElementById("dm-session-dur").textContent = rep.status === "ONLINE"
                ? (rep.session_duration_human || formatDurationShort(rep.session_duration_seconds))
                : "Offline";
            document.getElementById("dm-total-online").textContent = rep.total_online_human || formatDurationShort(rep.total_online_seconds);
            document.getElementById("dm-uptime").textContent = `${rep.uptime_percent !== undefined ? rep.uptime_percent : 100}%`;
            document.getElementById("dm-first-seen").textContent = (rep.first_seen || "--").replace("T", " ");
            document.getElementById("dm-last-seen").textContent = (rep.last_seen || "--").replace("T", " ");
            document.getElementById("dm-disconnects").textContent = rep.disconnections_count || 0;

            // Bloco 2: Desempenho & Tráfego
            const ls = rep.latency_stats || {};
            document.getElementById("dm-lat-min").textContent = `${ls.min_ms !== undefined ? ls.min_ms : 0} ms`;
            document.getElementById("dm-lat-avg").textContent = `${ls.avg_ms !== undefined ? ls.avg_ms : 0} ms`;
            document.getElementById("dm-lat-max").textContent = `${ls.max_ms !== undefined ? ls.max_ms : 0} ms`;

            const trBox = document.getElementById("dm-traffic-box");
            const tr = rep.traffic || {};
            if (tr.available) {
                trBox.innerHTML = `
                    <div class="dm-traffic-grid">
                        <div>
                            <span class="dm-label">Download Acumulado (RX)</span>
                            <strong>${tr.rx_mb} MB</strong> <span class="text-small text-muted">(${tr.rx_rate_kbps} KB/s)</span>
                        </div>
                        <div>
                            <span class="dm-label">Upload Acumulado (TX)</span>
                            <strong>${tr.tx_mb} MB</strong> <span class="text-small text-muted">(${tr.tx_rate_kbps} KB/s)</span>
                        </div>
                    </div>
                    <p class="text-small text-muted" style="margin-top:4px;">${tr.note || ""}</p>
                `;
            } else {
                trBox.innerHTML = `
                    <p class="text-small text-muted"><strong>Tráfego RX/TX:</strong> ${tr.note || "Indisponível para hosts remotos (isolamento L2 sem root/acesso ao roteador)"}</p>
                `;
            }

            // Bloco 3: Serviços & Portas Detectadas
            const srvContainer = document.getElementById("dm-services-list");
            const srvs = rep.services || [];
            if (!srvs.length) {
                srvContainer.innerHTML = `<p class="text-small text-muted">Nenhuma porta TCP aberta detectada neste host.</p>`;
            } else {
                srvContainer.innerHTML = srvs.map(s => `
                    <div class="dm-service-item">
                        <div class="dm-service-port">
                            <span class="port-badge">${s.port}/TCP</span>
                            <strong>${s.service}</strong>
                        </div>
                        <code class="dm-service-banner">${s.banner || "Porta aberta"}</code>
                    </div>
                `).join("");
            }

            // Bloco 4: Alertas SOC vinculados a este IP
            const socAlertContainer = document.getElementById("dm-soc-alerts-list");
            const hostAlerts = rep.soc_alerts || [];
            if (!hostAlerts.length) {
                socAlertContainer.innerHTML = `<p class="text-small text-muted">&#x2705; Nenhum alerta SOC registrado para este dispositivo.</p>`;
            } else {
                socAlertContainer.innerHTML = hostAlerts.map(a => `
                    <div class="dm-event-item">
                        <div style="display:flex; justify-content:space-between; align-items:center; gap:6px; flex-wrap:wrap;">
                            <span>
                                <span class="soc-sev-tag soc-sev-${(a.severity || 'INFO').toLowerCase()}">${a.severity}</span>
                                <span class="mitre-tag">${a.mitre_id}</span>
                                <strong>${a.title}</strong>
                            </span>
                            <code class="text-small text-muted">${a.status}</code>
                        </div>
                        <span class="text-small text-muted">${a.details}</span>
                    </div>
                `).join("");
            }

            // Bloco 5: Histórico deste Host
            const evContainer = document.getElementById("dm-events-list");
            const evs = rep.events || [];
            if (!evs.length) {
                evContainer.innerHTML = `<p class="text-small text-muted">Nenhum evento específico registrado para este IP.</p>`;
            } else {
                evContainer.innerHTML = evs.map(e => {
                    const isLeave = e.message.includes("SAIU") || e.severity === "WARNING";
                    const dot = isLeave ? "&#x1F534;" : "&#x1F7E2;";
                    return `
                        <div class="dm-event-item">
                            <span class="dm-event-time">${dot} <code>${(e.timestamp || "").replace("T", " ").slice(0, 19)}</code></span>
                            <span class="dm-event-msg">${e.message}</span>
                        </div>
                    `;
                }).join("");
            }
        } catch (err) {
            console.error("Erro ao abrir relatório individual:", err);
            document.getElementById("dm-hostname").textContent = "Falha de comunicação ao carregar relatório.";
        }
    }

    // 1. Carregar Dashboard Geral
    async function loadDashboard() {
        try {
            const res = await apiFetch("/api/dashboard");
            const data = await res.json();

            const net = data.network || {};
            currentNetwork = net;

            netIface.textContent = net.interface || "--";
            netIp.textContent = net.is_connected ? `${net.ip || "--"} / ${net.cidr || 24}` : "Desconectado";
            if (netMac) {
                netMac.textContent = net.mac || "--";
            }
            netMask.textContent = net.is_connected ? (net.netmask || "--") : "--";
            netGw.textContent = net.is_connected ? (net.gateway || "--") : "--";
            netDns.textContent = (net.dns && net.dns.length) ? net.dns.join(", ") : "--";

            if (devicesSubnetSubtitle) {
                const lastScanSuffix = data.metrics && data.metrics.last_scan_time
                    ? ` • Última verificação: ${data.metrics.last_scan_time}`
                    : "";
                devicesSubnetSubtitle.textContent = net.is_connected && net.network_cidr
                    ? `Sub-rede: ${net.network_cidr} • Toque em um host para abrir o Relatório Individual${lastScanSuffix}`
                    : "Conecte a uma rede Wi-Fi para monitorar dispositivos";
            }

            if (net.is_connected === false) {
                wifiWarningBanner.classList.remove("hidden");
                wifiWarningText.textContent = net.status_reason || "Conecte o aparelho a uma rede Wi-Fi para iniciar o monitoramento";
                btnScan.title = net.status_reason || "Requer conexão Wi-Fi";
            } else {
                wifiWarningBanner.classList.add("hidden");
                btnScan.title = "";
            }

            const c = data.connectivity || {};
            const cls = net.is_connected === false ? "WIFI_DESCONECTADO" : (c.classification || "DESCONHECIDO");
            connPill.textContent = cls.replace(/_/g, " ");
            connPill.className = "pill";

            if (cls === "OPERACIONAL") {
                connPill.classList.add("pill-operacional");
                globalBadge.textContent = "ONLINE";
                globalBadge.className = "badge badge-online";
            } else if (cls.includes("FALHA") || cls === "WIFI_DESCONECTADO") {
                connPill.classList.add("pill-falha");
                globalBadge.textContent = net.is_connected === false ? "SEM WI-FI" : "DEGRADADO";
                globalBadge.className = "badge badge-offline";
            } else {
                connPill.classList.add("pill-unknown");
                globalBadge.textContent = "AGUARDANDO";
                globalBadge.className = "badge badge-pending";
            }

            connDetails.textContent = net.is_connected === false ? (net.status_reason || "") : (c.details || "");
            latGw.textContent = c.gateway_latency !== null && c.gateway_latency !== undefined ? `${c.gateway_latency} ms` : "FALHA";
            latWan.textContent = c.external_latency !== null && c.external_latency !== undefined ? `${c.external_latency} ms` : "FALHA";
            latDns.textContent = c.dns_latency !== null && c.dns_latency !== undefined ? `${c.dns_latency} ms` : "FALHA";

            devCount.textContent = data.metrics.total_devices || 0;
            srvCount.textContent = data.metrics.total_services || 0;
            updateSocNavBadge(data.metrics.soc_open_alerts, data.metrics.soc_posture);

            renderHistoryBars(data.history || []);

            if (!scanPollTimer) {
                setScanButtonState(Boolean(data.metrics.is_scanning), net.is_connected !== false);
            }

        } catch (err) {
            console.error("Erro ao carregar dashboard:", err);
            globalBadge.textContent = "ERRO API";
            globalBadge.className = "badge badge-offline";
        }
    }

    function renderHistoryBars(history) {
        historyChart.innerHTML = "";
        if (!history.length) {
            historyChart.innerHTML = "<span class='text-muted text-small'>Sem dados de latência coletados.</span>";
            return;
        }

        const maxLat = Math.max(...history.map(h => Math.max(h.gateway_latency || 0, h.external_latency || 0, h.dns_latency || 0)), 150);

        history.forEach(item => {
            const col = document.createElement("div");
            col.className = "history-col";
            col.title = `${item.timestamp}\nGW: ${item.gateway_latency}ms\nWAN: ${item.external_latency}ms\nDNS: ${item.dns_latency}ms\nStatus: ${item.classification}`;

            const bar = document.createElement("div");
            bar.className = "history-bar";

            const val = item.external_latency || item.gateway_latency || 5;
            const heightPercent = Math.min(100, Math.max(8, (val / maxLat) * 100));
            bar.style.height = `${heightPercent}%`;

            if (item.classification === "OPERACIONAL") {
                bar.style.backgroundColor = "#238636";
            } else {
                bar.style.backgroundColor = "#f85149";
            }

            col.appendChild(bar);
            historyChart.appendChild(col);
        });
    }

    function renderPortBadges(portsStr) {
        if (!portsStr || !portsStr.trim()) {
            return '<span class="text-muted text-small">Nenhuma porta</span>';
        }
        const ports = portsStr.split(",").map(p => p.trim()).filter(Boolean);
        if (!ports.length) {
            return '<span class="text-muted text-small">Nenhuma porta</span>';
        }
        return `<div class="ports-wrap">${ports.map(p => `<span class="port-badge">${p}</span>`).join("")}</div>`;
    }

    function formatTimeHHMMSS(isoStr) {
        if (!isoStr) return "--:--:--";
        const parts = String(isoStr).split("T");
        const timePart = parts.length > 1 ? parts[1] : String(isoStr);
        return timePart.slice(0, 8);
    }

    function renderRecentChanges(changes) {
        if (!recentChangesList) return;
        if (!changes || !changes.length) {
            recentChangesList.innerHTML = `<span class="text-muted text-small">Nenhuma entrada ou saída recente registrada nesta sub-rede.</span>`;
            return;
        }
        recentChangesList.innerHTML = changes.map(c => {
            const isLeave = c.action === "LEFT";
            const icon = isLeave ? "&#x1F534;" : "&#x1F7E2;";
            const cls = isLeave ? "recent-chip-leave" : "recent-chip-enter";
            const timeAgo = c.time_ago_human || `há ${formatDurationShort(c.seconds_ago)}`;
            return `
                <button type="button" class="recent-change-chip ${cls}" data-ip="${c.ip}">
                    <span>${icon} <strong>${c.label}</strong> &bull; ${timeAgo}</span>
                </button>
            `;
        }).join("");

        recentChangesList.querySelectorAll(".recent-change-chip").forEach(chip => {
            chip.addEventListener("click", () => {
                const ip = chip.dataset.ip;
                if (ip) openDeviceReportModal(ip);
            });
        });
    }

    // 2. Carregar Dispositivos (com movimentação recente, badges pulsantes, status de confiança e clique para relatório)
    async function loadDevices() {
        try {
            const res = await apiFetch("/api/devices");
            const data = await res.json();
            const devs = data.devices || [];
            currentBaselineLocked = Boolean(data.baseline_locked);

            devCount.textContent = devs.length;
            renderRecentChanges(data.recent_changes || []);

            if (!devs.length) {
                devicesTbody.innerHTML = `<tr class="empty-row"><td colspan="7" class="text-center text-muted">Nenhum dispositivo detectado na sub-rede atual. Clique em "Escanear Rede".</td></tr>`;
                return data;
            }

            devicesTbody.innerHTML = devs.map(device => {
                const isLocalHost = Boolean(
                    currentNetwork.is_connected &&
                    currentNetwork.ip &&
                    device.ip === currentNetwork.ip &&
                    device.status === "ONLINE"
                );

                const isGateway = Boolean(
                    currentNetwork.is_connected &&
                    currentNetwork.gateway &&
                    device.ip === currentNetwork.gateway
                );

                let rowClass = "device-row clickable-row";
                let roleBadge = "";
                if (isLocalHost) {
                    rowClass += " row-local-host";
                    roleBadge = '<span class="role-badge role-local">HOST LOCAL</span>';
                } else if (isGateway) {
                    rowClass += " row-gateway";
                    roleBadge = '<span class="role-badge role-gateway">GATEWAY</span>';
                }

                // Badge de confiança quando baseline estiver travada ou host for confiável
                let trustBadge = "";
                if (currentBaselineLocked && !device.is_trusted) {
                    trustBadge = '<span class="role-badge role-untrusted">NÃO AUTORIZADO</span>';
                } else if (device.is_trusted === 1) {
                    trustBadge = '<span class="role-badge role-trusted">CONFIÁVEL</span>';
                }

                // Destaque visual imediato para dispositivos com movimentação recente (<= 180s)
                let movementBadge = "";
                if (device.recently_changed) {
                    if (device.status === "ONLINE") {
                        rowClass += " row-recently-entered";
                        movementBadge = '<span class="pulse-badge pulse-enter">ENTROU AGORA</span>';
                    } else {
                        rowClass += " row-recently-left";
                        movementBadge = '<span class="pulse-badge pulse-leave">SAIU AGORA</span>';
                    }
                }

                let baseHostname = device.hostname || "Dispositivo na LAN";
                if (!isLocalHost && baseHostname.includes("Host Local")) {
                    baseHostname = "Dispositivo na LAN";
                }
                if (!isGateway && baseHostname.includes("Gateway")) {
                    baseHostname = "Dispositivo na LAN";
                }
                const displayHostname = device.custom_name ? `${device.custom_name}` : baseHostname;

                const vendorLabel = device.vendor && device.vendor !== "Desconhecido" ? device.vendor : "";
                const typeLabel = device.device_type && device.device_type !== "Desconhecido" ? device.device_type : "";
                const latencyVal = (device.latency !== null && device.latency !== undefined) ? `${device.latency} ms` : "--";
                const lastSeenTime = formatTimeHHMMSS(device.last_seen);
                const statusPillClass = device.status === "ONLINE" ? "pill-operacional" : "pill-falha";

                const sessionInfo = device.status === "ONLINE"
                    ? `Conectado há ${formatDurationShort(device.session_duration_seconds)}`
                    : `Offline • Quedas: ${device.disconnections_count || 0}`;

                return `
                    <tr class="${rowClass}" data-ip="${device.ip}" title="Toque para abrir o Relatório Individual de ${device.ip}">
                        <td class="cell-ip">
                            <strong>${device.ip}</strong>
                            ${roleBadge}
                            ${trustBadge}
                            ${movementBadge}
                        </td>
                        <td class="cell-host">
                            <span class="device-hostname">${displayHostname}</span>
                            ${typeLabel ? `<span class="device-submeta">${typeLabel}</span>` : ""}
                        </td>
                        <td class="cell-mac">
                            <code class="device-mac">${device.mac || 'N/A'}</code>
                            ${vendorLabel ? `<span class="device-submeta">${vendorLabel}</span>` : ""}
                        </td>
                        <td class="cell-ports">${renderPortBadges(device.open_ports)}</td>
                        <td class="cell-lat"><span class="meta-label">Lat:</span> ${latencyVal}</td>
                        <td class="cell-seen text-small">
                            <span class="session-badge">${sessionInfo}</span>
                            <span class="seen-clock"><span class="meta-label">Visto:</span> <code>${lastSeenTime}</code></span>
                        </td>
                        <td class="cell-status"><span class="pill ${statusPillClass}">${device.status}</span></td>
                    </tr>
                `;
            }).join("");

            devicesTbody.querySelectorAll("tr.device-row").forEach(tr => {
                tr.addEventListener("click", () => {
                    const ip = tr.dataset.ip;
                    if (ip) openDeviceReportModal(ip);
                });
            });

            return data;
        } catch (err) {
            console.error("Erro ao carregar dispositivos:", err);
            return null;
        }
    }

    // 3. Carregar Visão Geral SOC (GET /api/soc/overview)
    async function loadSocOverview() {
        try {
            const res = await apiFetch("/api/soc/overview");
            const data = await res.json();

            currentBaselineLocked = Boolean(data.baseline_locked);
            const counts = data.counts || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, total_open: 0 };
            updateSocNavBadge(counts.total_open, data.posture);

            if (socSubnetLabel) {
                socSubnetLabel.textContent = data.network_cidr ? `Sub-rede: ${data.network_cidr}` : "--";
            }
            if (socGwMac) {
                socGwMac.textContent = data.gateway_mac_locked || "N/A";
            }

            if (socPosturePill) {
                const p = data.posture || "SEGURO";
                socPosturePill.className = "soc-posture-badge";
                if (p === "CRITICO") {
                    socPosturePill.textContent = "CRÍTICO";
                    socPosturePill.classList.add("soc-posture-crit");
                } else if (p === "ATENCAO") {
                    socPosturePill.textContent = "ATENÇÃO";
                    socPosturePill.classList.add("soc-posture-warn");
                } else {
                    socPosturePill.textContent = "SEGURO";
                    socPosturePill.classList.add("soc-posture-safe");
                }
            }

            if (socCntCritical) socCntCritical.textContent = counts.CRITICAL || 0;
            if (socCntHigh) socCntHigh.textContent = counts.HIGH || 0;
            if (socCntMedium) socCntMedium.textContent = counts.MEDIUM || 0;

            // Renderiza os 4 chips de sensores automáticos
            if (socSensorsGrid && data.sensors) {
                socSensorsGrid.innerHTML = data.sensors.map(s => {
                    const isAlert = s.status === "ALERTA" || s.status === "SUSPEITO";
                    const stClass = isAlert ? "sensor-chip-alert" : "sensor-chip-ok";
                    return `
                        <div class="soc-sensor-chip ${stClass}">
                            <div class="soc-sensor-top">
                                <strong>${s.name}</strong>
                                <span class="mitre-tag">${s.mitre}</span>
                            </div>
                            <div class="soc-sensor-bottom">
                                <span class="sensor-state-dot"></span>
                                <span class="sensor-state-label">${s.status}</span>
                                <span class="text-small text-muted">&bull; ${s.detail || ""}</span>
                            </div>
                        </div>
                    `;
                }).join("");
            }

            // Botão Baseline 1-toque
            if (btnSocBaselineToggle) {
                if (currentBaselineLocked) {
                    btnSocBaselineToggle.textContent = "🔓 Destravar Baseline da Rede";
                    btnSocBaselineToggle.className = "btn btn-outline";
                    if (socBaselineDesc) {
                        socBaselineDesc.textContent = `Baseline ATIVA (${data.trusted_devices_count || 0} dispositivos autorizados). Qualquer aparelho novo gera alerta ROGUE_DEVICE (T1200).`;
                    }
                } else {
                    btnSocBaselineToggle.textContent = "🔒 Travar Baseline da Rede Atual";
                    btnSocBaselineToggle.className = "btn btn-primary";
                    if (socBaselineDesc) {
                        socBaselineDesc.textContent = "Com um toque, autoriza os dispositivos atualmente conectados e alerta automaticamente qualquer aparelho novo na rede.";
                    }
                }
            }

            // Feed de Alertas SOC
            if (socAlertsList) {
                const alerts = data.alerts || [];
                if (!alerts.length) {
                    socAlertsList.innerHTML = `
                        <div class="soc-empty-box">
                            <span>&#x1F6E1; Nenhum alerta SOC registrado para a rede ${data.network_cidr || "atual"}. Todos os 4 sensores operam normalmente.</span>
                        </div>
                    `;
                } else {
                    socAlertsList.innerHTML = alerts.map(a => {
                        const isOpen = a.status === "OPEN";
                        const sevLower = (a.severity || "INFO").toLowerCase();
                        const targetBadge = a.target_ip
                            ? `<button type="button" class="soc-target-link" data-ip="${a.target_ip.split(",")[0].trim()}">Alvo: ${a.target_ip}${a.target_mac ? ` (${a.target_mac})` : ""}</button>`
                            : "";
                        return `
                            <div class="soc-alert-card ${isOpen ? `soc-alert-open-${sevLower}` : "soc-alert-ack"}">
                                <div class="soc-alert-header">
                                    <div class="soc-alert-tags">
                                        <span class="soc-sev-tag soc-sev-${sevLower}">${a.severity}</span>
                                        <span class="mitre-tag">${a.mitre_id}</span>
                                        <span class="soc-cat-tag">${a.category}</span>
                                        ${targetBadge}
                                    </div>
                                    <div class="soc-alert-meta">
                                        <code class="text-small text-muted">${(a.timestamp || "").replace("T", " ").slice(0, 19)}</code>
                                        ${isOpen
                                            ? `<button type="button" class="btn btn-secondary btn-sm btn-ack-alert" data-id="${a.id}">Reconhecer (ACK)</button>`
                                            : `<span class="pill pill-unknown" style="font-size:0.7rem;padding:2px 8px;">RECONHECIDO</span>`
                                        }
                                    </div>
                                </div>
                                <h4 class="soc-alert-title">${a.title}</h4>
                                <p class="soc-alert-details">${a.details}</p>
                            </div>
                        `;
                    }).join("");

                    socAlertsList.querySelectorAll(".btn-ack-alert").forEach(btn => {
                        btn.addEventListener("click", async () => {
                            const id = btn.dataset.id;
                            btn.disabled = true;
                            try {
                                await apiFetch(`/api/soc/alerts/${id}/ack`, { method: "POST" });
                                await loadSocOverview();
                                await loadDashboard();
                            } finally {
                                btn.disabled = false;
                            }
                        });
                    });

                    socAlertsList.querySelectorAll(".soc-target-link").forEach(linkBtn => {
                        linkBtn.addEventListener("click", () => {
                            const ip = linkBtn.dataset.ip;
                            if (ip) openDeviceReportModal(ip);
                        });
                    });
                }
            }
        } catch (err) {
            console.error("Erro ao carregar visão SOC:", err);
        }
    }

    // Botão Travar / Destravar Baseline 1-toque
    if (btnSocBaselineToggle) {
        btnSocBaselineToggle.addEventListener("click", async () => {
            btnSocBaselineToggle.disabled = true;
            const endpoint = currentBaselineLocked ? "/api/soc/baseline/unlock" : "/api/soc/baseline/lock";
            try {
                await apiFetch(endpoint, { method: "POST" });
                await loadSocOverview();
                await loadDevices();
                await loadDashboard();
            } finally {
                btnSocBaselineToggle.disabled = false;
            }
        });
    }

    // 4. Disparar Varredura Rápida com Polling de 1000ms
    btnScan.addEventListener("click", async () => {
        if (scanPollTimer) {
            clearInterval(scanPollTimer);
            scanPollTimer = null;
        }
        setScanButtonState(true, true);

        try {
            const res = await apiFetch("/api/scan", { method: "POST" });
            const data = await res.json();
            if (!res.ok) {
                alert(data.message || "Não foi possível iniciar a varredura.");
                setScanButtonState(false, currentNetwork.is_connected !== false);
                return;
            }

            scanPollTimer = setInterval(async () => {
                try {
                    const check = await apiFetch("/api/devices");
                    const devData = await check.json();
                    if (devData && devData.is_scanning === false) {
                        clearInterval(scanPollTimer);
                        scanPollTimer = null;
                        await loadDashboard();
                        await loadDevices();
                        await loadSocOverview();
                        await loadEvents();
                        setScanButtonState(false, currentNetwork.is_connected !== false);
                    }
                } catch (pollErr) {
                    console.error("Erro no polling de scan:", pollErr);
                }
            }, 1000);
        } catch (err) {
            alert("Falha ao disparar varredura: " + err);
            setScanButtonState(false, currentNetwork.is_connected !== false);
        }
    });

    // Botão Limpar Histórico (DELETE /api/devices/offline)
    if (btnClearOffline) {
        btnClearOffline.addEventListener("click", async () => {
            btnClearOffline.disabled = true;
            try {
                const res = await apiFetch("/api/devices/offline", { method: "DELETE" });
                const data = await res.json();
                if (res.ok) {
                    await loadDashboard();
                    await loadDevices();
                    await loadEvents();
                } else {
                    alert(data.message || "Falha ao limpar histórico.");
                }
            } catch (err) {
                alert("Erro ao limpar histórico: " + err);
            } finally {
                btnClearOffline.disabled = false;
            }
        });
    }

    // 5. Carregar Serviços
    async function loadServices() {
        try {
            const res = await apiFetch("/api/services");
            const data = await res.json();
            const srvs = data.services || [];

            if (!srvs.length) {
                servicesTbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">Nenhum serviço cadastrado.</td></tr>`;
                return;
            }

            servicesTbody.innerHTML = srvs.map(s => `
                <tr>
                    <td><strong>${s.name}</strong></td>
                    <td><code>${s.host}:${s.port}</code></td>
                    <td><span class="pill pill-unknown">${s.service_type}</span></td>
                    <td><span class="pill ${s.status === 'ONLINE' ? 'pill-operacional' : (s.status === 'DEGRADADO' ? 'pill-degradado' : 'pill-falha')}">${s.status}</span></td>
                    <td>${s.latency ? s.latency + ' ms' : '--'}</td>
                    <td><span class="text-small text-muted">${s.details || '-'}</span></td>
                    <td>
                        <button class="btn btn-danger-sm btn-delete-srv" data-id="${s.id}">Remover</button>
                    </td>
                </tr>
            `).join("");

            document.querySelectorAll(".btn-delete-srv").forEach(btn => {
                btn.addEventListener("click", async () => {
                    const id = btn.dataset.id;
                    if (confirm("Deseja remover este serviço?")) {
                        await apiFetch(`/api/services?id=${id}`, { method: "DELETE" });
                        loadServices();
                        loadDashboard();
                    }
                });
            });
        } catch (err) {
            console.error("Erro ao carregar serviços:", err);
        }
    }

    // Formulário Adicionar Serviço
    formAddService.addEventListener("submit", async (e) => {
        e.preventDefault();
        const payload = {
            name: document.getElementById("srv-name").value,
            host: document.getElementById("srv-host").value,
            port: parseInt(document.getElementById("srv-port").value),
            service_type: document.getElementById("srv-type").value
        };

        try {
            const res = await apiFetch("/api/services", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (data.status === "SUCCESS") {
                modal.classList.add("hidden");
                formAddService.reset();
                loadServices();
                loadDashboard();
            } else {
                alert("Erro: " + data.message);
            }
        } catch (err) {
            alert("Erro de comunicação: " + err);
        }
    });

    btnVerifyServices.addEventListener("click", async () => {
        btnVerifyServices.disabled = true;
        btnVerifyServices.textContent = "Testando...";
        try {
            await apiFetch("/api/services/verify", { method: "POST" });
            await loadServices();
            await loadDashboard();
        } finally {
            btnVerifyServices.disabled = false;
            btnVerifyServices.textContent = "Testar Todos Agora";
        }
    });

    // 6. Carregar Eventos
    async function loadEvents() {
        try {
            const res = await apiFetch("/api/events");
            const data = await res.json();
            const evs = data.events || [];

            if (!evs.length) {
                eventsTbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">Nenhum evento registrado.</td></tr>`;
                return;
            }

            eventsTbody.innerHTML = evs.map(e => `
                <tr>
                    <td class="text-small"><code>${e.timestamp.replace("T", " ").slice(0, 19)}</code></td>
                    <td><span class="pill pill-unknown">${e.event_type}</span></td>
                    <td><span class="pill ${e.severity === 'CRITICAL' ? 'pill-falha' : (e.severity === 'WARNING' ? 'pill-degradado' : 'pill-operacional')}">${e.severity}</span></td>
                    <td>${e.message}</td>
                </tr>
            `).join("");
        } catch (err) {
            console.error("Erro ao carregar eventos:", err);
        }
    }

    // Botão Atualizar Geral
    btnRefreshAll.addEventListener("click", async () => {
        await loadDashboard();
        await loadDevices();
        await loadSocOverview();
        await loadServices();
        await loadEvents();
    });

    // Carga inicial sequencial
    (async () => {
        await loadDashboard();
        await loadDevices();
        await loadSocOverview();
        await loadServices();
        await loadEvents();
    })();

    // Polling reativo a cada 4 segundos na aba ativa (cache: 'no-store')
    setInterval(async () => {
        if (scanPollTimer) return;
        await loadDashboard();
        await loadDevices();
        if (activeTabId === "tab-soc") {
            await loadSocOverview();
        } else if (activeTabId === "tab-services") {
            await loadServices();
        } else if (activeTabId === "tab-reports") {
            await loadEvents();
        }
    }, 4000);
});
