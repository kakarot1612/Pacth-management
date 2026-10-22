// State
let allServers = [];
let currentSelectedServer = null;
let currentAiGuidance = null;
let currentApprovals = {};
let currentScheduler = {};

// DOM Elements
const schedulerText = document.getElementById("schedulerText");
const serversTableBody = document.getElementById("serversTableBody");
const searchInput = document.getElementById("searchInput");
const filterStatus = document.getElementById("filterStatus");
const serverCountTag = document.getElementById("serverCountTag");

const valComplianceRate = document.getElementById("valComplianceRate");
const barCompliance = document.getElementById("barCompliance");
const valComplianceStatus = document.getElementById("valComplianceStatus");
const valCriticalCompliance = document.getElementById("valCriticalCompliance");
const barCriticalCompliance = document.getElementById("barCriticalCompliance");
const valCriticalCount = document.getElementById("valCriticalCount");
const valPendingRescanCount = document.getElementById("valPendingRescanCount");
const valRebootPendingCount = document.getElementById("valRebootPendingCount");

const inspectorPanel = document.getElementById("inspectorPanel");
const inspectorEmpty = document.getElementById("inspectorEmpty");
const inspectorContent = document.getElementById("inspectorContent");
const insServerName = document.getElementById("insServerName");
const insServerSub = document.getElementById("insServerSub");
const insHotfixCount = document.getElementById("insHotfixCount");
const insVulnCount = document.getElementById("insVulnCount");
const insRescanCount = document.getElementById("insRescanCount");
const insRebootState = document.getElementById("insRebootState");
const vulnCardsContainer = document.getElementById("vulnCardsContainer");

const btnRefresh = document.getElementById("btnRefresh");
const btnRunScan = document.getElementById("btnRunScan");
const btnCloseInspector = document.getElementById("btnCloseInspector");
const btnForceRescan = document.getElementById("btnForceRescan");
const btnCheckReboot = document.getElementById("btnCheckReboot");

// Modal Elements
const aiModal = document.getElementById("aiModal");
const aiModalTitle = document.getElementById("aiModalTitle");
const aiModalSource = document.getElementById("aiModalSource");
const aiModalLoading = document.getElementById("aiModalLoading");
const aiModalText = document.getElementById("aiModalText");
const btnCloseAiModal = document.getElementById("btnCloseAiModal");
const btnCopyAiScript = document.getElementById("btnCopyAiScript");
const btnCreateExceptionFromAi = document.getElementById("btnCreateExceptionFromAi");
const toastContainer = document.getElementById("toastContainer");

// Audit Modal Elements
const btnOpenAuditLogs = document.getElementById("btnOpenAuditLogs");
const btnOpenAuditReport = document.getElementById("btnOpenAuditReport");
const auditLogsModal = document.getElementById("auditLogsModal");
const btnCloseAuditLogsModal = document.getElementById("btnCloseAuditLogsModal");
const btnCloseAuditLogsModalBottom = document.getElementById("btnCloseAuditLogsModalBottom");
const auditLogSearch = document.getElementById("auditLogSearch");
const auditLogActionFilter = document.getElementById("auditLogActionFilter");
const btnRefreshAuditLogs = document.getElementById("btnRefreshAuditLogs");
const auditLogsTbody = document.getElementById("auditLogsTbody");
const auditLogCount = document.getElementById("auditLogCount");

const auditReportModal = document.getElementById("auditReportModal");
const btnCloseAuditReportModal = document.getElementById("btnCloseAuditReportModal");
const btnCloseAuditReportModalBottom = document.getElementById("btnCloseAuditReportModalBottom");
const auditModalTotalServers = document.getElementById("auditModalTotalServers");
const auditModalCompliance = document.getElementById("auditModalCompliance");
const auditModalRemediated = document.getElementById("auditModalRemediated");
const auditModalReboot = document.getElementById("auditModalReboot");

let currentAuditLogs = [];

// Initialize
document.addEventListener("DOMContentLoaded", () => {
    loadData();
    setupEventListeners();
    // Tự động làm mới trạng thái định kỳ mỗi 20 giây
    setInterval(loadData, 20000);
});

function setupEventListeners() {
    btnRefresh.addEventListener("click", async () => {
        btnRefresh.disabled = true;
        btnRefresh.innerHTML = `<span class="spinner" style="width:14px;height:14px;margin:0;display:inline-block;vertical-align:middle;"></span> Đang làm mới...`;
        showToast("Đang đồng bộ và quét đối chiếu trạng thái máy chủ mới nhất...");
        try {
            await fetch("/api/scan", { method: "POST" });
            await loadData();
            showToast("✅ Đã cập nhật thành công trạng thái mới nhất từ Wazuh & WSUS!", "success");
        } catch (err) {
            await loadData();
            showToast("Đã làm mới dữ liệu: " + err.message, "warning");
        } finally {
            btnRefresh.disabled = false;
            btnRefresh.innerHTML = `<span class="icon">🔄</span> Làm mới`;
        }
    });

    btnRunScan.addEventListener("click", async () => {
        btnRunScan.disabled = true;
        btnRunScan.innerHTML = `<span class="spinner" style="width:14px;height:14px;margin:0;display:inline-block;vertical-align:middle;"></span> Đang quét...`;
        showToast("Bắt đầu quy trình kiểm toán & đối chiếu Rule #4...");
        try {
            const resp = await fetch("/api/scan", { method: "POST" });
            const data = await resp.json();
            showToast("Quét hoàn tất! Đã cập nhật trạng thái mới nhất.");
            loadData();
        } catch (err) {
            showToast("Lỗi khi gửi lệnh quét: " + err.message, "danger");
        } finally {
            btnRunScan.disabled = false;
            btnRunScan.innerHTML = `<span class="icon">⚡</span> Quét & Đối chiếu Lỗ hổng`;
        }
    });

    searchInput.addEventListener("input", renderServersTable);
    filterStatus.addEventListener("change", renderServersTable);

    btnCloseInspector.addEventListener("click", () => {
        inspectorContent.style.display = "none";
        inspectorEmpty.style.display = "block";
        document.querySelectorAll(".data-table tbody tr").forEach(r => r.classList.remove("active-row"));
        currentSelectedServer = null;
    });

    btnForceRescan.addEventListener("click", async () => {
        if (!currentSelectedServer) return;
        btnForceRescan.disabled = true;
        btnForceRescan.textContent = "Đang quét live...";
        try {
            const resp = await fetch("/api/trigger-rescan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ agent_id: currentSelectedServer.agent_id })
            });
            const res = await resp.json();
            if (res.success) {
                showToast(res.message || `Đã quét và cập nhật ${currentSelectedServer.agent_name}`);
                await loadData();
            } else {
                showToast(res.message || "Quét lại thất bại", "warning");
            }
        } catch (e) {
            showToast("Không thể gửi lệnh rescan: " + e.message, "danger");
        } finally {
            btnForceRescan.disabled = false;
            btnForceRescan.textContent = "🔄 Ép Wazuh Quét Lại";
        }
    });

    btnCheckReboot.addEventListener("click", async () => {
        if (!currentSelectedServer) return;
        const isPending = currentSelectedServer.reboot_pending;
        if (isPending) {
            const confirmClear = confirm(
                `⚠️ Máy chủ ${currentSelectedServer.agent_name} đang có cờ CẦN KHỞI ĐỘNG LẠI!\n` +
                `Lý do: ${currentSelectedServer.reboot_reasons || 'Pending Update Component'}\n\n` +
                `Nếu bạn ĐÃ KHỞI ĐỘNG LẠI (Restart) máy chủ này rồi, bạn có muốn XÓA CỜ REBOOT không?`
            );
            if (confirmClear) {
                try {
                    await fetch("/api/server-reboot-status", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ agent_id: currentSelectedServer.agent_id, reboot_pending: false })
                    });
                    showToast(`✅ Đã xóa cờ chờ Reboot cho ${currentSelectedServer.agent_name}!`);
                    loadData();
                } catch (e) {
                    showToast("Lỗi khi cập nhật trạng thái reboot: " + e.message, "danger");
                }
            }
        } else {
            const togglePending = confirm(
                `✅ Máy chủ ${currentSelectedServer.agent_name} hiện KHÔNG CÓ cờ chờ Reboot.\n\n` +
                `Bạn có muốn đánh dấu máy chủ này CẦN REBOOT (ví dụ: vừa cài đặt bản vá đang đợi cửa sổ bảo trì) không?`
            );
            if (togglePending) {
                try {
                    await fetch("/api/server-reboot-status", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ agent_id: currentSelectedServer.agent_id, reboot_pending: true, reboot_reasons: "Admin Manual Flag" })
                    });
                    showToast(`⚠️ Đã gắn cờ Cần Reboot cho ${currentSelectedServer.agent_name}!`);
                    loadData();
                } catch (e) {
                    showToast("Lỗi khi cập nhật trạng thái reboot: " + e.message, "danger");
                }
            }
        }
    });

    btnCloseAiModal.addEventListener("click", () => {
        aiModal.style.display = "none";
    });

    btnCopyAiScript.addEventListener("click", () => {
        if (!currentAiGuidance) return;
        const codeMatch = currentAiGuidance.match(/```powershell([\s\S]*?)```/);
        const scriptToCopy = codeMatch ? codeMatch[1].trim() : currentAiGuidance;
        navigator.clipboard.writeText(scriptToCopy).then(() => {
            showToast("Đã sao chép kịch bản PowerShell vào clipboard!");
        });
    });

    btnCreateExceptionFromAi.addEventListener("click", async () => {
        if (!currentSelectedServer || !currentSelectedServer.active_ai_cve) return;
        const cve = currentSelectedServer.active_ai_cve;
        const server = currentSelectedServer.agent_name;
        const reason = prompt("Lý do chấp nhận rủi ro / chưa thể vá:", "Ứng dụng Legacy chưa hỗ trợ bản vá tháng này");
        if (!reason) return;

        try {
            const resp = await fetch("/api/exception", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    cve: cve,
                    server: server,
                    reason: reason,
                    control: "Áp dụng hướng dẫn giảm nhẹ từ AI Gemini, cô lập mạng và giám sát Wazuh",
                    owner: "Infra Team",
                    approved_by: "SecOps Lead",
                    expires: "2026-12-31"
                })
            });
            showToast(`Đã đăng ký ngoại lệ thành công cho ${cve} trên ${server}!`);
            aiModal.style.display = "none";
            loadData();
        } catch (e) {
            showToast("Lỗi khi lưu ngoại lệ: " + e.message, "danger");
        }
    });

    // Audit Logs Modal Listeners
    if (btnOpenAuditLogs) {
        btnOpenAuditLogs.addEventListener("click", () => {
            auditLogsModal.style.display = "flex";
            loadAuditLogs();
        });
    }
    if (btnCloseAuditLogsModal) {
        btnCloseAuditLogsModal.addEventListener("click", () => {
            auditLogsModal.style.display = "none";
        });
    }
    if (btnCloseAuditLogsModalBottom) {
        btnCloseAuditLogsModalBottom.addEventListener("click", () => {
            auditLogsModal.style.display = "none";
        });
    }
    if (btnRefreshAuditLogs) {
        btnRefreshAuditLogs.addEventListener("click", () => {
            loadAuditLogs();
        });
    }
    if (auditLogSearch) {
        auditLogSearch.addEventListener("input", renderAuditLogs);
    }
    if (auditLogActionFilter) {
        auditLogActionFilter.addEventListener("change", renderAuditLogs);
    }

    // Audit Report Modal Listeners
    if (btnOpenAuditReport) {
        btnOpenAuditReport.addEventListener("click", () => {
            updateAuditReportSnapshot();
            auditReportModal.style.display = "flex";
        });
    }
    if (btnCloseAuditReportModal) {
        btnCloseAuditReportModal.addEventListener("click", () => {
            auditReportModal.style.display = "none";
        });
    }
    if (btnCloseAuditReportModalBottom) {
        btnCloseAuditReportModalBottom.addEventListener("click", () => {
            auditReportModal.style.display = "none";
        });
    }

    // Close Modals on Outside Click
    window.addEventListener("click", (e) => {
        if (e.target === aiModal) aiModal.style.display = "none";
        if (e.target === auditLogsModal) auditLogsModal.style.display = "none";
        if (e.target === auditReportModal) auditReportModal.style.display = "none";
    });
}

// Load status & servers
async function loadData() {
    try {
        const [statusResp, serversResp, apprResp, schedResp] = await Promise.all([
            fetch("/api/status"),
            fetch("/api/servers"),
            fetch("/api/wsus-approvals").catch(() => ({ json: () => ({ approvals: {} }) })),
            fetch("/api/scheduler-status").catch(() => ({ json: () => ({}) }))
        ]);

        const statusData = await statusResp.json();
        const serversData = await serversResp.json();
        const apprData = await apprResp.json();
        const schedData = await schedResp.json();

        currentApprovals = apprData.approvals || {};
        currentScheduler = schedData || {};

        updateMetrics(statusData);
        updateSchedulerDisplay(currentScheduler);
        allServers = serversData.servers || [];
        renderServersTable();

        if (currentSelectedServer) {
            const refreshed = allServers.find(s => s.agent_id === currentSelectedServer.agent_id);
            if (refreshed) selectServer(refreshed);
        }
    } catch (e) {
        console.error("Error loading data:", e);
        showToast("Không thể kết nối đến máy chủ API: " + e.message, "danger");
    }
}

function updateSchedulerDisplay(sched) {
    if (!schedulerText) return;
    if (sched.is_scanning) {
        schedulerText.innerHTML = `<span style="color:#fbbf24">⚡ Đang quét tự động...</span>`;
    } else if (sched.is_running) {
        schedulerText.textContent = `Quét nền: Mỗi ${sched.interval_minutes || 30}p (Kế tiếp: ${sched.remaining_minutes || 30}p)`;
    } else {
        schedulerText.textContent = `Quét nền: Chưa bật`;
    }
}

function updateMetrics(status) {
    const m = status.metrics || {};
    const compRate = m.overall_compliance_percent || 0;
    valComplianceRate.textContent = `${compRate}%`;
    barCompliance.style.width = `${compRate}%`;

    if (compRate >= 95) {
        valComplianceRate.className = "kpi-number text-success";
        valComplianceStatus.innerHTML = `<span class="badge badge-clean">ĐẠT CHUẨN SLA</span>`;
    } else {
        valComplianceRate.className = "kpi-number text-danger";
        valComplianceStatus.innerHTML = `<span class="badge badge-vulnerable">CẦN XỬ LÝ (Mục tiêu ≥ 95%)</span>`;
    }

    const critRate = m.critical_compliance_percent || 100;
    valCriticalCompliance.textContent = `${critRate}%`;
    barCriticalCompliance.style.width = `${critRate}%`;
    valCriticalCount.textContent = m.critical_confirmed || 0;

    valPendingRescanCount.textContent = m.remediated_pending_rescan || 0;
    valRebootPendingCount.textContent = m.reboot_pending_count || 0;
}

function renderServersTable() {
    const q = searchInput.value.toLowerCase().trim();
    const filter = filterStatus.value;

    const filtered = allServers.filter(s => {
        const matchesQuery = (
            s.agent_name.toLowerCase().includes(q) ||
            (s.os_name && s.os_name.toLowerCase().includes(q)) ||
            (s.os_build && s.os_build.includes(q))
        );

        if (!matchesQuery) return false;

        const summary = s.summary || {};
        const confirmedVulns = summary.confirmed_vulnerable || 0;
        const pendingRescan = summary.remediated_pending_rescan || 0;
        const isReboot = s.reboot_pending;

        if (filter === "clean") return confirmedVulns === 0;
        if (filter === "vulnerable") return confirmedVulns > 0;
        if (filter === "pending_rescan") return pendingRescan > 0;
        if (filter === "reboot_pending") return isReboot;
        return true;
    });

    serverCountTag.textContent = `${filtered.length} máy chủ`;

    if (filtered.length === 0) {
        serversTableBody.innerHTML = `<tr><td colspan="9" class="empty-state">Không có máy chủ nào phù hợp với bộ lọc</td></tr>`;
        return;
    }

    serversTableBody.innerHTML = filtered.map(s => {
        const sum = s.summary || {};
        const isVuln = (sum.confirmed_vulnerable || 0) > 0;
        const isPendingRescan = (sum.remediated_pending_rescan || 0) > 0;
        const isReboot = s.reboot_pending;

        let statusBadge = `<span class="badge badge-clean">✅ Sạch</span>`;
        if (isReboot) {
            if (sum.confirmed_vulnerable > 0) {
                statusBadge = `<span class="badge" style="background:var(--apple-orange-subtle);color:var(--apple-orange-text);border:1px solid var(--apple-orange-border);" title="Đã cài KB OS (Chờ Restart), còn ${sum.confirmed_vulnerable} lỗ hổng phần mềm ứng dụng">🔄 Chờ Restart OS • ${sum.confirmed_vulnerable} App</span>`;
            } else {
                statusBadge = `<span class="badge badge-reboot" title="Đã cài bản vá OS, cần khởi động lại máy chủ">🔄 Đã Cài KB • Chờ Restart</span>`;
            }
        } else if (isVuln) {
            const allApproved = (s.missing_kbs && s.missing_kbs.length > 0) && s.missing_kbs.every(kb => isKbApprovedOnWsus(kb, s.wsus_group));
            if (allApproved) {
                statusBadge = `<span class="badge" style="background:var(--apple-blue-subtle);color:var(--apple-blue);border:1px solid var(--apple-blue-border);" title="Bản vá đã được phê duyệt trên WSUS và đẩy về node, đáp ứng khắc phục lỗ hổng Wazuh">⚡ Đã Đẩy WSUS (${sum.confirmed_vulnerable})</span>`;
            } else {
                statusBadge = `<span class="badge badge-vulnerable">⚠️ ${sum.confirmed_vulnerable} Cần vá</span>`;
            }
        } else if (isPendingRescan) {
            statusBadge = `<span class="badge badge-pending-rescan">⏳ Chờ Wazuh Rescan</span>`;
        }

        const rebootBadge = isReboot
            ? `<span class="badge badge-reboot" style="cursor:help;" title="${escapeHtml(s.reboot_reasons || 'Cần khởi động lại máy chủ')}">⚠️ Cần Reboot</span>`
            : `<span style="color:var(--text-tertiary)">Không</span>`;

        const isActive = currentSelectedServer && currentSelectedServer.agent_id === s.agent_id;

        return `
        <tr class="${isActive ? 'active-row' : ''}" onclick="window.onServerRowClick('${s.agent_id}')">
            <td>
                <strong>${escapeHtml(s.agent_name)}</strong>
                <div style="font-size:11px;color:var(--text-tertiary)">ID: ${s.agent_id}</div>
            </td>
            <td>
                <div>${escapeHtml(s.os_name || 'Windows')}</div>
                <div style="font-size:11px;color:var(--text-tertiary)">Build: ${escapeHtml(s.os_build || 'N/A')}</div>
            </td>
            <td><span class="badge" style="background:var(--bg-surface-tertiary);color:var(--text-secondary);border:1px solid var(--divider);">${escapeHtml(s.wsus_group || '07-Production')}</span></td>
            <td><strong>${s.installed_hotfix_count || 0}</strong> KBs</td>
            <td><strong class="${sum.confirmed_vulnerable > 0 ? 'text-danger' : ''}">${sum.confirmed_vulnerable || 0}</strong></td>
            <td><strong class="${sum.remediated_pending_rescan > 0 ? 'text-warning' : ''}">${sum.remediated_pending_rescan || 0}</strong></td>
            <td>${rebootBadge}</td>
            <td>${statusBadge}</td>
            <td>
                <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); window.onServerRowClick('${s.agent_id}')">Chi tiết</button>
            </td>
        </tr>
        `;
    }).join("");
}

// Global click handler for row
window.onServerRowClick = function(agentId) {
    const srv = allServers.find(s => s.agent_id === agentId);
    if (srv) selectServer(srv);
};

function selectServer(server) {
    currentSelectedServer = server;
    renderServersTable();

    inspectorEmpty.style.display = "none";
    inspectorContent.style.display = "flex";

    insServerName.textContent = server.agent_name;
    insServerSub.textContent = `${server.os_name || 'Windows Server'} • Build: ${server.os_build || 'N/A'} • Group: ${server.wsus_group || '07-Production'}`;

    const sum = server.summary || {};
    insHotfixCount.textContent = server.installed_hotfix_count || 0;
    insVulnCount.textContent = sum.confirmed_vulnerable || 0;
    insRebootState.innerHTML = server.reboot_pending 
        ? `<span class="badge badge-reboot" style="font-size:11px;">⚠️ CẦN REBOOT</span>` 
        : `<span class="badge badge-clean" style="font-size:11px;">Không</span>`;

    const rebootNotice = document.getElementById("insRebootNotice");
    if (rebootNotice) {
        if (server.reboot_pending) {
            rebootNotice.style.display = "block";
            rebootNotice.innerHTML = `⚠️ <strong>Cần khởi động lại máy chủ (Reboot Required):</strong><br><span style="color:#fdba74;font-size:11px;">${escapeHtml(server.reboot_reasons || 'Máy chủ đã cài đặt bản vá mới (Cumulative Update) nhưng Kernel Build chưa kích hoạt. Vui lòng Restart máy chủ để hoàn tất áp dụng bản vá.')}</span>`;
        } else {
            rebootNotice.style.display = "none";
        }
    }

    // Populate Hotfix Pills
    const hotfixes = server.installed_hotfixes || [];
    const pillsContainer = document.getElementById("insHotfixPills");
    const lcuBadge = document.getElementById("insLcuBadge");
    if (pillsContainer) {
        if (hotfixes.length > 0) {
            pillsContainer.innerHTML = hotfixes.map(kb => 
                `<span class="badge" style="background:var(--apple-blue-subtle);color:var(--apple-blue);border:1px solid var(--apple-blue-border);font-size:11px;padding:3px 8px;margin:2px;">${escapeHtml(kb)}</span>`
            ).join("");
        } else {
            pillsContainer.innerHTML = `<span style="font-size:12px;color:var(--text-tertiary);">Chưa có dữ liệu hotfix từ Syscollector</span>`;
        }
    }
    if (lcuBadge) {
        if (server.os_build && server.os_build.includes("17763.9245")) {
            lcuBadge.innerHTML = `<span style="color:var(--apple-green-text);font-size:11px;font-weight:600;">🛡️ Đã có LCU mới nhất (KB5122876 / Build 17763.9245)</span>`;
        } else if (server.os_build) {
            lcuBadge.innerHTML = `<span style="color:var(--text-tertiary);font-size:11px;">Build: ${escapeHtml(server.os_build)}</span>`;
        } else {
            lcuBadge.textContent = "";
        }
    }

    renderVulnCards(server.vulnerabilities || [], server);
}

function isKbApprovedOnWsus(kbNumber, groupName) {
    if (!kbNumber) return false;
    const clean = String(kbNumber).trim().toUpperCase();
    const g = groupName || 'BPVN-Server';
    if (currentApprovals[`${clean}_${g}`]?.status === 'APPROVED') return true;
    if (currentApprovals[`${clean}_BPVN-Server`]?.status === 'APPROVED') return true;
    if (currentApprovals[clean]?.status === 'APPROVED') return true;
    return Object.values(currentApprovals).some(a => 
        a && a.status === 'APPROVED' && String(a.kb).trim().toUpperCase() === clean
    );
}

function renderVulnCards(vulns, server) {
    if (vulns.length === 0) {
        vulnCardsContainer.innerHTML = `
            <div style="text-align:center;padding:36px;color:var(--apple-green-text);background:var(--apple-green-subtle);border-radius:14px;border:1px dashed var(--apple-green-border);">
                <div style="font-size:32px;margin-bottom:8px;">🎉</div>
                <strong style="font-size:14px;">Máy chủ hoàn toàn sạch lỗ hổng!</strong>
                <p style="font-size:12px;color:var(--text-secondary);margin-top:6px;">Tất cả bản vá đã được áp dụng và xác minh qua Wazuh Syscollector.</p>
            </div>
        `;
        return;
    }

    vulnCardsContainer.innerHTML = vulns.map((v, idx) => {
        const severity = (v.severity || "Medium").toUpperCase();
        let sevClass = "badge-clean";
        if (severity === "CRITICAL") sevClass = "badge-vulnerable";
        else if (severity === "HIGH") sevClass = "badge-reboot";
        else if (severity === "MEDIUM") sevClass = "badge-pending-rescan";

        const hasKb = Boolean(v.expected_kb);
        const status = v.status;

        let statusText = "";
        let actionButtonHtml = "";

        const groupName = server.wsus_group || 'BPVN-Server';
        const isApprovedOnWsus = hasKb && isKbApprovedOnWsus(v.expected_kb, groupName);

        let approvalBadge = "";
        if (isApprovedOnWsus) {
            approvalBadge = `<span class="badge" style="background:var(--apple-blue-subtle);color:var(--apple-blue);border:1px solid var(--apple-blue-border);font-weight:600;" title="Đã được phê duyệt trên WSUS và đẩy về node">⚡ Đã Phê duyệt từ WSUS</span>`;
        }

        let reasonText = v.reason || '';

        const isServerPendingRestart = (server.reboot_pending || v.reboot_required) && hasKb;

        if (status === "SOLVED") {
            statusText = `<span class="badge badge-clean">Đã khắc phục (Solved)</span>`;
        } else if (isServerPendingRestart) {
            statusText = `<span class="badge badge-reboot" style="background:#fff6e8;color:#b35900;border:1px solid rgba(255,149,0,0.4);font-weight:600;">🔄 Đã Cài Đặt Bản Vá • Chờ Khởi Động Lại (Pending Restart)</span>`;
            reasonText = `Bản vá ${v.expected_kb || 'WSUS'} ĐÃ ĐƯỢC CÀI ĐẶT trên máy chủ. Máy chủ đang ghi nhận cờ CHỜ KHỞI ĐỘNG LẠI (Reboot Required) để hoàn tất kích hoạt bản vá vào Windows Kernel. Sau khi restart máy, Wazuh sẽ tự động cập nhật an toàn.`;
            actionButtonHtml = `
                <button class="btn btn-sm btn-outline" style="color:#b35900;border-color:rgba(255,149,0,0.4);background:#ffffff;" onclick="window.triggerRebootCheck('${server.agent_id}')" title="Sau khi đã Restart máy chủ, bấm vào đây để kiểm tra và xóa cờ Reboot">
                    🔄 Soát / Xóa Cờ Reboot
                </button>
                <button class="btn btn-sm btn-outline" onclick="window.triggerAgentRescan('${server.agent_id}')" title="Gửi lệnh quét lại ngay">
                    🔄 Quét Lại Syscollector
                </button>
            `;
        } else if (status === "REMEDIATED_PENDING_WAZUH_RESCAN") {
            const rebootBadge = v.reboot_required 
                ? `<span class="badge badge-reboot" style="font-size:10px;margin-left:4px;">🔄 Chờ Restart máy</span>` 
                : "";
            statusText = `<span class="badge badge-pending-rescan">Rule #4: Đã cài KB • Chờ Wazuh Rescan</span> ${rebootBadge}`;
            actionButtonHtml = `
                <button class="btn btn-sm btn-outline" onclick="window.triggerAgentRescan('${server.agent_id}')">
                    🔄 Quét Lại Syscollector
                </button>
            `;
        } else {
            // CONFIRMED_VULNERABLE
            if (!hasKb) {
                statusText = `<span class="badge" style="background:var(--apple-red-subtle);color:var(--apple-red-text);border:1px solid var(--apple-red-border);">⚠️ Lỗ hổng Ứng dụng (Non-KB)</span>`;
                reasonText = v.reason || "Lỗ hổng thuộc phần mềm ứng dụng bên thứ 3 (Non-KB), không có bản vá OS qua WSUS. Cần nâng cấp trực tiếp phần mềm hoặc đăng ký Ngoại lệ (Exception) theo hướng dẫn của AI Gemini.";
            } else if (isApprovedOnWsus) {
                statusText = `<span class="badge" style="background:var(--apple-blue-subtle);color:var(--apple-blue);border:1px solid var(--apple-blue-border);">⚡ Đã Phê duyệt từ WSUS • Đang chờ cài đặt</span>`;
                reasonText = v.reason || `Bản vá ${v.expected_kb} ĐÃ ĐƯỢC PHÊ DUYỆT từ WSUS và đẩy về máy chủ để đáp ứng vá lỗ hổng [${v.cve}] của Wazuh (hoặc theo đợt Patch định kỳ WSUS). Gói đã sẵn sàng cài đặt trên máy.`;
            } else {
                statusText = `<span class="badge badge-vulnerable">Chưa khắc phục</span>`;
            }

            if (hasKb) {
                if (isApprovedOnWsus) {
                    actionButtonHtml = `
                        <button class="btn btn-sm btn-primary" onclick="window.installUpdate('${v.expected_kb}', '${server.agent_name}')" title="Kích hoạt cài đặt ngay bản vá đã đẩy từ WSUS về máy">
                            ⬇️ Cài đặt ngay (Trigger Install)
                        </button>
                        <button class="btn btn-sm btn-outline" style="color:var(--apple-red-text);border-color:var(--apple-red-border);background:#ffffff;" onclick="window.unapproveWsusUpdate('${v.expected_kb}', '${groupName}')" title="Hủy phê duyệt để tránh đẩy trùng lặp">
                            Hủy Duyệt (Unapprove)
                        </button>
                    `;
                } else {
                    actionButtonHtml = `
                        <button class="btn btn-sm btn-primary" onclick="window.approveWsusUpdate('${v.expected_kb}', '${groupName}')">
                            ⚡ Phê duyệt WSUS
                        </button>
                    `;
                }
            } else {
                actionButtonHtml = `
                    <button class="btn btn-sm btn-ai" onclick="window.openGeminiAdvice('${v.cve}', '${server.agent_name}', '${server.os_name}', ${idx})">
                        🤖 Hỏi AI Gemini Hướng dẫn Khắc phục
                    </button>
                `;
            }
        }

        const kbHtml = hasKb
            ? `<span class="kb-badge">Bản vá: ${v.expected_kb}</span>`
            : `<span class="kb-missing-badge">⚠️ Chưa có KB trực tiếp</span>`;

        return `
        <div class="vuln-card">
            <div class="vuln-card-top">
                <span class="vuln-cve-id">${escapeHtml(v.cve)}</span>
                <span class="badge ${sevClass}">${severity} (CVSS: ${v.cvss || 0})</span>
            </div>
            <div class="vuln-title">${escapeHtml(v.title || 'Vulnerability')}</div>
            <div class="vuln-meta-row">
                ${kbHtml}
                ${approvalBadge}
                ${statusText}
            </div>
            <div style="font-size:11px;color:#94a3b8;margin-top:2px;">
                ${escapeHtml(reasonText)}
            </div>
            <div class="vuln-action-row">
                ${actionButtonHtml}
            </div>
        </div>
        `;
    }).join("");
}

// Global Actions for card buttons
window.triggerAgentRescan = async function(agentId) {
    showToast("Đang kết nối Wazuh & rà soát Syscollector live...");
    try {
        const resp = await fetch("/api/trigger-rescan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ agent_id: agentId })
        });
        const res = await resp.json();
        if (res.success) {
            showToast(res.message || "Đã quét lại thành công!");
            await loadData();
        } else {
            showToast(res.message || "Quét lại thất bại", "warning");
        }
    } catch (e) {
        showToast("Lỗi khi rescan: " + e.message, "danger");
    }
};

window.approveWsusUpdate = async function(kbNumber, targetGroup) {
    let selectedGroup = targetGroup || "BPVN-Server";
    try {
        const gResp = await fetch("/api/groups");
        const gData = await gResp.json();
        const groups = (gData.groups || []).map(g => g.name || g.id);
        if (groups.length > 0) {
            const groupListHint = groups.slice(0, 6).join(", ");
            const userChoice = prompt(
                `Nhập hoặc xác nhận nhóm WSUS bạn muốn phê duyệt [${kbNumber}]:\n(Các nhóm hiện có trong policy: ${groupListHint})`,
                selectedGroup
            );
            if (!userChoice) return;
            selectedGroup = userChoice.trim();
        } else {
            const userChoice = prompt(`Nhập tên nhóm WSUS cần phê duyệt [${kbNumber}]:`, selectedGroup);
            if (!userChoice) return;
            selectedGroup = userChoice.trim();
        }
    } catch (e) {
        if (!confirm(`Bạn có chắc chắn muốn phê duyệt triển khai bản vá ${kbNumber} cho nhóm: [${selectedGroup}]?`)) return;
    }

    showToast(`Đang gửi yêu cầu phê duyệt ${kbNumber} tới nhóm WSUS [${selectedGroup}]...`);
    try {
        const resp = await fetch("/api/approve-kb", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ kb: kbNumber, group: selectedGroup })
        });
        const data = await resp.json();
        if (data.already_approved) {
            showToast(data.message, "warning");
        } else {
            showToast(data.message, "success");
        }
        loadData();
    } catch (e) {
        showToast("Lỗi phê duyệt: " + e.message, "danger");
    }
};

window.unapproveWsusUpdate = async function(kbNumber, targetGroup) {
    if (!confirm(`Bạn có chắc chắn muốn HỦY PHÊ DUYỆT (Unapprove) bản vá ${kbNumber} cho nhóm: [${targetGroup}]?`)) {
        return;
    }
    showToast(`Đang gửi yêu cầu hủy phê duyệt ${kbNumber}...`);
    try {
        const resp = await fetch("/api/unapprove-kb", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ kb: kbNumber, group: targetGroup })
        });
        const data = await resp.json();
        showToast(data.message, "success");
        loadData();
    } catch (e) {
        showToast("Lỗi khi hủy phê duyệt: " + e.message, "danger");
    }
};

window.installUpdate = async function(kbNumber, serverName) {
    showToast(`Đang chuẩn bị lệnh kích hoạt cài đặt ${kbNumber} trên máy chủ ${serverName}...`);
    try {
        const resp = await fetch("/api/install-kb", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ kb: kbNumber, server: serverName })
        });
        const data = await resp.json();
        const copyCmd = confirm(
            `KÍCH HOẠT CÀI ĐẶT BẢN VÁ TỪ WSUS:\n\n` +
            `Máy chủ: ${serverName}\n` +
            `Mã KB: ${kbNumber}\n\n` +
            `Lệnh PowerShell thực thi tại node:\n${data.command}\n\n` +
            `Bấm OK để tự động sao chép lệnh PowerShell này vào Clipboard.`
        );
        if (copyCmd) {
            navigator.clipboard.writeText(data.command);
            showToast("Đã sao chép lệnh PowerShell vào Clipboard!", "success");
        }
    } catch (e) {
        showToast("Lỗi kích hoạt cài đặt: " + e.message, "danger");
    }
};

window.openGeminiAdvice = async function(cveId, serverName, osName, vulnIdx) {
    if (currentSelectedServer) {
        currentSelectedServer.active_ai_cve = cveId;
    }

    aiModalTitle.textContent = `Hướng dẫn Khắc phục Lỗ hổng: ${cveId}`;
    aiModal.style.display = "flex";
    aiModalLoading.style.display = "block";
    aiModalText.style.display = "none";

    try {
        const vuln = currentSelectedServer.vulnerabilities[vulnIdx] || {};
        const resp = await fetch("/api/gemini-advice", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                cve: cveId,
                server: serverName,
                os: osName,
                title: vuln.title,
                severity: vuln.severity,
                cvss: vuln.cvss
            })
        });

        const data = await resp.json();
        currentAiGuidance = data.guidance_markdown;
        aiModalSource.textContent = data.source || "Google Gemini";

        aiModalLoading.style.display = "none";
        aiModalText.style.display = "block";
        aiModalText.innerHTML = renderSimpleMarkdown(data.guidance_markdown);
    } catch (e) {
        aiModalLoading.style.display = "none";
        aiModalText.style.display = "block";
        aiModalText.innerHTML = `<p class="text-danger">Không thể tải hướng dẫn AI: ${e.message}</p>`;
    }
};

// Utilities
function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function renderSimpleMarkdown(md) {
    if (!md) return "";
    let html = escapeHtml(md);

    // Code blocks
    html = html.replace(/```(?:powershell|bash|cmd)?([\s\S]*?)```/g, function(match, code) {
        return `<pre><code>${code.trim()}</code></pre>`;
    });

    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Headers
    html = html.replace(/^### (.*$)/gim, '<h4>$1</h4>');
    html = html.replace(/^#### (.*$)/gim, '<h5>$1</h5>');

    // Bold
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

    // Blockquotes
    html = html.replace(/^> (.*$)/gim, '<blockquote>$1</blockquote>');

    // List items
    html = html.replace(/^\- (.*$)/gim, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');

    // Newlines
    html = html.replace(/\n\n/g, '<br><br>');

    return html;
}

function showToast(msg, type = "info") {
    const toast = document.createElement("div");
    toast.className = "toast";
    let icon = "ℹ️";
    if (type === "success") icon = "✅";
    if (type === "danger") icon = "❌";
    toast.innerHTML = `<span>${icon}</span> <span>${escapeHtml(msg)}</span>`;
    toastContainer.appendChild(toast);
    setTimeout(() => {
        toast.remove();
    }, 4000);
}

// Audit Logs & Compliance Reporting Logic
async function loadAuditLogs() {
    if (!auditLogsTbody) return;
    auditLogsTbody.innerHTML = `<tr><td colspan="6" class="empty-state">Đang tải dữ liệu nhật ký kiểm toán...</td></tr>`;
    try {
        const resp = await fetch("/api/audit-logs?limit=300");
        const data = await resp.json();
        currentAuditLogs = data.logs || [];
        renderAuditLogs();
    } catch (e) {
        auditLogsTbody.innerHTML = `<tr><td colspan="6" class="empty-state text-danger">Lỗi khi tải nhật ký: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function renderAuditLogs() {
    if (!auditLogsTbody) return;
    const q = (auditLogSearch ? auditLogSearch.value.trim().toLowerCase() : "");
    const actionFilter = (auditLogActionFilter ? auditLogActionFilter.value : "ALL");

    let filtered = currentAuditLogs.filter(item => {
        if (actionFilter !== "ALL" && item.action !== actionFilter) {
            return false;
        }
        if (!q) return true;
        const targetStr = (item.target || "").toLowerCase();
        const detailsStr = (item.details || "").toLowerCase();
        const actionStr = (item.action || "").toLowerCase();
        const sourceStr = (item.source || "").toLowerCase();
        return targetStr.includes(q) || detailsStr.includes(q) || actionStr.includes(q) || sourceStr.includes(q);
    });

    if (auditLogCount) {
        auditLogCount.textContent = `Hiển thị ${filtered.length} / ${currentAuditLogs.length} bản ghi nhật ký kiểm toán`;
    }

    if (filtered.length === 0) {
        auditLogsTbody.innerHTML = `<tr><td colspan="6" class="empty-state">Không tìm thấy bản ghi nhật ký nào phù hợp.</td></tr>`;
        return;
    }

    const actionColors = {
        "SCAN_CYCLE": "#38bdf8",
        "AGENT_RESCAN": "#a855f7",
        "WSUS_APPROVE": "#10b981",
        "WSUS_UNAPPROVE": "#f59e0b",
        "REBOOT_FLAG_CHANGE": "#fb923c",
        "RULE4_VERIFICATION": "#34d399",
        "EXPORT_REPORT": "#818cf8"
    };

    auditLogsTbody.innerHTML = filtered.map(log => {
        const color = actionColors[log.action] || "#64748b";
        const statusBadge = (log.status === "SUCCESS")
            ? `<span class="badge" style="background:var(--apple-green-subtle);color:var(--apple-green-text);font-size:11px;">SUCCESS</span>`
            : `<span class="badge" style="background:var(--apple-red-subtle);color:var(--apple-red-text);font-size:11px;">${escapeHtml(log.status)}</span>`;

        const timeStr = log.timestamp ? log.timestamp.replace("T", " ").substring(0, 19) : "";

        return `
            <tr>
                <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-tertiary);white-space:nowrap;">${escapeHtml(timeStr)}</td>
                <td>
                    <span class="badge" style="background:var(--bg-surface-tertiary);color:${color};font-weight:600;font-size:11px;border:1px solid var(--divider);">
                        ${escapeHtml(log.action)}
                    </span>
                </td>
                <td style="font-weight:600;font-size:12px;color:var(--text-primary);">${escapeHtml(log.target || "-")}</td>
                <td style="font-size:12px;color:var(--text-secondary);line-height:1.45;">${escapeHtml(log.details || "-")}</td>
                <td style="font-size:11px;color:var(--text-tertiary);">${escapeHtml(log.source || "System")}</td>
                <td style="text-align:center;">${statusBadge}</td>
            </tr>
        `;
    }).join("");
}

function updateAuditReportSnapshot() {
    if (!allServers || allServers.length === 0) return;
    if (auditModalTotalServers) auditModalTotalServers.textContent = allServers.length;
    if (auditModalCompliance && valComplianceRate) {
        auditModalCompliance.textContent = valComplianceRate.textContent;
    }
    const totalRemediated = allServers.reduce((acc, s) => acc + (s.remediated_by_rule4 || 0), 0);
    if (auditModalRemediated) auditModalRemediated.textContent = totalRemediated;
    const totalReboot = allServers.filter(s => s.reboot_pending).length;
    if (auditModalReboot) auditModalReboot.textContent = totalReboot;
}

// Expose globally
window.openAuditLogsModal = () => {
    if (auditLogsModal) auditLogsModal.style.display = "flex";
    loadAuditLogs();
};
window.closeAuditLogsModal = () => {
    if (auditLogsModal) auditLogsModal.style.display = "none";
};
window.openAuditReportModal = () => {
    updateAuditReportSnapshot();
    if (auditReportModal) auditReportModal.style.display = "flex";
};
window.closeAuditReportModal = () => {
    if (auditReportModal) auditReportModal.style.display = "none";
};
window.loadAuditLogs = loadAuditLogs;
window.updateAuditReportSnapshot = updateAuditReportSnapshot;
window.triggerRebootCheck = (agentId) => {
    const srv = allServers.find(s => s.agent_id === agentId) || currentSelectedServer;
    if (srv) {
        currentSelectedServer = srv;
        btnCheckReboot.click();
    }
};

