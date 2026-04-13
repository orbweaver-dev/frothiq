/**
 * Hybrid Orchestration Intelligence Layer — Frappe UI  (Phase 3)
 *
 * Renders the "Orchestration Intelligence" tab in the FrothIQ Admin Panel.
 *
 * Sections
 * --------
 *   1. System Balance Indicator — live cross-subsystem health card
 *   2. Decision Stream         — scrollable recent evaluation log
 *   3. Rule Activation Heatmap — bar chart of rule fire counts
 *   4. Per-Tenant Inspector    — on-demand evaluation for a specific tenant
 *
 * All data is fetched from orbweaver_frothiq.frothiq_portal.api.orchestration_api.
 * Refresh cadence: System Balance 10 s, Decision Stream 15 s, Heatmap 60 s.
 */

/* global frappe */

frappe.provide("frothiq.orchestration");

frothiq.orchestration.OrchestrationUI = class OrchestrationUI {
    /**
     * @param {string} wrapper_id - CSS selector for the container element
     */
    constructor(wrapper_id) {
        this.wrapper = document.querySelector(wrapper_id);
        if (!this.wrapper) {
            console.warn("[OrchestrationUI] wrapper not found:", wrapper_id);
            return;
        }
        this._timers = [];
        this._render();
        this._startAutoRefresh();
    }

    // -----------------------------------------------------------------------
    // Render skeleton
    // -----------------------------------------------------------------------

    _render() {
        this.wrapper.innerHTML = `
<style>
.orch-grid         { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }
.orch-section      { background:#fff; border:1px solid #e2e8f0; border-radius:8px; padding:16px; }
.orch-section h4   { margin:0 0 12px; font-size:13px; font-weight:600; color:#1e293b; text-transform:uppercase; letter-spacing:.05em; }
.orch-full         { grid-column:1 / -1; }
.orch-badge        { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; margin:2px; }
.orch-badge-green  { background:#dcfce7; color:#166534; }
.orch-badge-red    { background:#fee2e2; color:#991b1b; }
.orch-badge-orange { background:#ffedd5; color:#92400e; }
.orch-badge-blue   { background:#dbeafe; color:#1e40af; }
.orch-badge-gray   { background:#f1f5f9; color:#475569; }
.orch-stat         { display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid #f1f5f9; font-size:12px; }
.orch-stat:last-child { border-bottom:none; }
.orch-stat-label   { color:#64748b; }
.orch-stat-value   { font-weight:600; color:#1e293b; }
.orch-bar-wrap     { margin:4px 0; }
.orch-bar-label    { font-size:11px; color:#475569; margin-bottom:2px; display:flex; justify-content:space-between; }
.orch-bar-track    { background:#f1f5f9; border-radius:4px; height:10px; overflow:hidden; }
.orch-bar-fill     { height:100%; border-radius:4px; background:#4f8ef7; transition:width .4s ease; }
.orch-stream-row   { font-size:11px; padding:6px 0; border-bottom:1px solid #f8fafc; line-height:1.4; }
.orch-stream-row:last-child { border-bottom:none; }
.orch-stream-time  { color:#94a3b8; margin-right:6px; }
.orch-stream-tenant{ font-weight:600; color:#0f1629; margin-right:6px; }
.orch-inspector    { display:flex; gap:8px; align-items:flex-end; margin-bottom:12px; flex-wrap:wrap; }
.orch-inspector input { flex:1; min-width:160px; padding:6px 10px; border:1px solid #e2e8f0; border-radius:6px; font-size:12px; }
.orch-inspector button{ padding:6px 14px; background:#4f8ef7; color:#fff; border:none; border-radius:6px; cursor:pointer; font-size:12px; }
.orch-result       { background:#f8fafc; border-radius:6px; padding:10px; font-size:12px; margin-top:8px; white-space:pre-wrap; font-family:monospace; max-height:220px; overflow-y:auto; }
.orch-refresh-ts   { font-size:10px; color:#94a3b8; text-align:right; margin-top:4px; }
</style>

<div class="orch-grid">

  <!-- 1. System Balance Indicator -->
  <div class="orch-section">
    <h4>System Balance Indicator</h4>
    <div id="orch-balance-content"><em style="color:#94a3b8;font-size:12px;">Loading…</em></div>
    <div class="orch-refresh-ts" id="orch-balance-ts"></div>
  </div>

  <!-- Audit Stats -->
  <div class="orch-section">
    <h4>Audit Stats — Last 24 h</h4>
    <div id="orch-stats-content"><em style="color:#94a3b8;font-size:12px;">Loading…</em></div>
    <div class="orch-refresh-ts" id="orch-stats-ts"></div>
  </div>

  <!-- 3. Rule Activation Heatmap -->
  <div class="orch-section">
    <h4>Rule Activation Heatmap — Last 24 h</h4>
    <div id="orch-heatmap-content"><em style="color:#94a3b8;font-size:12px;">Loading…</em></div>
    <div class="orch-refresh-ts" id="orch-heatmap-ts"></div>
  </div>

  <!-- Suppression Flags -->
  <div class="orch-section">
    <h4>Suppression Flags — Last 24 h</h4>
    <div id="orch-flags-content"><em style="color:#94a3b8;font-size:12px;">Loading…</em></div>
    <div class="orch-refresh-ts" id="orch-flags-ts"></div>
  </div>

  <!-- 2. Decision Stream -->
  <div class="orch-section orch-full">
    <h4>Decision Stream <span style="font-weight:400;font-size:11px;color:#94a3b8;">(latest 50)</span></h4>
    <div id="orch-stream-content"><em style="color:#94a3b8;font-size:12px;">Loading…</em></div>
    <div class="orch-refresh-ts" id="orch-stream-ts"></div>
  </div>

  <!-- 4. Per-Tenant Inspector -->
  <div class="orch-section orch-full">
    <h4>Per-Tenant Inspector</h4>
    <div class="orch-inspector">
      <input type="text" id="orch-tenant-input" placeholder="Tenant ID or email…" />
      <button id="orch-inspect-btn">Inspect</button>
    </div>
    <div id="orch-inspector-result" style="display:none;"></div>
  </div>

</div>`;

        // Wire up inspector button
        this.wrapper.querySelector("#orch-inspect-btn").addEventListener("click", () => {
            const tid = this.wrapper.querySelector("#orch-tenant-input").value.trim();
            if (tid) this._loadDecisionStream(tid);
        });
    }

    // -----------------------------------------------------------------------
    // Data loaders
    // -----------------------------------------------------------------------

    _call(method, args, cb) {
        frappe.call({
            method: `orbweaver_frothiq.frothiq_portal.api.orchestration_api.${method}`,
            args: args || {},
            callback: r => { if (r && r.message !== undefined) cb(r.message); },
        });
    }

    _loadBalance() {
        this._call("get_system_balance_indicator", {}, data => {
            const el = this.wrapper.querySelector("#orch-balance-content");
            if (!el) return;
            const defBadge = data.allow_defense_actions
                ? '<span class="orch-badge orch-badge-green">Defense ✓</span>'
                : '<span class="orch-badge orch-badge-red">Defense ✗</span>';
            const simBadge = data.simulation_healthy
                ? '<span class="orch-badge orch-badge-green">Sim ✓</span>'
                : '<span class="orch-badge orch-badge-orange">Sim degraded</span>';
            const monBadge = data.allow_monetization
                ? `<span class="orch-badge orch-badge-blue">Mon: ${data.monetization_mode}</span>`
                : '<span class="orch-badge orch-badge-red">Mon blocked</span>';
            const scBadge = data.short_circuited
                ? '<span class="orch-badge orch-badge-orange">Short-circuit</span>'
                : '';

            const stats = [
                ["Defense State", data.defense_state],
                ["Threat Level",  data.threat_level.toFixed(1)],
                ["DAS / DEI / PPS", `${data.simulation_scores.DAS} / ${data.simulation_scores.DEI} / ${data.simulation_scores.PPS}`],
                ["Active Campaigns", data.active_campaigns],
                ["Active Policies",  data.active_policies],
            ].map(([l, v]) => `<div class="orch-stat"><span class="orch-stat-label">${l}</span><span class="orch-stat-value">${v}</span></div>`).join("");

            el.innerHTML = `<div style="margin-bottom:8px;">${defBadge}${simBadge}${monBadge}${scBadge}</div>${stats}`;
            this.wrapper.querySelector("#orch-balance-ts").textContent =
                "Refreshed " + new Date().toLocaleTimeString();
        });
    }

    _loadStats() {
        this._call("get_audit_stats", { window_hours: 24 }, data => {
            const el = this.wrapper.querySelector("#orch-stats-content");
            if (!el) return;
            const pct = v => (v * 100).toFixed(1) + "%";
            const stats = [
                ["Total Evaluations",       data.total_evaluations],
                ["Monetization Block Rate", pct(data.monetization_block_rate)],
                ["Defense Escalation Rate", pct(data.defense_escalation_rate)],
                ["Short-Circuit Rate",      pct(data.short_circuit_rate)],
            ].map(([l, v]) => `<div class="orch-stat"><span class="orch-stat-label">${l}</span><span class="orch-stat-value">${v}</span></div>`).join("");
            el.innerHTML = stats;
            this.wrapper.querySelector("#orch-stats-ts").textContent =
                "Refreshed " + new Date().toLocaleTimeString();
        });
    }

    _loadHeatmap() {
        this._call("get_rule_activation_heatmap", { window_hours: 24 }, data => {
            const el = this.wrapper.querySelector("#orch-heatmap-content");
            if (!el) return;
            const entries = Object.entries(data);
            if (!entries.length) {
                el.innerHTML = '<em style="color:#94a3b8;font-size:12px;">No rule activations in the last 24 h.</em>';
            } else {
                const max = entries[0][1] || 1;
                el.innerHTML = entries.map(([rule, count]) => {
                    const pct = Math.round((count / max) * 100);
                    return `<div class="orch-bar-wrap">
                        <div class="orch-bar-label"><span>${rule.replace(/_/g," ")}</span><span>${count}</span></div>
                        <div class="orch-bar-track"><div class="orch-bar-fill" style="width:${pct}%"></div></div>
                    </div>`;
                }).join("");
            }
            this.wrapper.querySelector("#orch-heatmap-ts").textContent =
                "Refreshed " + new Date().toLocaleTimeString();
        });
    }

    _loadFlags() {
        this._call("get_suppression_flag_summary", { window_hours: 24 }, data => {
            const el = this.wrapper.querySelector("#orch-flags-content");
            if (!el) return;
            const entries = Object.entries(data);
            if (!entries.length) {
                el.innerHTML = '<em style="color:#94a3b8;font-size:12px;">No suppression flags in the last 24 h.</em>';
            } else {
                el.innerHTML = entries.map(([flag, count]) =>
                    `<div class="orch-stat">
                        <span class="orch-stat-label" style="font-family:monospace;">${flag}</span>
                        <span class="orch-stat-value">${count}</span>
                    </div>`
                ).join("");
            }
            this.wrapper.querySelector("#orch-flags-ts").textContent =
                "Refreshed " + new Date().toLocaleTimeString();
        });
    }

    _loadStream(tenant_id) {
        const args = tenant_id ? { limit: 50, tenant_id } : { limit: 50 };
        this._call("get_decision_stream", args, data => {
            const el = this.wrapper.querySelector("#orch-stream-content");
            if (!el) return;
            if (!data.length) {
                el.innerHTML = '<em style="color:#94a3b8;font-size:12px;">No decisions recorded yet.</em>';
            } else {
                el.innerHTML = data.map(r => {
                    const ts = new Date(r.timestamp * 1000).toLocaleTimeString();
                    const scTag = r.short_circuited ? ' <span class="orch-badge orch-badge-orange">SC</span>' : "";
                    const monTag = r.allow_monetization
                        ? `<span class="orch-badge orch-badge-blue">${r.monetization_mode}</span>`
                        : '<span class="orch-badge orch-badge-red">blocked</span>';
                    const rules = (r.triggered_rules || []).map(
                        n => `<span class="orch-badge orch-badge-gray">${n.replace(/_/g," ")}</span>`
                    ).join(" ");
                    return `<div class="orch-stream-row">
                        <span class="orch-stream-time">${ts}</span>
                        <span class="orch-stream-tenant">${r.tenant_id}</span>
                        ${monTag}${scTag}
                        ${rules}
                    </div>`;
                }).join("");
            }
            this.wrapper.querySelector("#orch-stream-ts").textContent =
                "Refreshed " + new Date().toLocaleTimeString();
        });
    }

    _loadDecisionStream(tenant_id) {
        this._call("get_decision_stream", { limit: 1, tenant_id }, data => {
            const el = this.wrapper.querySelector("#orch-inspector-result");
            if (!el) return;
            el.style.display = "block";
            if (!data.length) {
                el.innerHTML = '<div class="orch-result">No decisions found for this tenant.</div>';
            } else {
                el.innerHTML = `<div class="orch-result">${JSON.stringify(data[0], null, 2)}</div>`;
            }
        });
    }

    // -----------------------------------------------------------------------
    // Auto-refresh
    // -----------------------------------------------------------------------

    _startAutoRefresh() {
        // Initial load
        this._loadBalance();
        this._loadStats();
        this._loadHeatmap();
        this._loadFlags();
        this._loadStream();

        this._timers.push(setInterval(() => { this._loadBalance(); this._loadStats(); }, 10_000));
        this._timers.push(setInterval(() => this._loadStream(), 15_000));
        this._timers.push(setInterval(() => { this._loadHeatmap(); this._loadFlags(); }, 60_000));
    }

    destroy() {
        this._timers.forEach(t => clearInterval(t));
        this._timers = [];
    }
};


// ---------------------------------------------------------------------------
// Auto-init when the DOM contains #frothiq-orchestration-panel
// ---------------------------------------------------------------------------

frappe.ready(function () {
    if (document.querySelector("#frothiq-orchestration-panel")) {
        window._frothiqOrchestrationUI = new frothiq.orchestration.OrchestrationUI(
            "#frothiq-orchestration-panel"
        );
    }
});
