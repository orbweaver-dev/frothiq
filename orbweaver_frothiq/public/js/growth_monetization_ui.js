/**
 * FrothIQ — Growth & Monetization Dashboard UI  (Phase 6)
 *
 * Renders the "Growth & Monetization" tab in the FrothIQ Control Center.
 * Admin + Analyst access only. Tenant-agnostic aggregate view.
 *
 * Sections
 * --------
 *  1. Revenue Pressure Heatmap    — tenants ranked by revenue_score
 *  2. Upgrade Funnel View         — observed → nudged → engaged → converted
 *  3. Value Event Stream          — live monetization trigger feed
 *  4. Paywall Activity Tracker    — impressions, active banners, by event type
 *  5. Plan Recommendation Panel   — per-tenant plan gaps and upgrade paths
 *
 * Privacy: this UI shows only tenant IDs (names), plan tiers, and aggregate
 * signal scores. No personal data, no IP addresses, no request content.
 */

"use strict";

window.FrothIQGrowthMonetizationUI = class FrothIQGrowthMonetizationUI {
    constructor(wrapper) {
        this.wrapper      = wrapper;
        this.$el          = $(wrapper);
        this._stream_timer = null;
    }

    async render() {
        this.$el.empty().append(this._shell_html());
        await Promise.all([
            this._render_heatmap(),
            this._render_funnel(),
            this._render_paywall_activity(),
        ]);
        await this._render_value_stream();
        this._start_stream_refresh();
        await this._render_plan_panel();
    }

    destroy() {
        if (this._stream_timer) {
            clearInterval(this._stream_timer);
            this._stream_timer = null;
        }
    }

    // ------------------------------------------------------------------
    // Shell layout
    // ------------------------------------------------------------------

    _shell_html() {
        return `
<div class="gm-container" style="padding:16px;">
  <!-- Row 1: Heatmap + Funnel -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;">
    <div class="gm-section" id="gm-heatmap">
      <div class="gm-section-header">
        <h5 style="margin:0;">${__("Revenue Pressure Heatmap")}</h5>
        <span class="badge badge-info gm-heatmap-count">—</span>
      </div>
      <div class="gm-heatmap-body" style="margin-top:10px;max-height:340px;overflow-y:auto;"></div>
    </div>
    <div class="gm-section" id="gm-funnel">
      <div class="gm-section-header">
        <h5 style="margin:0;">${__("Upgrade Funnel")}</h5>
      </div>
      <div class="gm-funnel-body" style="margin-top:10px;"></div>
    </div>
  </div>

  <!-- Row 2: Paywall Activity -->
  <div class="gm-section" id="gm-paywall" style="margin-bottom:20px;">
    <div class="gm-section-header">
      <h5 style="margin:0;">${__("Paywall Activity Tracker")}</h5>
    </div>
    <div class="gm-paywall-body" style="margin-top:10px;"></div>
  </div>

  <!-- Row 3: Value Event Stream -->
  <div class="gm-section" id="gm-stream" style="margin-bottom:20px;">
    <div class="gm-section-header">
      <h5 style="margin:0;">${__("Value Event Stream")}</h5>
      <span class="text-muted" style="font-size:11px;">${__("auto-refresh 30s")}</span>
    </div>
    <div class="gm-stream-body" style="margin-top:10px;"></div>
  </div>

  <!-- Row 4: Plan Recommendation Panel -->
  <div class="gm-section" id="gm-plans">
    <div class="gm-section-header">
      <h5 style="margin:0;">${__("Plan Recommendation Panel")}</h5>
    </div>
    <div class="gm-plans-body" style="margin-top:10px;"></div>
  </div>
</div>`;
    }

    // ------------------------------------------------------------------
    // 1. Revenue Pressure Heatmap
    // ------------------------------------------------------------------

    async _render_heatmap() {
        const section = this.$el.find("#gm-heatmap");
        const body    = section.find(".gm-heatmap-body");

        let data;
        try {
            data = await this._call("get_revenue_heatmap", { limit: 30 });
        } catch (e) {
            body.html(`<div class="text-danger">${__("Failed to load heatmap.")}</div>`);
            return;
        }

        const tenants = data.tenants || [];
        section.find(".gm-heatmap-count").text(tenants.length);

        if (!tenants.length) {
            body.html(`<div class="text-muted text-center" style="padding:20px;">${__("No active tenants.")}</div>`);
            return;
        }

        let html = "";
        for (const t of tenants) {
            const bar_w  = Math.max(t.revenue_score, 2).toFixed(0);
            const color  = {red: "#dc3545", orange: "#fd7e14", green: "#28a745"}[t.color_band] || "#aaa";
            const plan_badge = this._plan_badge(t.plan);
            html += `
<div class="gm-heatmap-row" style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid #f0f0f0;">
  <div style="width:110px;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${t.tenant_id}">${t.tenant_id}</div>
  ${plan_badge}
  <div style="flex:1;height:10px;background:#f0f0f0;border-radius:5px;overflow:hidden;">
    <div style="width:${bar_w}%;height:100%;background:${color};border-radius:5px;transition:width .3s;"></div>
  </div>
  <span style="font-size:11px;font-weight:700;color:${color};width:32px;text-align:right;">${t.revenue_score.toFixed(0)}</span>
  <span style="font-size:10px;color:#888;" title="${__("Upgrade probability")}">${(t.upgrade_probability * 100).toFixed(0)}%</span>
</div>`;
        }
        body.html(html);
    }

    // ------------------------------------------------------------------
    // 2. Upgrade Funnel
    // ------------------------------------------------------------------

    async _render_funnel() {
        const body = this.$el.find("#gm-funnel .gm-funnel-body");
        let data;
        try {
            data = await this._call("get_upgrade_funnel");
        } catch (e) {
            body.html(`<div class="text-danger">${__("Failed to load funnel.")}</div>`);
            return;
        }

        const states  = data.states || {};
        const total   = data.total  || 1;
        const stages  = ["observed", "nudged", "engaged", "converted", "retained"];
        const colors  = {
            observed:  "#6c757d",
            nudged:    "#17a2b8",
            engaged:   "#ffc107",
            converted: "#28a745",
            retained:  "#4f8ef7",
        };

        let html = `<div style="display:flex;flex-direction:column;gap:6px;">`;
        for (const stage of stages) {
            const count = states[stage] || 0;
            const pct   = total > 0 ? ((count / total) * 100).toFixed(1) : "0.0";
            const color = colors[stage];
            html += `
<div style="display:flex;align-items:center;gap:8px;">
  <span style="width:80px;font-size:12px;text-transform:capitalize;color:#333;">${stage}</span>
  <div style="flex:1;height:18px;background:#f0f0f0;border-radius:4px;overflow:hidden;">
    <div style="width:${pct}%;height:100%;background:${color};border-radius:4px;transition:width .3s;"></div>
  </div>
  <span style="font-size:12px;font-weight:700;color:${color};width:32px;text-align:right;">${count}</span>
  <span style="font-size:10px;color:#888;width:36px;">${pct}%</span>
</div>`;
        }
        html += `</div>
<div style="margin-top:10px;font-size:11px;color:#888;">${__("Total active tenants: {0}", [total])}</div>`;
        body.html(html);
    }

    // ------------------------------------------------------------------
    // 3. Value Event Stream (auto-refresh 30s)
    // ------------------------------------------------------------------

    _start_stream_refresh() {
        this._refresh_stream();
        this._stream_timer = setInterval(() => this._refresh_stream(), 30000);
    }

    async _refresh_stream() {
        await this._render_value_stream();
    }

    async _render_value_stream() {
        const body = this.$el.find("#gm-stream .gm-stream-body");
        let data;
        try {
            data = await this._call("get_value_event_stream", { limit: 50 });
        } catch (e) {
            body.html(`<div class="text-muted">${__("Event stream unavailable.")}</div>`);
            return;
        }

        const events     = data.events     || [];
        const type_counts = data.type_counts || {};

        // Summary chips
        let chips = `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;">`;
        for (const [type, count] of Object.entries(type_counts).sort((a, b) => b[1] - a[1])) {
            chips += `<span class="badge badge-secondary" style="font-size:10px;">${type.replace(/_/g, " ")}: ${count}</span>`;
        }
        chips += `</div>`;

        if (!events.length) {
            body.html(chips + `<div class="text-muted text-center" style="padding:12px;">${__("No monetization events recorded.")}</div>`);
            return;
        }

        let table = `
<div style="font-size:11px;max-height:200px;overflow-y:auto;">
<table class="table table-condensed" style="margin:0;">
  <thead><tr>
    <th>${__("Event")}</th>
    <th>${__("Tenant")}</th>
    <th>${__("Severity")}</th>
    <th>${__("Timestamp")}</th>
  </tr></thead>
  <tbody>`;

        for (const ev of events.slice(0, 30)) {
            const ts = ev.event_timestamp
                ? frappe.datetime.str_to_user(ev.event_timestamp)
                : "—";
            const badge = this._event_type_badge(ev.event_type);
            table += `<tr>
  <td>${badge}</td>
  <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${ev.tenant || "—"}</td>
  <td><span class="indicator-pill ${ev.severity || 'blue'}">${ev.severity || "—"}</span></td>
  <td>${ts}</td>
</tr>`;
        }
        table += `</tbody></table></div>`;
        body.html(chips + table);
    }

    // ------------------------------------------------------------------
    // 4. Paywall Activity Tracker
    // ------------------------------------------------------------------

    async _render_paywall_activity() {
        const body = this.$el.find("#gm-paywall .gm-paywall-body");
        let data;
        try {
            data = await this._call("get_paywall_activity");
        } catch (e) {
            body.html(`<div class="text-muted">${__("Paywall stats unavailable.")}</div>`);
            return;
        }

        const by_type = data.by_event_type || {};

        let html = `
<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px;">
  <div class="gm-stat-card">
    <div class="gm-stat-value">${data.total_active_banners || 0}</div>
    <div class="gm-stat-label">${__("Active Banners")}</div>
  </div>
  <div class="gm-stat-card">
    <div class="gm-stat-value">${data.total_impressions_24h || 0}</div>
    <div class="gm-stat-label">${__("Impressions (24h)")}</div>
  </div>
</div>`;

        if (Object.keys(by_type).length) {
            html += `<div style="font-size:11px;"><strong>${__("By event type:")}</strong><br>`;
            for (const [type, count] of Object.entries(by_type).sort((a, b) => b[1] - a[1])) {
                html += `<span style="margin-right:10px;">${type.replace(/_/g, " ")}: <strong>${count}</strong></span>`;
            }
            html += `</div>`;
        }

        body.html(html);
    }

    // ------------------------------------------------------------------
    // 5. Plan Recommendation Panel
    // ------------------------------------------------------------------

    async _render_plan_panel() {
        const body = this.$el.find("#gm-plans .gm-plans-body");

        let data;
        try {
            data = await this._call("get_plan_recommendation_panel", { limit: 30 });
        } catch (e) {
            body.html(`<div class="text-muted">${__("Plan recommendations unavailable.")}</div>`);
            return;
        }

        const recs = data.recommendations || [];
        if (!recs.length) {
            body.html(`<div class="text-muted text-center" style="padding:20px;">${__("All tenants appear to be on optimal plans.")}</div>`);
            return;
        }

        let html = `
<div style="font-size:12px;overflow-x:auto;">
<table class="table table-condensed">
  <thead><tr>
    <th>${__("Tenant")}</th>
    <th>${__("Current")}</th>
    <th>${__("Recommended")}</th>
    <th>${__("Upgrade Path")}</th>
    <th>${__("Delta Value")}</th>
    <th>${__("Est. Monthly Loss")}</th>
    <th>${__("Friction Points")}</th>
  </tr></thead>
  <tbody>`;

        for (const r of recs) {
            const path = (r.upgrade_path || []).join(" → ");
            html += `<tr>
  <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${r.tenant_id}">${r.tenant_id}</td>
  <td>${this._plan_badge(r.current_plan)}</td>
  <td>${this._plan_badge(r.recommended_plan)}</td>
  <td><span style="font-size:10px;color:#555;">${path || "—"}</span></td>
  <td><strong style="color:#4f8ef7;">${r.upgrade_delta_value.toFixed(1)}</strong></td>
  <td>$${r.lost_value_monthly.toFixed(0)}/mo</td>
  <td><span class="badge badge-secondary">${r.inefficiency_count}</span></td>
</tr>`;
        }
        html += `</tbody></table></div>`;
        body.html(html);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    _plan_badge(plan) {
        const styles = {
            free:       "background:#6c757d;color:#fff",
            pro:        "background:#4f8ef7;color:#fff",
            enterprise: "background:#0ea5e9;color:#fff",
        };
        const style = styles[plan] || "background:#aaa;color:#fff";
        return `<span class="badge" style="${style};font-size:10px;">${plan || "free"}</span>`;
    }

    _event_type_badge(event_type) {
        const colors = {
            GLOBAL_INTEL_SPIKE:        "#dc3545",
            CAMPAIGN_PROPAGATION_EVENT:"#fd7e14",
            SIMULATION_INSIGHT_EVENT:  "#6f42c1",
            POLICY_UPGRADE_OPPORTUNITY:"#17a2b8",
            HIGH_THREAT_DETECTED:      "#dc3545",
            EVENTS_SPIKE:              "#ffc107",
            SITE_LIMIT_REACHED:        "#fd7e14",
            CAMPAIGNS_ACTIVE:          "#28a745",
            INTEL_NEAR_LIMIT:          "#6c757d",
        };
        const color = colors[event_type] || "#aaa";
        const label = (event_type || "").replace(/_/g, " ").toLowerCase();
        return `<span style="font-size:10px;color:${color};font-weight:600;">${label}</span>`;
    }

    _call(method, args) {
        return new Promise((resolve, reject) => {
            frappe.call({
                method: `orbweaver_frothiq.frothiq_portal.api.monetization_api.${method}`,
                args: args || {},
                callback: (r) => {
                    if (r && r.message !== undefined) resolve(r.message);
                    else reject(new Error("No response from server"));
                },
                error: (err) => reject(err),
            });
        });
    }
};


// ---------------------------------------------------------------------------
// CSS
// ---------------------------------------------------------------------------

(function () {
    if (document.getElementById("gm-styles")) return;
    const style = document.createElement("style");
    style.id = "gm-styles";
    style.textContent = `
.gm-section {
    background: #fff;
    border: 1px solid #e0e0e0;
    border-radius: 8px;
    padding: 14px;
}
.gm-section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #f0f0f0;
    padding-bottom: 8px;
    margin-bottom: 4px;
}
.gm-stat-card {
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 6px;
    padding: 10px 16px;
    text-align: center;
    min-width: 100px;
}
.gm-stat-value {
    font-size: 24px;
    font-weight: 700;
    color: #0f1629;
}
.gm-stat-label {
    font-size: 11px;
    color: #666;
    margin-top: 2px;
}
`;
    document.head.appendChild(style);
})();
