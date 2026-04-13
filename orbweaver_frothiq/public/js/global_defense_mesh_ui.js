/**
 * FrothIQ — Global Defense Mesh UI (Phase 4)
 *
 * Renders the "Global Defense Mesh" tab in the FrothIQ Intelligence workspace page.
 * Enterprise-only view. Non-enterprise users see an upgrade prompt.
 *
 * Sections
 * --------
 *  1. Global Campaign Map      — clusters with confidence, site impact count, propagation radius
 *  2. Live Global Actions Feed — harden/soft_harden/monitor_boost feed, auto-refresh 5s
 *  3. Similarity Propagation Viewer — SVG graph: nodes=clusters, edges=similarity
 *  4. Global Policy Overrides  — Admin only: push emergency policy, rollback, audit log
 *
 * All data is tenant-agnostic: no IPs, no tenant IDs, no site names.
 * The API layer enforces this; the UI trusts the contract.
 */

"use strict";

window.FrothIQGlobalDefenseMesh = class FrothIQGlobalDefenseMesh {
    constructor(wrapper) {
        this.wrapper    = wrapper;
        this.$el        = $(wrapper);
        this._feed_timer = null;
        this._is_admin  = frappe.user.has_role("FrothIQ Admin");
        this._enterprise = false;  // resolved after status fetch
    }

    // ------------------------------------------------------------------
    // Entry point
    // ------------------------------------------------------------------

    async render() {
        this.$el.empty().append(this._shell_html());

        let status;
        try {
            status = await this._call("get_global_mesh_status");
        } catch (e) {
            this._show_error(__("Unable to connect to the Global Defense Mesh service."));
            return;
        }

        if (!status || !status.ok) {
            this._show_upgrade_prompt(status);
            return;
        }

        this._enterprise = true;
        this._render_status_bar(status.global_mesh || {});
        await this._render_cluster_map();
        this._render_live_feed_section();
        this._start_live_feed();
        await this._render_similarity_viewer();
        if (this._is_admin) {
            this._render_policy_panel();
        }
    }

    destroy() {
        this._stop_live_feed();
    }

    // ------------------------------------------------------------------
    // Shell layout
    // ------------------------------------------------------------------

    _shell_html() {
        return `
<div class="gdm-container" style="padding:16px;">
  <div class="gdm-status-bar" style="margin-bottom:16px;"></div>

  <div class="gdm-section" id="gdm-cluster-map">
    <div class="gdm-section-header">
      <h5 style="margin:0;">${__("Global Campaign Map")}</h5>
      <span class="badge badge-pill badge-secondary gdm-cluster-count">—</span>
    </div>
    <div class="gdm-cluster-grid" style="margin-top:10px;"></div>
  </div>

  <div class="gdm-section" id="gdm-live-feed" style="margin-top:20px;">
    <div class="gdm-section-header">
      <h5 style="margin:0;">${__("Live Global Actions Feed")}</h5>
      <span class="gdm-feed-badge text-muted" style="font-size:11px;">${__("auto-refresh 5s")}</span>
    </div>
    <div class="gdm-feed-controls" style="margin:8px 0;">
      <select class="form-control form-control-sm gdm-threat-filter" style="display:inline-block;width:auto;margin-right:6px;">
        <option value="">${__("All threat levels")}</option>
        <option value="critical">${__("Critical")}</option>
        <option value="high">${__("High")}</option>
        <option value="medium">${__("Medium")}</option>
        <option value="low">${__("Low")}</option>
      </select>
      <select class="form-control form-control-sm gdm-action-filter" style="display:inline-block;width:auto;">
        <option value="">${__("All action types")}</option>
        <option value="harden">${__("Harden")}</option>
        <option value="soft_harden">${__("Soft Harden")}</option>
        <option value="monitor_boost">${__("Monitor Boost")}</option>
        <option value="rate_limit_boost">${__("Rate Limit Boost")}</option>
      </select>
    </div>
    <div class="gdm-feed-body"></div>
  </div>

  <div class="gdm-section" id="gdm-similarity-viewer" style="margin-top:20px;">
    <div class="gdm-section-header">
      <h5 style="margin:0;">${__("Similarity Propagation Viewer")}</h5>
    </div>
    <div class="gdm-threshold-row" style="margin:8px 0;display:flex;align-items:center;gap:10px;">
      <label style="margin:0;font-size:12px;">${__("Threshold")}</label>
      <input type="range" class="gdm-threshold-slider" min="0" max="100" value="0" style="width:200px;">
      <span class="gdm-threshold-value" style="font-size:12px;font-weight:600;">0%</span>
      <button class="btn btn-sm btn-default gdm-refresh-graph">${__("Refresh")}</button>
    </div>
    <div class="gdm-graph-container" style="border:1px solid #e0e0e0;border-radius:6px;background:#fafafa;min-height:300px;position:relative;overflow:hidden;">
      <svg class="gdm-graph-svg" width="100%" height="300" xmlns="http://www.w3.org/2000/svg"></svg>
      <div class="gdm-graph-empty text-muted text-center" style="padding:60px 0;display:none;">
        ${__("No clusters above the selected similarity threshold.")}
      </div>
    </div>
    <div class="gdm-graph-legend" style="margin-top:6px;font-size:11px;color:#666;display:flex;gap:16px;flex-wrap:wrap;"></div>
  </div>

  <div class="gdm-section gdm-admin-only" id="gdm-policy-panel" style="margin-top:20px;display:none;">
    <div class="gdm-section-header">
      <h5 style="margin:0;">${__("Global Policy Overrides")}</h5>
      <span class="badge badge-warning">${__("Admin Only")}</span>
    </div>
    <div class="gdm-policy-body" style="margin-top:10px;"></div>
  </div>
</div>`;
    }

    // ------------------------------------------------------------------
    // Status bar
    // ------------------------------------------------------------------

    _render_status_bar(mesh) {
        const by_level = mesh.by_threat_level || {};
        const by_type  = mesh.by_action_type  || {};
        const age      = mesh.refresh_age_seconds != null
            ? `${Math.round(mesh.refresh_age_seconds)}s ago`
            : "—";

        const html = `
<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center;">
  ${this._stat_pill(__("Active Actions"), mesh.active_action_count || 0, "#4f8ef7")}
  ${this._stat_pill(__("Critical"), by_level.critical || 0, "#dc3545")}
  ${this._stat_pill(__("High"), by_level.high || 0, "#fd7e14")}
  ${this._stat_pill(__("Medium"), by_level.medium || 0, "#ffc107")}
  ${this._stat_pill(__("Low"), by_level.low || 0, "#28a745")}
  <span style="margin-left:auto;font-size:11px;color:#888;">${__("Last refresh:")} ${age}</span>
</div>`;
        this.$el.find(".gdm-status-bar").html(html);
    }

    _stat_pill(label, value, color) {
        return `
<div style="background:${color}18;border:1px solid ${color}40;border-radius:20px;padding:4px 12px;font-size:12px;">
  <span style="color:${color};font-weight:700;">${value}</span>
  <span style="color:#555;margin-left:4px;">${label}</span>
</div>`;
    }

    // ------------------------------------------------------------------
    // Global Campaign Map
    // ------------------------------------------------------------------

    async _render_cluster_map() {
        const section = this.$el.find("#gdm-cluster-map");
        const grid    = section.find(".gdm-cluster-grid");
        grid.html(`<div class="text-muted" style="font-size:12px;">${__("Loading clusters…")}</div>`);

        let data;
        try {
            data = await this._call("get_similarity_map", { threshold: 0.0 });
        } catch (e) {
            grid.html(`<div class="text-danger">${__("Failed to load cluster map.")}</div>`);
            return;
        }

        const nodes  = data.nodes || [];
        section.find(".gdm-cluster-count").text(nodes.length);

        if (!nodes.length) {
            grid.html(`<div class="text-muted" style="font-size:12px;">${__("No active clusters.")}</div>`);
            return;
        }

        // Enrich nodes with propagation radius (count of edges)
        const edges = data.edges || [];
        const edge_count = {};
        for (const e of edges) {
            edge_count[e.cluster_a] = (edge_count[e.cluster_a] || 0) + 1;
            edge_count[e.cluster_b] = (edge_count[e.cluster_b] || 0) + 1;
        }

        let html = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px;">`;
        for (const node of nodes) {
            const level_color = this._threat_color(node.threat_level);
            const radius      = edge_count[node.cluster_id] || 0;
            const short_id    = node.cluster_id.slice(-8).toUpperCase();
            html += `
<div class="gdm-cluster-card" style="border:1px solid ${level_color}60;border-radius:8px;padding:12px;background:#fff;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
    <code style="font-size:11px;color:#555;">${short_id}</code>
    <span class="badge" style="background:${level_color};color:#fff;font-size:10px;">${node.threat_level || "—"}</span>
  </div>
  <div style="font-size:12px;color:#333;margin-bottom:4px;">
    ${__("Attack vectors:")} ${(node.attack_vectors || []).join(", ") || "—"}
  </div>
  <div style="display:flex;gap:12px;font-size:11px;color:#555;margin-top:6px;">
    <span title="${__("Sites impacted")}">🏢 ${node.affected_site_count || 0}</span>
    <span title="${__("Similarity score")}">📊 ${((node.similarity_score || 0) * 100).toFixed(0)}%</span>
    <span title="${__("Propagation radius (connected clusters)")}">🔗 ${radius}</span>
  </div>
</div>`;
        }
        html += `</div>`;
        grid.html(html);
    }

    // ------------------------------------------------------------------
    // Live Global Actions Feed
    // ------------------------------------------------------------------

    _render_live_feed_section() {
        this.$el.find(".gdm-threat-filter, .gdm-action-filter").on("change", () => {
            this._refresh_feed();
        });
    }

    _start_live_feed() {
        this._refresh_feed();
        this._feed_timer = setInterval(() => this._refresh_feed(), 5000);
    }

    _stop_live_feed() {
        if (this._feed_timer) {
            clearInterval(this._feed_timer);
            this._feed_timer = null;
        }
    }

    async _refresh_feed() {
        const threat_level = this.$el.find(".gdm-threat-filter").val() || null;
        const action_type  = this.$el.find(".gdm-action-filter").val()  || null;

        let data;
        try {
            data = await this._call("get_global_actions", {
                limit: 30,
                threat_level,
                action_type,
            });
        } catch (e) {
            return;  // silently skip on auto-refresh failures
        }

        const actions = data.actions || [];
        const body    = this.$el.find(".gdm-feed-body");

        if (!actions.length) {
            body.html(`<div class="text-muted text-center" style="padding:20px;font-size:12px;">${__("No active global defense actions.")}</div>`);
            return;
        }

        let html = `<div style="font-size:12px;">
<table class="table table-condensed" style="margin:0;">
  <thead><tr>
    <th>${__("Cluster")}</th>
    <th>${__("Action")}</th>
    <th>${__("Threat")}</th>
    <th>${__("Confidence")}</th>
    <th>${__("Chain")}</th>
    <th>${__("Expires")}</th>
  </tr></thead>
  <tbody>`;

        for (const a of actions) {
            const level_color  = this._threat_color(a.threat_level);
            const action_badge = this._action_badge(a.action_type);
            const short_cluster = (a.cluster_id || "").slice(-8).toUpperCase();
            const short_chain   = (a.propagation_chain_id || "").slice(-8).toUpperCase();
            const confidence_pct = ((a.confidence || 0) * 100).toFixed(0) + "%";
            const expires = a.ttl_expires_at
                ? new Date(a.ttl_expires_at * 1000).toLocaleTimeString()
                : "—";
            const propagated_icon = a.is_propagated ? " 🔗" : "";

            html += `<tr>
  <td><code>${short_cluster}${propagated_icon}</code></td>
  <td>${action_badge}</td>
  <td><span style="color:${level_color};font-weight:600;">${a.threat_level || "—"}</span></td>
  <td>${confidence_pct}</td>
  <td><code style="font-size:10px;">${short_chain || "—"}</code></td>
  <td>${expires}</td>
</tr>`;
        }

        html += `</tbody></table></div>`;
        body.html(html);
    }

    // ------------------------------------------------------------------
    // Similarity Propagation Viewer (SVG graph)
    // ------------------------------------------------------------------

    async _render_similarity_viewer() {
        const section  = this.$el.find("#gdm-similarity-viewer");
        const slider   = section.find(".gdm-threshold-slider");
        const val_label = section.find(".gdm-threshold-value");

        slider.on("input", () => {
            val_label.text(slider.val() + "%");
        });

        section.find(".gdm-refresh-graph").on("click", async () => {
            await this._draw_graph(parseFloat(slider.val()) / 100);
        });

        await this._draw_graph(0.0);
    }

    async _draw_graph(threshold) {
        const section = this.$el.find("#gdm-similarity-viewer");
        const svg_el  = section.find(".gdm-graph-svg");
        const empty   = section.find(".gdm-graph-empty");
        const legend  = section.find(".gdm-graph-legend");

        svg_el.empty();
        legend.empty();

        let data;
        try {
            data = await this._call("get_similarity_map", { threshold });
        } catch (e) {
            svg_el.html(`<text x="50%" y="50%" text-anchor="middle" fill="#dc3545" font-size="12">${__("Failed to load graph")}</text>`);
            return;
        }

        const nodes  = data.nodes || [];
        const edges  = data.edges || [];
        const width  = svg_el[0].clientWidth  || 700;
        const height = 300;

        if (!nodes.length) {
            empty.show();
            svg_el.hide();
            return;
        }
        empty.hide();
        svg_el.show();

        // Simple force-free layout: place nodes in a circle
        const cx = width  / 2;
        const cy = height / 2;
        const r  = Math.min(cx, cy) * 0.70;
        const angle_step = (2 * Math.PI) / nodes.length;

        const positions = {};
        nodes.forEach((n, i) => {
            positions[n.cluster_id] = {
                x: cx + r * Math.cos(i * angle_step - Math.PI / 2),
                y: cy + r * Math.sin(i * angle_step - Math.PI / 2),
            };
        });

        let svg_html = "";

        // Defs: arrow marker
        svg_html += `<defs>
  <marker id="gdm-arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
    <path d="M0,0 L6,3 L0,6 Z" fill="#4f8ef7" opacity="0.6"/>
  </marker>
</defs>`;

        // Edges
        for (const e of edges) {
            const pa = positions[e.cluster_a];
            const pb = positions[e.cluster_b];
            if (!pa || !pb) continue;
            const opacity = Math.min(0.9, 0.2 + e.similarity * 0.7);
            const width_px = Math.max(1, e.similarity * 4).toFixed(1);
            svg_html += `<line x1="${pa.x.toFixed(1)}" y1="${pa.y.toFixed(1)}"
              x2="${pb.x.toFixed(1)}" y2="${pb.y.toFixed(1)}"
              stroke="#4f8ef7" stroke-width="${width_px}" opacity="${opacity}"
              marker-end="url(#gdm-arrow)">
  <title>${__("Similarity")}: ${(e.similarity * 100).toFixed(0)}% | ${__("Influence")}: ${(e.influence_score * 100).toFixed(0)}%</title>
</line>`;
        }

        // Nodes
        for (const n of nodes) {
            const pos   = positions[n.cluster_id];
            const color = this._threat_color(n.threat_level);
            const short = n.cluster_id.slice(-4).toUpperCase();
            const node_r = Math.max(16, Math.min(30, 12 + n.affected_site_count * 2));
            svg_html += `
<circle cx="${pos.x.toFixed(1)}" cy="${pos.y.toFixed(1)}" r="${node_r}"
  fill="${color}" fill-opacity="0.85" stroke="#fff" stroke-width="2">
  <title>${n.cluster_id}\n${__("Threat")}: ${n.threat_level}\n${__("Sites")}: ${n.affected_site_count}\n${__("Similarity")}: ${(n.similarity_score * 100).toFixed(0)}%</title>
</circle>
<text x="${pos.x.toFixed(1)}" y="${(pos.y + 4).toFixed(1)}" text-anchor="middle"
  font-size="9" fill="#fff" font-family="monospace" pointer-events="none">${short}</text>`;
        }

        svg_el.html(svg_html);

        // Legend
        const levels = ["critical", "high", "medium", "low"];
        let leg_html = `<span style="font-weight:600;">${__("Threat level:")} </span>`;
        for (const lv of levels) {
            const c = this._threat_color(lv);
            leg_html += `<span style="margin-right:10px;">
<svg width="10" height="10" style="vertical-align:middle;"><circle cx="5" cy="5" r="5" fill="${c}"/></svg>
&nbsp;${lv}
</span>`;
        }
        leg_html += `<span style="margin-left:auto;">${__("Node size = sites impacted | Edge width = similarity")}</span>`;
        legend.html(leg_html);
    }

    // ------------------------------------------------------------------
    // Global Policy Overrides (Admin only)
    // ------------------------------------------------------------------

    _render_policy_panel() {
        const panel = this.$el.find("#gdm-policy-panel");
        panel.show();

        const body = panel.find(".gdm-policy-body");
        body.html(`
<div style="display:flex;gap:10px;flex-wrap:wrap;">

  <!-- Emergency Policy Push -->
  <div class="card" style="flex:1;min-width:260px;">
    <div class="card-body" style="padding:12px;">
      <h6 style="color:#dc3545;">${__("Push Emergency Policy")}</h6>
      <div class="form-group" style="margin-bottom:8px;">
        <label style="font-size:11px;">${__("Rule Name")}</label>
        <input type="text" class="form-control form-control-sm gdm-ep-name" placeholder="e.g. emergency-block-brute-force">
      </div>
      <div style="display:flex;gap:6px;margin-bottom:8px;">
        <div class="form-group" style="flex:1;">
          <label style="font-size:11px;">${__("Priority (1–10)")}</label>
          <input type="number" class="form-control form-control-sm gdm-ep-priority" value="5" min="1" max="10">
        </div>
        <div class="form-group" style="flex:1;">
          <label style="font-size:11px;">${__("Action")}</label>
          <select class="form-control form-control-sm gdm-ep-action">
            <option value="block">${__("Block")}</option>
            <option value="rate_limit">${__("Rate Limit")}</option>
            <option value="observe">${__("Observe")}</option>
          </select>
        </div>
      </div>
      <div style="display:flex;gap:6px;margin-bottom:8px;">
        <div class="form-group" style="flex:1;">
          <label style="font-size:11px;">${__("Condition Field")}</label>
          <input type="text" class="form-control form-control-sm gdm-ep-field" value="score">
        </div>
        <div class="form-group" style="flex:0.6;">
          <label style="font-size:11px;">${__("Operator")}</label>
          <select class="form-control form-control-sm gdm-ep-operator">
            <option value="gte">&gt;=</option>
            <option value="gt">&gt;</option>
            <option value="eq">=</option>
            <option value="lte">&lt;=</option>
          </select>
        </div>
        <div class="form-group" style="flex:0.6;">
          <label style="font-size:11px;">${__("Value")}</label>
          <input type="text" class="form-control form-control-sm gdm-ep-value" value="80">
        </div>
      </div>
      <button class="btn btn-sm btn-danger gdm-push-ep-btn" style="width:100%;">${__("Push Emergency Policy")}</button>
    </div>
  </div>

  <!-- Rollback + Audit -->
  <div class="card" style="flex:1;min-width:240px;">
    <div class="card-body" style="padding:12px;">
      <h6 style="color:#fd7e14;">${__("Rollback Policy Batch")}</h6>
      <p style="font-size:11px;color:#666;">${__("Rolls back all ACTIVE rules in the selected namespace.")}</p>
      <div class="form-group" style="margin-bottom:8px;">
        <label style="font-size:11px;">${__("Namespace")}</label>
        <select class="form-control form-control-sm gdm-rb-namespace">
          <option value="global">${__("global (all tenants)")}</option>
        </select>
      </div>
      <button class="btn btn-sm btn-warning gdm-rollback-btn" style="width:100%;margin-bottom:10px;">${__("Rollback Last Batch")}</button>

      <h6 style="margin-top:10px;">${__("Policy Distribution")}</h6>
      <div class="gdm-policy-version-info text-muted" style="font-size:11px;">${__("Loading…")}</div>
      <div style="margin-top:10px;">
        <button class="btn btn-sm btn-default gdm-audit-btn" style="width:100%;">${__("View Audit Log")}</button>
      </div>
    </div>
  </div>

</div>
<div class="gdm-audit-log-section" style="margin-top:14px;display:none;">
  <h6>${__("Global Action Audit Log")}</h6>
  <div class="gdm-audit-body"></div>
</div>`);

        // Load policy version info
        this._load_policy_version_info();

        // Push emergency policy
        body.find(".gdm-push-ep-btn").on("click", async () => {
            const name = body.find(".gdm-ep-name").val().trim();
            if (!name) {
                frappe.msgprint(__("Please enter a rule name."));
                return;
            }
            const confirmed = await new Promise(resolve => {
                frappe.confirm(
                    __("Push emergency policy <b>{0}</b> (priority {1})? This takes effect immediately on all agent heartbeats.", [name, body.find(".gdm-ep-priority").val()]),
                    () => resolve(true), () => resolve(false),
                );
            });
            if (!confirmed) return;

            try {
                const result = await this._call("push_emergency_policy", {
                    rule_name:          name,
                    priority:           parseInt(body.find(".gdm-ep-priority").val()),
                    condition_field:    body.find(".gdm-ep-field").val(),
                    condition_operator: body.find(".gdm-ep-operator").val(),
                    condition_value:    body.find(".gdm-ep-value").val(),
                    action_type:        body.find(".gdm-ep-action").val(),
                });
                frappe.show_alert({
                    message: __("Emergency policy pushed. New global version: {0}", [result.new_global_version]),
                    indicator: "red",
                });
                this._load_policy_version_info();
            } catch (e) {
                frappe.msgprint({message: __("Failed to push emergency policy: ") + e.message, indicator: "red"});
            }
        });

        // Rollback
        body.find(".gdm-rollback-btn").on("click", async () => {
            const ns = body.find(".gdm-rb-namespace").val();
            const confirmed = await new Promise(resolve => {
                frappe.confirm(
                    __("Rollback ALL active policy rules in namespace <b>{0}</b>? This cannot be undone.", [ns]),
                    () => resolve(true), () => resolve(false),
                );
            });
            if (!confirmed) return;

            try {
                const result = await this._call("rollback_last_policy_batch", { namespace: ns });
                frappe.show_alert({
                    message: __("{0} rules rolled back in namespace '{1}'.", [result.rolled_back_count, ns]),
                    indicator: "orange",
                });
                this._load_policy_version_info();
            } catch (e) {
                frappe.msgprint({message: __("Rollback failed: ") + e.message, indicator: "red"});
            }
        });

        // Audit log
        body.find(".gdm-audit-btn").on("click", async () => {
            const audit_section = body.parent().find(".gdm-audit-log-section");
            if (audit_section.is(":visible")) {
                audit_section.hide();
                return;
            }
            await this._load_audit_log();
            audit_section.show();
        });
    }

    async _load_policy_version_info() {
        const el = this.$el.find(".gdm-policy-version-info");
        try {
            const data = await this._call("get_policy_distribution_status");
            if (data.ok) {
                el.html(`${__("Global policy version:")} <strong>${data.global_version}</strong>`);
            } else {
                el.text(__("Unavailable"));
            }
        } catch (e) {
            el.text(__("Unavailable"));
        }
    }

    async _load_audit_log() {
        const body_el = this.$el.find(".gdm-audit-body");
        body_el.html(`<div class="text-muted">${__("Loading…")}</div>`);

        let data;
        try {
            data = await this._call("get_audit_log", { limit: 50 });
        } catch (e) {
            body_el.html(`<div class="text-danger">${__("Failed to load audit log.")}</div>`);
            return;
        }

        const log = data.audit_log || [];
        if (!log.length) {
            body_el.html(`<div class="text-muted">${__("No audit log entries.")}</div>`);
            return;
        }

        let html = `<div style="font-size:11px;">
<table class="table table-condensed">
  <thead><tr>
    <th>${__("Action ID")}</th>
    <th>${__("Cluster")}</th>
    <th>${__("Type")}</th>
    <th>${__("Chain")}</th>
    <th>${__("Reason")}</th>
    <th>${__("Timestamp")}</th>
  </tr></thead>
  <tbody>`;

        for (const entry of log) {
            const ts = entry.timestamp
                ? new Date(entry.timestamp * 1000).toLocaleString()
                : "—";
            html += `<tr>
  <td><code>${(entry.action_id || "").slice(-8)}</code></td>
  <td><code>${(entry.cluster_id || "").slice(-8).toUpperCase()}</code></td>
  <td>${this._action_badge(entry.action_type)}</td>
  <td><code>${(entry.propagation_chain_id || "").slice(-8) || "—"}</code></td>
  <td>${entry.reason_code || "—"}</td>
  <td>${ts}</td>
</tr>`;
        }
        html += `</tbody></table></div>`;
        body_el.html(html);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    _threat_color(level) {
        return {
            critical: "#dc3545",
            high:     "#fd7e14",
            medium:   "#ffc107",
            low:      "#28a745",
        }[level] || "#6c757d";
    }

    _action_badge(action_type) {
        const styles = {
            harden:           "background:#dc3545;color:#fff",
            soft_harden:      "background:#fd7e14;color:#fff",
            monitor_boost:    "background:#17a2b8;color:#fff",
            rate_limit_boost: "background:#6f42c1;color:#fff",
        };
        const style = styles[action_type] || "background:#6c757d;color:#fff";
        const label = (action_type || "").replace(/_/g, " ");
        return `<span class="badge" style="${style};font-size:10px;">${label}</span>`;
    }

    _show_upgrade_prompt(status) {
        const plan = (status && status.plan) || "free";
        this.$el.html(`
<div class="text-center" style="padding:60px 20px;">
  <div style="font-size:48px;">🔒</div>
  <h4 style="margin-top:16px;">${__("Global Defense Mesh")}</h4>
  <p style="color:#666;max-width:440px;margin:12px auto;">
    ${__("Cross-tenant threat intelligence and autonomous defense coordination require an Enterprise plan.")}
  </p>
  <p class="text-muted" style="font-size:12px;">${__("Current plan: {0}", [plan])}</p>
  <a href="https://orbweaver.dev/pricing" target="_blank" class="btn btn-primary">${__("Upgrade to Enterprise")}</a>
</div>`);
    }

    _show_error(msg) {
        this.$el.html(`<div class="alert alert-danger">${msg}</div>`);
    }

    _call(method, args) {
        return new Promise((resolve, reject) => {
            frappe.call({
                method: `orbweaver_frothiq.frothiq_portal.api.global_defense_api.${method}`,
                args: args || {},
                callback: (r) => {
                    if (r && r.message !== undefined) {
                        resolve(r.message);
                    } else {
                        reject(new Error("No response from server"));
                    }
                },
                error: (err) => reject(err),
            });
        });
    }
};


// ---------------------------------------------------------------------------
// Integration: attach to FrothIQ Intelligence page
// ---------------------------------------------------------------------------

frappe.pages["frothiq-intelligence"] = frappe.pages["frothiq-intelligence"] || {};

(function () {
    const _orig_setup = frappe.pages["frothiq-intelligence"].setup;
    frappe.pages["frothiq-intelligence"].setup = function (wrapper) {
        if (_orig_setup) _orig_setup.call(this, wrapper);
        // Register the Global Defense Mesh tab after page setup
        if (window._frothiq_intelligence_page) {
            _inject_gdm_tab(window._frothiq_intelligence_page);
        }
    };
})();

function _inject_gdm_tab(page) {
    const tab_bar = $(page.wrapper).find(".frothiq-tabs");
    if (!tab_bar.length) return;
    if (tab_bar.find('[data-tab="global_defense_mesh"]').length) return;

    tab_bar.append(`
<li class="nav-item">
  <a class="nav-link frothiq-tab-link" data-tab="global_defense_mesh" href="#">
    ${__("Global Defense Mesh")}
  </a>
</li>`);

    const content_area = $(page.wrapper).find(".frothiq-tab-content");
    const gdm_pane = $(`<div class="frothiq-tab-pane" data-tab="global_defense_mesh" style="display:none;"></div>`);
    content_area.append(gdm_pane);

    let gdm_view = null;
    $(page.wrapper).on("frothiq-tab-shown", (e, tab) => {
        if (tab === "global_defense_mesh") {
            if (!gdm_view) {
                gdm_view = new window.FrothIQGlobalDefenseMesh(gdm_pane[0]);
            }
            gdm_view.render();
        } else if (gdm_view) {
            gdm_view.destroy();
        }
    });
}
