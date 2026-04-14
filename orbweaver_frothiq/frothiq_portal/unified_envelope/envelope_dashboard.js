// Copyright (c) 2026, OrbWeaver — Proprietary
// FrothIQ Unified Envelope Dashboard
//
// Renders the Control Center UI for the Unified Policy + License Signed Envelope.
// Components:
//   - Envelope Viewer        (license, policy, features, defense, orchestration sections)
//   - Diff Viewer            (version-vs-version comparison)
//   - Status Bar             (signature valid, drift alert, sync latency)
//   - Admin Actions          (force rebuild, emergency revoke, version rollback)
//   - Live update feed       (frothiq_envelope_update realtime event)
//
// Registered as a Frappe Page component via hooks.py:
//   page_js = { "frothiq_dashboard": "frothiq_portal/unified_envelope/envelope_dashboard.js" }

frappe.provide("frothiq.envelope");

frothiq.envelope.Dashboard = class EnvelopeDashboard {
    constructor(wrapper) {
        this.wrapper   = wrapper;
        this.envelope  = null;
        this.tenant_id = "";
        this._setup();
        this._subscribe_realtime();
    }

    // ------------------------------------------------------------------
    // Setup
    // ------------------------------------------------------------------

    _setup() {
        this.wrapper.innerHTML = `
            <div class="frothiq-envelope-dashboard" style="padding:16px">
                <!-- Tenant selector + status bar -->
                <div class="row mb-3">
                    <div class="col-md-6">
                        <div class="input-group">
                            <input type="text" class="form-control" id="env-tenant-input"
                                   placeholder="Tenant ID">
                            <div class="input-group-append">
                                <button class="btn btn-primary" id="env-load-btn">Load Envelope</button>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card" id="env-status-bar" style="min-height:48px">
                            <div class="card-body py-2 d-flex align-items-center" id="env-status-body">
                                <span class="text-muted">No envelope loaded</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Main envelope sections -->
                <div class="row">
                    <div class="col-md-7">
                        <!-- License section -->
                        <div class="card mb-3">
                            <div class="card-header d-flex justify-content-between">
                                <strong>License</strong>
                                <span id="env-license-status-badge"></span>
                            </div>
                            <div class="card-body" id="env-license-body">
                                <p class="text-muted">—</p>
                            </div>
                        </div>
                        <!-- Policy section -->
                        <div class="card mb-3">
                            <div class="card-header"><strong>Policy</strong></div>
                            <div class="card-body" id="env-policy-body">
                                <p class="text-muted">—</p>
                            </div>
                        </div>
                        <!-- Feature flags -->
                        <div class="card mb-3">
                            <div class="card-header"><strong>Feature Flags</strong></div>
                            <div class="card-body" id="env-features-body">
                                <p class="text-muted">—</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-5">
                        <!-- Defense section -->
                        <div class="card mb-3">
                            <div class="card-header"><strong>Defense State</strong></div>
                            <div class="card-body" id="env-defense-body">
                                <p class="text-muted">—</p>
                            </div>
                        </div>
                        <!-- Orchestration section -->
                        <div class="card mb-3">
                            <div class="card-header"><strong>Orchestration</strong></div>
                            <div class="card-body" id="env-orch-body">
                                <p class="text-muted">—</p>
                            </div>
                        </div>
                        <!-- Envelope metadata -->
                        <div class="card mb-3">
                            <div class="card-header"><strong>Envelope Metadata</strong></div>
                            <div class="card-body" id="env-meta-body">
                                <p class="text-muted">—</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Diff viewer -->
                <div class="row">
                    <div class="col-12">
                        <div class="card mb-3">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <strong>Version Diff Viewer</strong>
                                <div class="d-flex align-items-center">
                                    <input type="number" class="form-control form-control-sm mr-1"
                                           id="env-diff-old" placeholder="v_old" style="width:80px">
                                    <span class="mr-1">→</span>
                                    <input type="number" class="form-control form-control-sm mr-2"
                                           id="env-diff-new" placeholder="v_new" style="width:80px">
                                    <button class="btn btn-sm btn-secondary" id="env-diff-btn">Diff</button>
                                </div>
                            </div>
                            <div class="card-body" id="env-diff-body">
                                <p class="text-muted">Enter two version numbers above</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Admin actions -->
                <div class="row">
                    <div class="col-12">
                        <div class="card border-danger">
                            <div class="card-header">
                                <strong class="text-danger">Admin Actions</strong>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-4">
                                        <button class="btn btn-warning btn-sm w-100 mb-2"
                                                id="env-force-rebuild-btn">
                                            Force Rebuild Envelope
                                        </button>
                                    </div>
                                    <div class="col-md-4">
                                        <button class="btn btn-danger btn-sm w-100 mb-2"
                                                id="env-emergency-revoke-btn">
                                            Emergency Revoke
                                        </button>
                                    </div>
                                    <div class="col-md-4">
                                        <button class="btn btn-info btn-sm w-100 mb-2"
                                                id="env-audit-log-btn">
                                            View Audit Log
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Audit log -->
                <div class="row mt-3" id="env-audit-row" style="display:none">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header"><strong>Envelope Audit Log</strong></div>
                            <div class="card-body p-0">
                                <div id="env-audit-body"
                                     style="max-height:300px;overflow-y:auto;font-family:monospace;font-size:12px;padding:8px">
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        this._bind_events();
    }

    // ------------------------------------------------------------------
    // Data loading
    // ------------------------------------------------------------------

    load_envelope(tenant_id) {
        if (!tenant_id) { frappe.msgprint("Enter a Tenant ID"); return; }
        this.tenant_id = tenant_id;
        frappe.call({
            method: "orbweaver_frothiq.frothiq_portal.unified_envelope.envelope_api.get_envelope",
            args:   { tenant_id },
            callback: (r) => {
                if (r.message?.error) {
                    frappe.msgprint(`Error: ${r.message.error}`);
                    return;
                }
                this.envelope = r.message?.envelope;
                this._render_all();
            },
        });
    }

    _force_rebuild() {
        if (!this.tenant_id) { frappe.msgprint("Load an envelope first"); return; }
        frappe.confirm(`Force rebuild envelope for <strong>${_esc(this.tenant_id)}</strong>?`, () => {
            frappe.call({
                method:   "orbweaver_frothiq.frothiq_portal.unified_envelope.envelope_api.force_envelope_refresh",
                args:     { tenant_id: this.tenant_id },
                callback: (r) => {
                    const msg = r.message;
                    if (msg?.error) { frappe.msgprint(`Error: ${msg.error}`); return; }
                    frappe.msgprint(
                        `Envelope rebuilt. Version ${msg.version}. `
                        + `Redis: ${msg.broadcast?.redis_delivered ?? 0}`
                    );
                    this.load_envelope(this.tenant_id);
                },
            });
        });
    }

    _load_diff() {
        const old_v = parseInt(document.getElementById("env-diff-old")?.value);
        const new_v = parseInt(document.getElementById("env-diff-new")?.value);
        if (!this.tenant_id || isNaN(old_v) || isNaN(new_v)) {
            frappe.msgprint("Load an envelope and enter both version numbers");
            return;
        }
        frappe.call({
            method:   "orbweaver_frothiq.frothiq_portal.unified_envelope.envelope_api.get_envelope_diff",
            args:     { tenant_id: this.tenant_id, old_version: old_v, new_version: new_v },
            callback: (r) => {
                const msg = r.message;
                if (msg?.error) { frappe.msgprint(`Error: ${msg.error}`); return; }
                this._render_diff(msg.diff);
            },
        });
    }

    _load_audit() {
        frappe.call({
            method:   "orbweaver_frothiq.frothiq_portal.unified_envelope.envelope_api.get_envelope_audit_log",
            args:     { tenant_id: this.tenant_id, limit: 50 },
            callback: (r) => {
                const row = document.getElementById("env-audit-row");
                if (row) row.style.display = "";
                this._render_audit(r.message?.events || []);
            },
        });
    }

    // ------------------------------------------------------------------
    // Renderers
    // ------------------------------------------------------------------

    _render_all() {
        const e = this.envelope;
        if (!e) return;
        this._render_status(e);
        this._render_license(e.license, e.expires_at);
        this._render_policy(e.policy);
        this._render_features(e.features);
        this._render_defense(e.defense);
        this._render_orch(e.orchestration);
        this._render_meta(e);
    }

    _render_status(e) {
        const body  = document.getElementById("env-status-body");
        if (!body) return;
        const status   = e.license?.status || "unknown";
        const sigValid = e.signature ? "✓ Signed" : "✗ Unsigned";
        const cls      = { active: "success", trial: "info", suspended: "warning",
                           revoked: "danger", expired: "secondary" }[status] || "secondary";
        body.innerHTML = `
            <span class="badge badge-${cls} mr-2">${_esc(status)}</span>
            <span class="text-muted mr-3">${_esc(sigValid)}</span>
            <span class="text-muted mr-3">v${e.version}</span>
            <span class="text-muted">Tenant: <code>${_esc(e.tenant_id)}</code></span>
        `;
    }

    _render_license(lic, env_expires_at) {
        const el = document.getElementById("env-license-body");
        const badge_el = document.getElementById("env-license-status-badge");
        if (!el || !lic) return;
        const cls = { active: "success", trial: "info", suspended: "warning",
                      revoked: "danger", expired: "secondary" }[lic.status] || "secondary";
        if (badge_el) badge_el.innerHTML = `<span class="badge badge-${cls}">${_esc(lic.status)}</span>`;
        const exp = lic.expires_at ? new Date(lic.expires_at * 1000).toISOString().slice(0, 19).replace("T", " ") : "—";
        el.innerHTML = `
            <table class="table table-sm mb-0">
                <tr><td class="text-muted">Plan</td><td><strong>${_esc(lic.plan)}</strong></td></tr>
                <tr><td class="text-muted">Expires</td><td>${_esc(exp)}</td></tr>
                ${Object.entries(lic.limits || {}).map(([k, v]) =>
                    `<tr><td class="text-muted">${_esc(k)}</td><td>${_esc(String(v))}</td></tr>`
                ).join("")}
            </table>
        `;
    }

    _render_policy(pol) {
        const el = document.getElementById("env-policy-body");
        if (!el || !pol) return;
        el.innerHTML = `
            <small class="text-muted">Policy v${pol.policy_version}</small>
            <ul class="mb-0 mt-1" style="font-size:12px">
                ${(pol.active_rule_ids || []).map(id =>
                    `<li><code>${_esc(id)}</code></li>`
                ).join("") || "<li class='text-muted'>No active rules</li>"}
            </ul>
        `;
    }

    _render_features(feat) {
        const el = document.getElementById("env-features-body");
        if (!el || !feat) return;
        const entries = Object.entries(feat.features || {});
        if (!entries.length) { el.innerHTML = '<p class="text-muted">No features</p>'; return; }
        el.innerHTML = entries.map(([name, enabled]) =>
            `<span class="badge badge-${enabled ? "success" : "secondary"} mr-1 mb-1">${_esc(name)}</span>`
        ).join("");
    }

    _render_defense(def) {
        const el = document.getElementById("env-defense-body");
        if (!el || !def) return;
        const lvl_cls = { none: "secondary", low: "info", medium: "warning",
                          high: "danger", critical: "danger" }[def.threat_level] || "secondary";
        el.innerHTML = `
            <p class="mb-1">Threat: <span class="badge badge-${lvl_cls}">${_esc(def.threat_level)}</span></p>
            ${(def.active_campaigns || []).length ?
                `<small>Campaigns: ${def.active_campaigns.map(c => `<code>${_esc(c)}</code>`).join(", ")}</small>` : ""}
            ${(def.cluster_ids || []).length ?
                `<br><small>Clusters: ${def.cluster_ids.map(c => `<code>${_esc(c)}</code>`).join(", ")}</small>` : ""}
        `;
    }

    _render_orch(orch) {
        const el = document.getElementById("env-orch-body");
        if (!el || !orch) return;
        const bias = orch.system_bias || {};
        const biasHtml = Object.entries(bias).map(([k, v]) =>
            `<div class="d-flex justify-content-between mb-1">
                <small>${_esc(k)}</small>
                <div class="progress" style="width:60%;height:12px">
                    <div class="progress-bar" style="width:${Math.round(v*100)}%">${Math.round(v*100)}%</div>
                </div>
             </div>`
        ).join("") || "<p class='text-muted mb-0'>No bias set</p>";
        el.innerHTML = biasHtml;
    }

    _render_meta(e) {
        const el = document.getElementById("env-meta-body");
        if (!el) return;
        const issued = e.issued_at ? new Date(e.issued_at * 1000).toISOString().slice(0, 19).replace("T", " ") : "—";
        const expires = e.expires_at ? new Date(e.expires_at * 1000).toISOString().slice(0, 19).replace("T", " ") : "—";
        el.innerHTML = `
            <table class="table table-sm mb-0">
                <tr><td class="text-muted">Envelope ID</td><td><code style="font-size:10px">${_esc(e.envelope_id || "")}</code></td></tr>
                <tr><td class="text-muted">Version</td><td>${e.version}</td></tr>
                <tr><td class="text-muted">Issued</td><td>${_esc(issued)}</td></tr>
                <tr><td class="text-muted">Expires</td><td>${_esc(expires)}</td></tr>
                <tr><td class="text-muted">Schema</td><td>v${e.schema_version}</td></tr>
                <tr><td class="text-muted">Sig version</td><td>${e.signature_version}</td></tr>
            </table>
        `;
    }

    _render_diff(diff) {
        const el = document.getElementById("env-diff-body");
        if (!el) return;
        const entries = Object.entries(diff || {});
        if (!entries.length) {
            el.innerHTML = '<p class="text-success">No differences found</p>';
            return;
        }
        el.innerHTML = `<table class="table table-sm table-hover mb-0">
            <thead><tr><th>Field</th><th>Old</th><th>New</th></tr></thead>
            <tbody>
                ${entries.map(([field, change]) => `
                    <tr>
                        <td><code>${_esc(field)}</code></td>
                        <td><span class="text-danger">${_esc(JSON.stringify(change.old))}</span></td>
                        <td><span class="text-success">${_esc(JSON.stringify(change.new))}</span></td>
                    </tr>
                `).join("")}
            </tbody>
        </table>`;
    }

    _render_audit(events) {
        const el = document.getElementById("env-audit-body");
        if (!el) return;
        if (!events.length) { el.innerHTML = "<p class='text-muted'>No audit events</p>"; return; }
        el.innerHTML = events.map(ev => {
            const ts = ev.creation || "";
            return `<div class="mb-1">
                <span style="color:#888">${_esc(ts)}</span>
                <strong>${_esc(ev.event_type || "")}</strong>
                <span>${_esc(ev.tenant_id || "")}</span>
            </div>`;
        }).join("");
    }

    // ------------------------------------------------------------------
    // Event bindings
    // ------------------------------------------------------------------

    _bind_events() {
        const $ = (id) => document.getElementById(id);

        const loadBtn = $("env-load-btn");
        if (loadBtn) loadBtn.addEventListener("click", () => {
            const tid = $("env-tenant-input")?.value?.trim();
            this.load_envelope(tid);
        });

        const rebuildBtn = $("env-force-rebuild-btn");
        if (rebuildBtn) rebuildBtn.addEventListener("click", () => this._force_rebuild());

        const revokeBtn = $("env-emergency-revoke-btn");
        if (revokeBtn) revokeBtn.addEventListener("click", () => {
            if (!this.tenant_id) { frappe.msgprint("Load an envelope first"); return; }
            frappe.confirm(
                `<strong>Emergency revoke</strong> all access for <strong>${_esc(this.tenant_id)}</strong>?<br>
                 This builds a hard-block envelope and broadcasts it immediately.`,
                () => {
                    frappe.call({
                        method:   "orbweaver_frothiq.frothiq_portal.realtime_mesh.license_realtime_admin.force_revoke_broadcast",
                        args:     { tenant_id: this.tenant_id },
                        callback: (r) => {
                            frappe.msgprint(r.message?.success
                                ? `Emergency revoke broadcast for ${this.tenant_id}`
                                : `Error: ${JSON.stringify(r.message)}`);
                            this.load_envelope(this.tenant_id);
                        },
                    });
                }
            );
        });

        const auditBtn = $("env-audit-log-btn");
        if (auditBtn) auditBtn.addEventListener("click", () => this._load_audit());

        const diffBtn = $("env-diff-btn");
        if (diffBtn) diffBtn.addEventListener("click", () => this._load_diff());
    }

    // ------------------------------------------------------------------
    // Realtime
    // ------------------------------------------------------------------

    _subscribe_realtime() {
        frappe.realtime.on("frothiq_envelope_update", (data) => {
            // Auto-refresh if viewing this tenant
            if (data.tenant_id && data.tenant_id === this.tenant_id) {
                this.load_envelope(this.tenant_id);
            }
            // Show toast notification
            frappe.show_alert({
                message: `Envelope updated: ${data.tenant_id} v${data.version}`,
                indicator: "blue",
            }, 4);
        });
    }
};

// HTML escape helper (shared with license_mesh_dashboard.js)
if (typeof _esc === "undefined") {
    function _esc(str) {
        return String(str || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }
}
