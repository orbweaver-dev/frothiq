// Copyright (c) 2026, OrbWeaver — Proprietary
// FrothIQ License Mesh Dashboard — Control Center UI
//
// Renders the real-time license revocation mesh status panel.
// Components:
//   - Live license state map (per-tenant status badges)
//   - Revocation propagation timeline (animated event log)
//   - Drift alert panel (critical/warning)
//   - Node heartbeat monitor (stale indicator)
//   - Sync lag display (latency per node)
//
// Registered as a Frappe Page component via hooks.py:
//   page_js = { "frothiq_dashboard": "frothiq_portal/realtime_mesh/license_mesh_dashboard.js" }

frappe.provide("frothiq.mesh");

frothiq.mesh.Dashboard = class MeshDashboard {
    constructor(wrapper) {
        this.wrapper     = wrapper;
        this.state_map   = {};
        this.node_map    = {};
        this.event_log   = [];
        this.max_log_len = 50;
        this._setup();
        this._subscribe_realtime();
    }

    // ------------------------------------------------------------------
    // Setup
    // ------------------------------------------------------------------

    _setup() {
        this.wrapper.innerHTML = `
            <div class="frothiq-mesh-dashboard" style="padding:16px">
                <div class="row">
                    <div class="col-md-8">
                        <div class="card mb-3">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <strong>Live License State Map</strong>
                                <button class="btn btn-sm btn-primary" id="mesh-refresh-btn">Refresh</button>
                            </div>
                            <div class="card-body" id="mesh-state-map" style="min-height:120px">
                                <p class="text-muted">Loading...</p>
                            </div>
                        </div>
                        <div class="card mb-3">
                            <div class="card-header">
                                <strong>Revocation Event Log</strong>
                                <span class="badge badge-secondary ml-2" id="mesh-event-count">0</span>
                            </div>
                            <div class="card-body p-0">
                                <div id="mesh-event-log"
                                     style="height:220px;overflow-y:auto;font-family:monospace;font-size:12px;padding:8px">
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card mb-3">
                            <div class="card-header"><strong>Node Heartbeats</strong></div>
                            <div class="card-body" id="mesh-node-map" style="min-height:100px">
                                <p class="text-muted">No nodes registered</p>
                            </div>
                        </div>
                        <div class="card mb-3 border-warning">
                            <div class="card-header text-warning"><strong>Drift Alerts</strong></div>
                            <div class="card-body" id="mesh-drift-panel">
                                <p class="text-success">No drift detected</p>
                            </div>
                        </div>
                        <div class="card">
                            <div class="card-header"><strong>Mesh Health</strong></div>
                            <div class="card-body" id="mesh-health-panel">
                                <p class="text-muted">Loading...</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="row mt-2">
                    <div class="col-12">
                        <div class="card border-danger">
                            <div class="card-header d-flex justify-content-between">
                                <strong class="text-danger">Admin Actions</strong>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-4">
                                        <div class="input-group mb-2">
                                            <input type="text" class="form-control form-control-sm"
                                                   id="mesh-revoke-tenant" placeholder="Tenant ID">
                                            <div class="input-group-append">
                                                <button class="btn btn-sm btn-danger" id="mesh-force-revoke-btn">
                                                    Force Revoke
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <button class="btn btn-sm btn-warning" id="mesh-force-sync-btn">
                                            Force Sync All Tenants
                                        </button>
                                    </div>
                                    <div class="col-md-4">
                                        <button class="btn btn-sm btn-info" id="mesh-get-nodes-btn">
                                            Refresh Node Map
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        this._bind_events();
        this.refresh();
    }

    // ------------------------------------------------------------------
    // Data loading
    // ------------------------------------------------------------------

    refresh() {
        this._load_state_map();
        this._load_node_map();
        this._load_health();
    }

    _load_state_map() {
        frappe.call({
            method: "orbweaver_frothiq.frothiq_portal.realtime_mesh.license_realtime_admin.get_live_license_state_map",
            callback: (r) => {
                if (r.message) {
                    this.state_map = r.message;
                    this._render_state_map();
                }
            },
        });
    }

    _load_node_map() {
        frappe.call({
            method: "orbweaver_frothiq.frothiq_portal.realtime_mesh.license_realtime_admin.get_node_heartbeat_map",
            callback: (r) => {
                if (r.message) {
                    this.node_map = r.message;
                    this._render_node_map();
                }
            },
        });
    }

    _load_health() {
        // Health snapshot is computed client-side from recent events
        this._render_health();
    }

    // ------------------------------------------------------------------
    // Renderers
    // ------------------------------------------------------------------

    _render_state_map() {
        const el = document.getElementById("mesh-state-map");
        if (!el) return;

        const entries = Object.entries(this.state_map);
        if (!entries.length) {
            el.innerHTML = '<p class="text-muted">No tenants found</p>';
            return;
        }

        const _badge = (status) => {
            const map = {
                "active":    "success",
                "trial":     "info",
                "suspended": "warning",
                "revoked":   "danger",
                "expired":   "secondary",
            };
            const cls = map[status] || "secondary";
            return `<span class="badge badge-${cls}">${status}</span>`;
        };

        el.innerHTML = `
            <table class="table table-sm table-hover mb-0">
                <thead><tr>
                    <th>Tenant</th><th>Status</th><th>Plan</th><th>Expires</th>
                </tr></thead>
                <tbody>
                    ${entries.map(([tid, s]) => `
                        <tr>
                            <td><code>${_esc(tid)}</code></td>
                            <td>${_badge(s.status)}</td>
                            <td>${_esc(s.plan || "free")}</td>
                            <td><small>${_esc(s.expires_at || "—")}</small></td>
                        </tr>
                    `).join("")}
                </tbody>
            </table>
        `;
    }

    _render_node_map() {
        const el = document.getElementById("mesh-node-map");
        if (!el) return;

        const entries = Object.entries(this.node_map || {});
        if (!entries.length) {
            el.innerHTML = '<p class="text-muted">No nodes registered</p>';
            return;
        }

        el.innerHTML = entries.map(([nid, n]) => {
            const ago   = Math.floor(Date.now() / 1000 - (n.last_heartbeat || 0));
            const cls   = n.stale ? "text-danger" : "text-success";
            const label = n.stale ? "STALE" : "OK";
            return `
                <div class="d-flex justify-content-between mb-1">
                    <small><code>${_esc(nid)}</code> <em class="text-muted">${_esc(n.node_type || "")}</em></small>
                    <small class="${cls}">${label} (${ago}s ago)</small>
                </div>
            `;
        }).join("");
    }

    _render_health() {
        const el = document.getElementById("mesh-health-panel");
        if (!el) return;

        const events  = this.event_log;
        const revokes = events.filter(e => e.event_type === "LICENSE_REVOKED").length;
        const mode    = this._sync_client_mode || "unknown";

        el.innerHTML = `
            <div class="row text-center">
                <div class="col-4">
                    <div class="h4 text-primary">${events.length}</div>
                    <small class="text-muted">Events (session)</small>
                </div>
                <div class="col-4">
                    <div class="h4 text-danger">${revokes}</div>
                    <small class="text-muted">Revocations</small>
                </div>
                <div class="col-4">
                    <div class="h4">${Object.keys(this.node_map || {}).length}</div>
                    <small class="text-muted">Nodes</small>
                </div>
            </div>
        `;
    }

    _append_event_log(event) {
        this.event_log.unshift(event);
        if (this.event_log.length > this.max_log_len) {
            this.event_log.pop();
        }

        const el = document.getElementById("mesh-event-log");
        const ct = document.getElementById("mesh-event-count");
        if (!el) return;

        const ts   = new Date(event.ts * 1000).toISOString().slice(11, 23);
        const cls  = (event.event_type || "").includes("REVOKE") ? "color:red" : "color:inherit";
        const line = document.createElement("div");
        line.innerHTML = `<span style="color:#888">${ts}</span> `
            + `<strong style="${cls}">${_esc(event.event_type || "EVENT")}</strong> `
            + `<span>${_esc(event.tenant_id || "")}</span>`;
        el.prepend(line);

        // Trim DOM
        while (el.children.length > this.max_log_len) {
            el.removeChild(el.lastChild);
        }

        if (ct) ct.textContent = this.event_log.length;
    }

    _show_drift_alert(data) {
        const el = document.getElementById("mesh-drift-panel");
        if (!el) return;

        const cls = data.is_critical ? "danger" : "warning";
        const div = document.createElement("div");
        div.className = `alert alert-${cls} alert-sm p-1 mb-1`;
        div.innerHTML = `<strong>${_esc(data.drift_type)}</strong> — ${_esc(data.tenant_id)}`;
        el.prepend(div);
    }

    // ------------------------------------------------------------------
    // Admin actions
    // ------------------------------------------------------------------

    _bind_events() {
        const $ = (id) => document.getElementById(id);

        const refresh = $("mesh-refresh-btn");
        if (refresh) refresh.addEventListener("click", () => this.refresh());

        const forceRevoke = $("mesh-force-revoke-btn");
        if (forceRevoke) forceRevoke.addEventListener("click", () => {
            const tenantInput = $("mesh-revoke-tenant");
            const tid = tenantInput ? tenantInput.value.trim() : "";
            if (!tid) { frappe.msgprint("Enter a Tenant ID first"); return; }

            frappe.confirm(`Force revoke license for <strong>${_esc(tid)}</strong>?`, () => {
                frappe.call({
                    method: "orbweaver_frothiq.frothiq_portal.realtime_mesh.license_realtime_admin.force_revoke_broadcast",
                    args:   { tenant_id: tid },
                    callback: (r) => {
                        frappe.msgprint(r.message?.success
                            ? `Revoked and broadcast for ${tid}`
                            : `Error: ${JSON.stringify(r.message)}`);
                        this.refresh();
                    },
                });
            });
        });

        const forceSync = $("mesh-force-sync-btn");
        if (forceSync) forceSync.addEventListener("click", () => {
            frappe.confirm("Run full reconciliation sweep across all tenants?", () => {
                frappe.call({
                    method: "orbweaver_frothiq.frothiq_portal.realtime_mesh.license_realtime_admin.force_sync_all_tenants",
                    callback: (r) => {
                        frappe.msgprint(JSON.stringify(r.message?.report || r.message, null, 2));
                        this.refresh();
                    },
                });
            });
        });

        const getNodes = $("mesh-get-nodes-btn");
        if (getNodes) getNodes.addEventListener("click", () => this._load_node_map());
    }

    // ------------------------------------------------------------------
    // Real-time Frappe events
    // ------------------------------------------------------------------

    _subscribe_realtime() {
        frappe.realtime.on("frothiq_license_mesh_update", (data) => {
            this._append_event_log(data);
            // Refresh state map on revocation
            if ((data.event_type || "").includes("REVOKE")) {
                this._load_state_map();
            }
        });

        frappe.realtime.on("frothiq_mesh_health_update", (data) => {
            this._render_health_from_data(data);
        });

        frappe.realtime.on("frothiq_drift_alert", (data) => {
            this._show_drift_alert(data);
        });
    }

    _render_health_from_data(data) {
        const el = document.getElementById("mesh-health-panel");
        if (!el || !data) return;
        el.innerHTML = `
            <div class="row text-center">
                <div class="col-6">
                    <div class="h5 ${data.sync_success_rate < 0.9 ? "text-danger" : "text-success"}">
                        ${Math.round((data.sync_success_rate || 1) * 100)}%
                    </div>
                    <small class="text-muted">Sync success</small>
                </div>
                <div class="col-6">
                    <div class="h5 ${data.node_drift_rate > 0.05 ? "text-danger" : "text-success"}">
                        ${Math.round((data.node_drift_rate || 0) * 100)}%
                    </div>
                    <small class="text-muted">Drift rate</small>
                </div>
                <div class="col-6 mt-2">
                    <div class="h5">${Math.round(data.avg_propagation_latency_ms || 0)} ms</div>
                    <small class="text-muted">Avg latency</small>
                </div>
                <div class="col-6 mt-2">
                    <div class="h5 ${data.quarantine_triggers_per_hour > 10 ? "text-danger" : ""}">
                        ${data.quarantine_triggers_per_hour || 0}/hr
                    </div>
                    <small class="text-muted">Quarantines</small>
                </div>
            </div>
        `;
    }
};

// HTML escape helper
function _esc(str) {
    return String(str || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}
