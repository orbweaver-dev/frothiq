/**
 * FrothIQ Flywheel Dashboard
 *
 * Autonomous Security Intelligence Flywheel — Frappe desk UI layer.
 *
 * Renders into any container with:
 *   const fw = new FrothIQFlywheelDashboard(wrapper);
 *   fw.render();
 *
 * Sections:
 *   1. System Health Ring — 5 subsystem momentum gauges
 *   2. Correlation Heatmap — 5×5 matrix (pro/enterprise only)
 *   3. Momentum Timeline — signal delta over time
 *   4. Instability Alerts Panel — drift detection + warnings
 *   5. Optimization Suggestions — "what to improve next"
 *
 * Plan gating is enforced server-side. The UI renders upgrade prompts
 * for locked features.
 */

/* --------------------------------------------------------------------------
 * Utility
 * -------------------------------------------------------------------------- */

function _api(method, args) {
    return new Promise((resolve, reject) => {
        frappe.call({
            method: method,
            args: args || {},
            callback: (r) => (r.exc ? reject(r.exc) : resolve(r.message)),
        });
    });
}

function _momentum_color(val) {
    // val: 0.0–1.0 momentum
    if (val >= 0.70) return "#22c55e";   // green
    if (val >= 0.45) return "#f59e0b";   // amber
    return "#ef4444";                     // red
}

function _health_color(val) {
    if (val >= 75) return "#22c55e";
    if (val >= 50) return "#f59e0b";
    return "#ef4444";
}

function _badge(text, color) {
    return `<span style="
        display:inline-block;padding:2px 8px;border-radius:10px;
        background:${color}22;color:${color};font-size:11px;font-weight:600;
        border:1px solid ${color}44;">${text}</span>`;
}

function _pct(val, max) {
    return Math.min(100, Math.round((val / max) * 100));
}

function _severity_color(sev) {
    const m = { critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#6b7280" };
    return m[sev] || m.low;
}

/* --------------------------------------------------------------------------
 * FrothIQFlywheelDashboard
 * -------------------------------------------------------------------------- */

class FrothIQFlywheelDashboard {
    constructor(wrapper) {
        this.wrapper = wrapper;
        this._state   = null;
        this._plan    = "free";
        this._refresh_timer = null;
        this._REFRESH_MS = 30_000;
        this._SYSTEMS = ["defense_mesh", "policy_mesh", "simulation", "orchestration", "intel_market"];
        this._SYS_LABELS = {
            defense_mesh:  "Defense Mesh",
            policy_mesh:   "Policy Mesh",
            simulation:    "Simulation",
            orchestration: "Orchestration",
            intel_market:  "Intel Market",
            conversion:    "Conversion",
        };
    }

    /* ------------------------------------------------------------------
     * Public: render
     * ------------------------------------------------------------------ */

    render() {
        this.wrapper.innerHTML = `
        <div class="fiq-flywheel" style="font-family:var(--font-stack,sans-serif);padding:16px;">
          <div class="fiq-fw-header" style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
            <div>
              <h2 style="margin:0;font-size:20px;font-weight:700;color:var(--heading-color,#111);">
                🔄 Security Intelligence Flywheel
              </h2>
              <p style="margin:4px 0 0;font-size:13px;color:#6b7280;">
                Self-reinforcing detection → defense → policy → simulation loop
              </p>
            </div>
            <div id="fiq-fw-refresh-badge" style="font-size:12px;color:#9ca3af;"></div>
          </div>

          <!-- Row 1: Health Ring + Alerts -->
          <div style="display:grid;grid-template-columns:1fr 320px;gap:16px;margin-bottom:16px;">
            <div id="fiq-fw-health" class="fiq-fw-card"></div>
            <div id="fiq-fw-alerts" class="fiq-fw-card"></div>
          </div>

          <!-- Row 2: Heatmap -->
          <div id="fiq-fw-heatmap" class="fiq-fw-card" style="margin-bottom:16px;"></div>

          <!-- Row 3: Timeline + Suggestions -->
          <div style="display:grid;grid-template-columns:1fr 360px;gap:16px;">
            <div id="fiq-fw-timeline" class="fiq-fw-card"></div>
            <div id="fiq-fw-suggestions" class="fiq-fw-card"></div>
          </div>
        </div>`;

        // Card base styles
        this.wrapper.querySelectorAll(".fiq-fw-card").forEach(el => {
            el.style.cssText += `
                background:var(--card-bg,#fff);border:1px solid var(--border-color,#e5e7eb);
                border-radius:12px;padding:20px;`;
        });

        this._load_all();
        this._refresh_timer = setInterval(() => this._load_all(), this._REFRESH_MS);
    }

    destroy() {
        clearInterval(this._refresh_timer);
    }

    /* ------------------------------------------------------------------
     * Data loading
     * ------------------------------------------------------------------ */

    _load_all() {
        const ts = new Date().toLocaleTimeString();
        const badge = this.wrapper.querySelector("#fiq-fw-refresh-badge");
        if (badge) badge.textContent = `Last refresh: ${ts}`;

        _api("orbweaver_frothiq.frothiq.api.flywheel_api.get_flywheel_state")
            .then(d => { this._state = d; this._plan = d.plan || "free"; this._render_health(d); })
            .catch(e => this._render_error("#fiq-fw-health", "System health unavailable"));

        _api("orbweaver_frothiq.frothiq.api.flywheel_api.get_system_reinforcement_map")
            .then(d => this._render_heatmap(d))
            .catch(e => this._render_error("#fiq-fw-heatmap", "Heatmap unavailable"));

        _api("orbweaver_frothiq.frothiq.api.flywheel_api.get_flywheel_events", { limit: 60 })
            .then(d => this._render_timeline(d))
            .catch(e => this._render_error("#fiq-fw-timeline", "Event timeline unavailable"));

        _api("orbweaver_frothiq.frothiq.api.flywheel_api.get_optimization_suggestions")
            .then(d => this._render_suggestions(d))
            .catch(e => this._render_error("#fiq-fw-suggestions", "Suggestions unavailable"));
    }

    /* ------------------------------------------------------------------
     * Section 1: System Health Ring
     * ------------------------------------------------------------------ */

    _render_health(data) {
        const el = this.wrapper.querySelector("#fiq-fw-health");
        if (!el) return;

        const health   = data.global_health_score;
        const momentum = data.system_momentum || {};
        const instab   = data.instability_index || 0;

        const health_color = _health_color(health);

        // Build 5 gauge bars for subsystems
        const gauges = this._SYSTEMS.map(sys => {
            const mom = momentum[sys] || 0.5;
            const pct  = Math.round(mom * 100);
            const col  = _momentum_color(mom);
            const label = this._SYS_LABELS[sys] || sys;
            return `
            <div style="margin-bottom:10px;">
              <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px;">
                <span style="color:var(--text-color,#374151);">${label}</span>
                <span style="font-weight:600;color:${col};">${pct}%</span>
              </div>
              <div style="background:#f3f4f6;border-radius:4px;height:8px;overflow:hidden;">
                <div style="width:${pct}%;height:100%;background:${col};border-radius:4px;
                            transition:width 0.4s ease;"></div>
              </div>
            </div>`;
        }).join("");

        el.innerHTML = `
        <div style="display:flex;align-items:center;gap:24px;">
          <!-- Global health dial -->
          <div style="text-align:center;min-width:100px;">
            <div style="font-size:40px;font-weight:800;color:${health_color};">
              ${health != null ? Math.round(health) : "—"}
            </div>
            <div style="font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.05em;">
              Global Health
            </div>
            <div style="margin-top:6px;">
              ${_badge(`Instability: ${Math.round(instab * 100)}%`, instab > 0.5 ? "#ef4444" : instab > 0.25 ? "#f59e0b" : "#6b7280")}
            </div>
          </div>
          <!-- Subsystem momentum bars -->
          <div style="flex:1;">
            <div style="font-size:13px;font-weight:600;color:#374151;margin-bottom:12px;">
              Subsystem Momentum
            </div>
            ${gauges}
          </div>
        </div>
        ${this._render_alerts_inline(data.drift_alerts || [])}`;
    }

    _render_alerts_inline(alerts) {
        if (!alerts.length) return "";
        const items = alerts.map(a => {
            const col = a.includes("critical") ? "#ef4444" : "#f59e0b";
            return `<li style="color:${col};margin-bottom:2px;">⚠ ${a.replace(/_/g, " ")}</li>`;
        }).join("");
        return `
        <div style="margin-top:16px;padding:10px 14px;background:#fef3c7;border-radius:8px;
                    border:1px solid #fbbf24;">
          <div style="font-size:12px;font-weight:700;color:#92400e;margin-bottom:6px;">DRIFT ALERTS</div>
          <ul style="margin:0;padding-left:16px;font-size:12px;">${items}</ul>
        </div>`;
    }

    /* ------------------------------------------------------------------
     * Section 2 (in alerts panel) — also rendered via health ring above
     * Note: separate alerts card shows per-system detail
     * ------------------------------------------------------------------ */

    _render_alerts_card(data) {
        const el = this.wrapper.querySelector("#fiq-fw-alerts");
        if (!el || !data) return;
        // Handled inline in _render_health; this card is a placeholder
    }

    /* ------------------------------------------------------------------
     * Section 2: Correlation Heatmap
     * ------------------------------------------------------------------ */

    _render_heatmap(data) {
        const el = this.wrapper.querySelector("#fiq-fw-heatmap");
        if (!el) return;

        // Upgrade gate
        if (data.access === "upgrade_required") {
            el.innerHTML = this._upgrade_prompt("Pro", "system correlation heatmap");
            return;
        }

        const hm       = data.heatmap || {};
        const systems  = hm.systems || this._SYSTEMS;
        const matrix   = hm.matrix || [];
        const triggers = hm.triggers || [];
        const bias_map = data.bias_map || {};

        // Build heatmap grid
        const cell_size = 52;
        const cols = systems.length;

        const header_cells = ["", ...systems.map(s =>
            `<th style="width:${cell_size}px;font-size:10px;font-weight:600;
                        color:#6b7280;text-align:center;padding:4px 2px;
                        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:${cell_size}px;">
              ${this._SYS_LABELS[s] || s}
            </th>`
        )].join("");

        const rows = systems.map((sys_a, i) => {
            const cells = systems.map((sys_b, j) => {
                const val = (matrix[i] || [])[j] || 0;
                const intensity = Math.abs(val);
                const hue = val >= 0 ? "34, 197, 94" : "239, 68, 68";  // green or red
                const bg  = `rgba(${hue}, ${Math.round(intensity * 0.7)})`;
                const text_col = intensity > 0.5 ? "#fff" : "#374151";
                return `<td style="width:${cell_size}px;height:${cell_size}px;text-align:center;
                                   background:${bg};color:${text_col};font-size:12px;font-weight:600;
                                   border:1px solid rgba(0,0,0,.06);border-radius:4px;">
                  ${val === 1 || val === 1.0 ? "—" : val.toFixed(2)}
                </td>`;
            }).join("");

            const bias = bias_map[sys_a];
            const bias_str = bias != null ? bias.toFixed(2) : "1.00";
            const bias_col = bias > 1.2 ? "#22c55e" : bias < 0.8 ? "#ef4444" : "#6b7280";

            return `<tr>
              <td style="font-size:11px;font-weight:600;color:#374151;padding:4px 10px 4px 0;
                         white-space:nowrap;">${this._SYS_LABELS[sys_a] || sys_a}
                <span style="font-size:10px;color:${bias_col};margin-left:4px;">×${bias_str}</span>
              </td>
              ${cells}
            </tr>`;
        }).join("");

        const trigger_html = triggers.length
            ? triggers.map(t => _badge(t.replace(/_/g, " "), "#3b82f6")).join(" ")
            : '<span style="color:#9ca3af;font-size:12px;">No active correlation triggers</span>';

        el.innerHTML = `
        <div style="font-size:13px;font-weight:700;color:#374151;margin-bottom:14px;">
          5×5 Cross-System Correlation Matrix
          <span style="font-size:11px;font-weight:400;color:#9ca3af;margin-left:8px;">
            (Pearson r over 7-day window)
          </span>
        </div>
        <div style="overflow-x:auto;">
          <table style="border-collapse:separate;border-spacing:3px;">
            <thead><tr>${header_cells}</tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <div style="margin-top:12px;font-size:12px;">
          <span style="font-weight:600;color:#374151;">Active Triggers: </span>
          ${trigger_html}
        </div>`;
    }

    /* ------------------------------------------------------------------
     * Section 3: Momentum Timeline
     * ------------------------------------------------------------------ */

    _render_timeline(data) {
        const el = this.wrapper.querySelector("#fiq-fw-timeline");
        if (!el) return;

        const events = data.events || [];
        const plan   = data.plan   || "free";
        const window_h = data.window_hours || 24;

        el.innerHTML = `
        <div style="font-size:13px;font-weight:700;color:#374151;margin-bottom:14px;">
          Signal Flow
          <span style="font-size:11px;font-weight:400;color:#9ca3af;margin-left:8px;">
            Last ${window_h}h • ${events.length} events
            ${plan === "free" ? ' • <span style="color:#f59e0b;">Pro: 7-day view</span>' : ""}
          </span>
        </div>
        <div id="fiq-fw-timeline-list" style="max-height:280px;overflow-y:auto;">
          ${this._render_event_list(events)}
        </div>`;
    }

    _render_event_list(events) {
        if (!events.length) {
            return `<div style="text-align:center;padding:40px;color:#9ca3af;font-size:13px;">
              No flywheel events recorded yet.<br>
              <small>Events appear as subsystems detect, respond, and evaluate threats.</small>
            </div>`;
        }
        return events.slice(0, 50).map(e => {
            const col  = _severity_color(e.severity);
            const sign = e.delta >= 0 ? "+" : "";
            const origin_label = this._SYS_LABELS[e.origin] || e.origin || "?";
            const ts   = e.ts ? new Date(e.ts * 1000).toLocaleTimeString() : "—";
            return `
            <div style="display:flex;align-items:center;gap:10px;padding:6px 0;
                        border-bottom:1px solid #f3f4f6;">
              <div style="width:8px;height:8px;border-radius:50%;background:${col};flex-shrink:0;"></div>
              <div style="flex:1;min-width:0;">
                <div style="font-size:12px;color:#111;font-weight:600;">
                  ${(e.type || "?").replace(/_/g, " ")}
                </div>
                <div style="font-size:11px;color:#6b7280;">${origin_label} · ${ts}</div>
              </div>
              <div style="font-size:12px;font-weight:700;color:${e.delta >= 0 ? "#22c55e" : "#ef4444"};
                          white-space:nowrap;">
                ${sign}${(e.delta || 0).toFixed(1)}
              </div>
              ${_badge(e.severity || "low", col)}
            </div>`;
        }).join("");
    }

    /* ------------------------------------------------------------------
     * Section 5: Optimization Suggestions
     * ------------------------------------------------------------------ */

    _render_suggestions(data) {
        const el = this.wrapper.querySelector("#fiq-fw-suggestions");
        if (!el) return;

        const sugs = data.suggestions || [];
        const plan = data.plan || "free";

        const priority_colors = {
            high: "#ef4444", medium: "#f59e0b", low: "#3b82f6", info: "#6b7280"
        };

        const items = sugs.map(s => {
            const col = priority_colors[s.priority] || "#6b7280";
            return `
            <div style="padding:10px 12px;background:${col}0d;border-left:3px solid ${col};
                        border-radius:0 8px 8px 0;margin-bottom:8px;">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
                ${_badge(s.priority.toUpperCase(), col)}
                <span style="font-size:11px;font-weight:600;color:#374151;">
                  ${this._SYS_LABELS[s.system] || s.system}
                </span>
              </div>
              <div style="font-size:12px;color:#374151;font-weight:600;margin-bottom:2px;">
                ${(s.action || "").replace(/_/g, " ")}
              </div>
              <div style="font-size:11px;color:#6b7280;">${s.reason || ""}</div>
            </div>`;
        }).join("");

        el.innerHTML = `
        <div style="font-size:13px;font-weight:700;color:#374151;margin-bottom:14px;">
          Optimization Suggestions
          ${plan === "free"
            ? '<span style="font-size:11px;font-weight:400;color:#f59e0b;margin-left:8px;">Pro: full list</span>'
            : ""}
        </div>
        <div>${items || '<p style="color:#9ca3af;font-size:13px;">All systems nominal.</p>'}</div>`;
    }

    /* ------------------------------------------------------------------
     * Helpers
     * ------------------------------------------------------------------ */

    _upgrade_prompt(plan_name, feature) {
        return `
        <div style="text-align:center;padding:40px 20px;">
          <div style="font-size:32px;margin-bottom:12px;">🔒</div>
          <div style="font-size:15px;font-weight:700;color:#374151;margin-bottom:6px;">
            ${plan_name} Feature
          </div>
          <div style="font-size:13px;color:#6b7280;margin-bottom:16px;">
            Upgrade to ${plan_name} to access the ${feature}.
          </div>
          <button onclick="frappe.set_route('Form', 'FrothIQ Tenant')"
                  style="padding:8px 20px;background:#4f8ef7;color:#fff;border:none;
                         border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;">
            Upgrade Plan
          </button>
        </div>`;
    }

    _render_error(selector, msg) {
        const el = this.wrapper.querySelector(selector);
        if (el) el.innerHTML = `
            <div style="color:#9ca3af;font-size:13px;text-align:center;padding:20px;">${msg}</div>`;
    }
}

// Export for use in page controllers
window.FrothIQFlywheelDashboard = FrothIQFlywheelDashboard;
