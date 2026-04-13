/**
 * FrothIQ Simulation Center — Desk UI Extension (Phase D4)
 *
 * Adds a "Simulation Center" page to the FrothIQ workspace accessible to
 * Enterprise plan tenants.  Free/Pro users see an upgrade prompt.
 *
 * Features
 * --------
 *   - Scenario list + one-click run button
 *   - Live run progress via frappe.realtime
 *   - Detection Accuracy Score (DAS) heatmap by scenario type
 *   - Defense Effectiveness Index (DEI) + Policy Precision Score (PPS) cards
 *   - False positive / false negative breakdown table
 *   - Recent threshold-breach alerts panel
 *   - Last nightly summary card
 *
 * Entry point: frappe.pages["frothiq-simulation"]
 */

frappe.pages["frothiq-simulation"] = frappe.pages["frothiq-simulation"] || {};

frappe.pages["frothiq-simulation"].on_page_load = function (wrapper) {
	const page = frappe.ui.make_app_page({
		parent: wrapper,
		title:  __("Simulation Center"),
		single_column: true,
	});

	const view = new FrothIQSimulationView(page);
	view.init();
};

// ---------------------------------------------------------------------------
// Main view class
// ---------------------------------------------------------------------------

class FrothIQSimulationView {
	constructor(page) {
		this.page      = page;
		this.$main     = $(page.main);
		this.scenarios = [];
		this.runs      = [];
		this._running  = false;
	}

	init() {
		this._render_skeleton();
		this._check_access();
		this._subscribe_realtime();
	}

	// ------------------------------------------------------------------
	// Access check
	// ------------------------------------------------------------------

	_check_access() {
		frappe.call({
			method: "orbweaver_frothiq.frothiq_portal.api.simulation_api.get_simulation_status",
			callback: (r) => {
				if (!r.exc && r.message) {
					if (r.message.is_enterprise) {
						this._render_dashboard(r.message);
					} else {
						this._render_upgrade_prompt(r.message.plan || "free");
					}
				} else {
					this._render_error("Could not load simulation status.");
				}
			},
		});
	}

	// ------------------------------------------------------------------
	// Skeleton
	// ------------------------------------------------------------------

	_render_skeleton() {
		this.$main.empty().html(`
			<div class="frothiq-sim-wrap" style="padding: 20px;">
				<div id="sim-loading" style="text-align:center; padding: 60px 0; color: #888;">
					<span class="fa fa-spinner fa-spin fa-2x"></span>
					<p style="margin-top: 12px;">${__("Loading Simulation Center…")}</p>
				</div>
				<div id="sim-content" style="display:none;"></div>
			</div>
		`);
	}

	_show_content() {
		this.$main.find("#sim-loading").hide();
		this.$main.find("#sim-content").show();
	}

	// ------------------------------------------------------------------
	// Upgrade prompt (non-enterprise)
	// ------------------------------------------------------------------

	_render_upgrade_prompt(plan) {
		const $c = this.$main.find("#sim-content");
		$c.html(`
			<div style="max-width: 560px; margin: 60px auto; text-align: center;">
				<div style="font-size: 48px; margin-bottom: 16px;">🛡️</div>
				<h3 style="color: #0f1629;">${__("Simulation Center")}</h3>
				<p style="color: #555; line-height: 1.6; margin: 16px 0 24px;">
					${__("Attack Simulation & Validation is an Enterprise feature. Simulate real attack patterns against your detection pipeline, measure accuracy, and run nightly regression checks — without touching production.")}
				</p>
				<div style="background: #f0f4ff; border: 1px solid #d0dbff; border-radius: 8px; padding: 20px; margin-bottom: 28px; text-align: left;">
					<strong style="color:#0f1629;">${__("Simulation Center includes:")}</strong>
					<ul style="margin: 12px 0 0 16px; color: #444; line-height: 2;">
						<li>${__("5 built-in attack scenario templates")}</li>
						<li>${__("Detection Accuracy Score (DAS) — F1-based, 0–100")}</li>
						<li>${__("Defense Effectiveness Index (DEI)")}</li>
						<li>${__("Policy Precision Score (PPS)")}</li>
						<li>${__("Nightly automated regression checks")}</li>
						<li>${__("30-day trend tracking & drift alerts")}</li>
					</ul>
				</div>
				<span style="display:inline-block; background: #4f8ef7; color: #fff; border-radius: 6px; padding: 10px 28px; font-weight: 600; cursor: default;">
					${__("Upgrade to Enterprise to unlock")}
				</span>
				<p style="margin-top: 16px; color: #888; font-size: 12px;">
					${__("Current plan:")} <strong>${frappe.utils.escape_html(plan)}</strong>
				</p>
			</div>
		`);
		this._show_content();
	}

	// ------------------------------------------------------------------
	// Main dashboard (enterprise)
	// ------------------------------------------------------------------

	_render_dashboard(status) {
		const $c = this.$main.find("#sim-content");
		$c.html(`
			<div style="display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px;">
				<div id="sim-summary-cards" style="flex: 1; min-width: 260px;"></div>
			</div>
			<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
				<div id="sim-scenario-panel" style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:20px;"></div>
				<div id="sim-runs-panel"     style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:20px;"></div>
			</div>
			<div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:20px; margin-bottom:20px;" id="sim-metrics-panel"></div>
			<div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:20px;" id="sim-alerts-panel"></div>
		`);
		this._show_content();

		this._render_summary_cards(status.last_nightly_summary);
		this._load_scenarios();
		this._load_recent_runs();
		this._load_metrics();
		this._load_alerts();
	}

	// ------------------------------------------------------------------
	// Summary cards
	// ------------------------------------------------------------------

	_render_summary_cards(nightly) {
		const $el = this.$main.find("#sim-summary-cards");
		if (!nightly || !nightly.overall_das) {
			$el.html(`<p style="color:#888; font-size:13px;">${__("No nightly run data yet. Runs occur automatically each night or can be triggered manually.")}</p>`);
			return;
		}

		const das = nightly.overall_das || 0;
		const dei = nightly.overall_dei || 0;
		const pps = nightly.overall_pps || 0;
		const alerts = nightly.total_alerts || 0;

		$el.html(`
			<div style="display:flex; gap:12px; flex-wrap:wrap;">
				${this._metric_card("DAS", das, "Detection Accuracy", "#4f8ef7")}
				${this._metric_card("DEI", dei, "Defense Effectiveness", "#0ea5e9")}
				${this._metric_card("PPS", pps, "Policy Precision", "#7c3aed")}
				${this._metric_card("⚠️", alerts, "Active Alerts", alerts > 0 ? "#ef4444" : "#22c55e", true)}
			</div>
			<p style="color:#888; font-size:11px; margin-top:8px;">
				${__("Last nightly run:")} ${nightly.ts ? frappe.datetime.str_to_user(new Date(nightly.ts * 1000).toISOString()) : "—"}
				&nbsp;·&nbsp; ${nightly.scenarios_run || 0} ${__("scenarios")}
			</p>
		`);
	}

	_metric_card(label, value, subtitle, color, is_count = false) {
		const display = is_count ? value : `${Number(value).toFixed(1)}`;
		const badge_color = is_count ? color : (value >= 70 ? "#22c55e" : value >= 50 ? "#f59e0b" : "#ef4444");
		return `
			<div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px; min-width:120px; text-align:center;">
				<div style="font-size:28px; font-weight:700; color:${badge_color};">${display}</div>
				<div style="font-size:12px; font-weight:600; color:${color}; margin:2px 0;">${label}</div>
				<div style="font-size:11px; color:#888;">${subtitle}</div>
			</div>
		`;
	}

	// ------------------------------------------------------------------
	// Scenario panel
	// ------------------------------------------------------------------

	_load_scenarios() {
		frappe.call({
			method: "orbweaver_frothiq.frothiq_portal.api.simulation_api.get_simulation_scenarios",
			callback: (r) => {
				if (!r.exc && r.message && r.message.scenarios) {
					this.scenarios = r.message.scenarios;
					this._render_scenario_panel();
				}
			},
		});
	}

	_render_scenario_panel() {
		const $el = this.$main.find("#sim-scenario-panel");
		$el.html(`
			<h5 style="margin:0 0 14px; color:#0f1629;">${__("Run a Simulation")}</h5>
			<div style="margin-bottom:12px;">
				<label style="font-size:12px; color:#555;">${__("Scenario")}</label>
				<select id="sim-scenario-select" class="form-control form-control-sm" style="margin-top:4px;">
					${this.scenarios.map(s => `<option value="${s.name}">${frappe.utils.escape_html(s.name)} — ${frappe.utils.escape_html(s.description || s.scenario_type)}</option>`).join("")}
				</select>
			</div>
			<div style="margin-bottom:12px; display:flex; gap:12px; align-items:center;">
				<label style="font-size:12px; color:#555; margin:0;">
					<input type="checkbox" id="sim-use-replay"> ${__("Replay from live correlator")}
				</label>
				<label style="font-size:12px; color:#555; margin:0;">
					${__("Campaigns:")} <input type="number" id="sim-count" value="5" min="1" max="20" style="width:50px; margin-left:4px;" class="form-control form-control-sm d-inline-block">
				</label>
			</div>
			<button id="sim-run-btn" class="btn btn-primary btn-sm">${__("▶ Run Simulation")}</button>
			<div id="sim-run-status" style="margin-top:12px; font-size:12px;"></div>
		`);

		$el.find("#sim-run-btn").on("click", () => this._trigger_run());
	}

	_trigger_run() {
		if (this._running) return;
		const scenario = this.$main.find("#sim-scenario-select").val();
		const use_replay = this.$main.find("#sim-use-replay").is(":checked");
		const count = parseInt(this.$main.find("#sim-count").val()) || 5;

		const $btn = this.$main.find("#sim-run-btn");
		const $status = this.$main.find("#sim-run-status");

		this._running = true;
		$btn.prop("disabled", true).text(__("Running…"));
		$status.html(`<span style="color:#f59e0b;">⏳ ${__("Simulation in progress…")}</span>`);

		frappe.call({
			method:  "orbweaver_frothiq.frothiq_portal.api.simulation_api.run_simulation",
			args:    { scenario_name: scenario, use_replay, synthetic_count: count },
			callback: (r) => {
				this._running = false;
				$btn.prop("disabled", false).text(__("▶ Run Simulation"));

				if (r.exc) {
					$status.html(`<span style="color:#ef4444;">✗ ${__("Simulation failed")}: ${frappe.utils.escape_html(r.exc)}</span>`);
					return;
				}
				const m = r.message;
				const alert_html = m.alerts && m.alerts.length
					? `<br>⚠ ${frappe.utils.escape_html(m.alerts.join(", "))}`
					: "";
				$status.html(`
					<span style="color:#22c55e;">✓ ${__("Complete")}</span>
					— DAS: <strong>${(m.das || 0).toFixed(1)}</strong>
					&nbsp;DEI: <strong>${(m.dei || 0).toFixed(1)}</strong>
					&nbsp;PPS: <strong>${(m.pps || 0).toFixed(1)}</strong>
					${alert_html}
				`);
				// Refresh runs panel
				this._load_recent_runs();
			},
		});
	}

	// ------------------------------------------------------------------
	// Recent runs panel
	// ------------------------------------------------------------------

	_load_recent_runs() {
		frappe.call({
			method:  "orbweaver_frothiq.frothiq_portal.api.simulation_api.get_simulation_runs",
			args:    { limit: 10 },
			callback: (r) => {
				if (!r.exc && r.message) {
					this.runs = r.message.runs || [];
					this._render_runs_panel();
				}
			},
		});
	}

	_render_runs_panel() {
		const $el = this.$main.find("#sim-runs-panel");
		$el.html(`<h5 style="margin:0 0 14px; color:#0f1629;">${__("Recent Runs")}</h5>`);

		if (!this.runs.length) {
			$el.append(`<p style="color:#888; font-size:13px;">${__("No runs yet.")}</p>`);
			return;
		}

		const rows = this.runs.map(r => {
			const ts = r.ts ? new Date(r.ts * 1000).toLocaleString() : "—";
			const das_color = r.das >= 70 ? "#22c55e" : r.das >= 50 ? "#f59e0b" : "#ef4444";
			const alerts = (r.alerts || []).length;
			return `
				<tr>
					<td style="font-size:11px; color:#555;">${frappe.utils.escape_html(r.scenario_name || r.scenario_type || "—")}</td>
					<td style="color:${das_color}; font-weight:600;">${(r.das||0).toFixed(1)}</td>
					<td>${(r.dei||0).toFixed(1)}</td>
					<td>${(r.pps||0).toFixed(1)}</td>
					<td>${alerts > 0 ? `<span style="color:#ef4444;">⚠ ${alerts}</span>` : "✓"}</td>
					<td style="font-size:10px; color:#888;">${ts}</td>
				</tr>
			`;
		}).join("");

		$el.append(`
			<table class="table table-sm" style="font-size:12px;">
				<thead><tr>
					<th>${__("Scenario")}</th>
					<th>DAS</th><th>DEI</th><th>PPS</th>
					<th>${__("Alerts")}</th>
					<th>${__("Time")}</th>
				</tr></thead>
				<tbody>${rows}</tbody>
			</table>
		`);
	}

	// ------------------------------------------------------------------
	// Metrics panel
	// ------------------------------------------------------------------

	_load_metrics() {
		frappe.call({
			method:   "orbweaver_frothiq.frothiq_portal.api.simulation_api.get_simulation_metrics",
			callback: (r) => {
				if (!r.exc && r.message) {
					this._render_metrics_panel(r.message);
				}
			},
		});
	}

	_render_metrics_panel(data) {
		const $el = this.$main.find("#sim-metrics-panel");
		$el.html(`<h5 style="margin:0 0 14px; color:#0f1629;">${__("30-Day Accuracy Trends by Scenario")}</h5>`);

		const by_scenario = data.by_scenario || {};
		const keys = Object.keys(by_scenario);

		if (!keys.length) {
			$el.append(`<p style="color:#888; font-size:13px;">${__("No historical data yet.")}</p>`);
			return;
		}

		const rows = keys.map(k => {
			const sc = by_scenario[k];
			const das = sc.avg_das != null ? sc.avg_das.toFixed(1) : "—";
			const dei = sc.avg_dei != null ? sc.avg_dei.toFixed(1) : "—";
			const pps = sc.avg_pps != null ? sc.avg_pps.toFixed(1) : "—";
			const trend = sc.trend_das != null
				? (sc.trend_das > 0 ? `<span style="color:#22c55e;">↑ ${sc.trend_das.toFixed(1)}</span>`
				:  sc.trend_das < 0 ? `<span style="color:#ef4444;">↓ ${Math.abs(sc.trend_das).toFixed(1)}</span>`
				: "→")
				: "—";
			const runs = (sc.runs || []).length;
			return `
				<tr>
					<td><code style="font-size:11px;">${frappe.utils.escape_html(k)}</code></td>
					<td style="font-weight:600;">${das}</td>
					<td>${dei}</td>
					<td>${pps}</td>
					<td>${trend}</td>
					<td style="color:#888;">${runs}</td>
				</tr>
			`;
		}).join("");

		$el.append(`
			<table class="table table-sm" style="font-size:12px;">
				<thead><tr>
					<th>${__("Scenario Type")}</th>
					<th>${__("Avg DAS")}</th>
					<th>${__("Avg DEI")}</th>
					<th>${__("Avg PPS")}</th>
					<th>${__("DAS Trend")}</th>
					<th>${__("Runs")}</th>
				</tr></thead>
				<tbody>${rows}</tbody>
			</table>
			<p style="font-size:11px; color:#888; margin-top:4px;">
				${__("Trend = slope of last 5 DAS values. ↑ improving, ↓ degrading.")}
			</p>
		`);
	}

	// ------------------------------------------------------------------
	// Alerts panel
	// ------------------------------------------------------------------

	_load_alerts() {
		frappe.call({
			method:   "orbweaver_frothiq.frothiq_portal.api.simulation_api.get_simulation_alerts",
			args:     { limit: 10 },
			callback: (r) => {
				if (!r.exc && r.message) {
					this._render_alerts_panel(r.message.alerts || []);
				}
			},
		});
	}

	_render_alerts_panel(alerts) {
		const $el = this.$main.find("#sim-alerts-panel");
		$el.html(`<h5 style="margin:0 0 14px; color:#0f1629;">${__("Recent Threshold Alerts")}</h5>`);

		if (!alerts.length) {
			$el.append(`<p style="color:#22c55e; font-size:13px;">✓ ${__("No threshold breaches in recent runs.")}</p>`);
			return;
		}

		const rows = alerts.map(a => {
			const ts = a.ts ? new Date(a.ts * 1000).toLocaleString() : "—";
			const types = (a.alerts || []).map(al =>
				`<span style="background:#fee2e2; color:#b91c1c; border-radius:4px; padding:1px 6px; font-size:10px; margin-right:4px;">${frappe.utils.escape_html(al)}</span>`
			).join("");
			return `
				<tr>
					<td style="font-size:11px;">${frappe.utils.escape_html(a.scenario_type || "—")}</td>
					<td>${types}</td>
					<td style="font-size:10px; color:#888;">${ts}</td>
				</tr>
			`;
		}).join("");

		$el.append(`
			<table class="table table-sm" style="font-size:12px;">
				<thead><tr>
					<th>${__("Scenario")}</th>
					<th>${__("Alerts")}</th>
					<th>${__("Time")}</th>
				</tr></thead>
				<tbody>${rows}</tbody>
			</table>
		`);
	}

	// ------------------------------------------------------------------
	// Realtime
	// ------------------------------------------------------------------

	_subscribe_realtime() {
		frappe.realtime.on("frothiq_simulation_complete", (data) => {
			frappe.show_alert({
				message: __("Simulation complete — DAS: {0}, DEI: {1}, PPS: {2}", [
					(data.das || 0).toFixed(1),
					(data.dei || 0).toFixed(1),
					(data.pps || 0).toFixed(1),
				]),
				indicator: data.alerts && data.alerts.length ? "orange" : "green",
			}, 7);
		});
	}

	_render_error(msg) {
		this.$main.find("#sim-content").html(
			`<p style="color:#ef4444; padding:20px;">${frappe.utils.escape_html(msg)}</p>`
		);
		this._show_content();
	}
}
