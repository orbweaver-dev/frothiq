/**
 * FrothIQ Command Center
 *
 * Six sections (tabs):
 *   1. Overview       — stat cards + quick metrics
 *   2. Live Feed      — real-time request stream (Socket.IO + 5s poll)
 *   3. IP Intel       — search + full IP dossier
 *   4. Campaigns      — active campaign list + expand
 *   5. Response       — active blocks + timeline + manual controls
 *   6. System Health  — core health, CSF, versions, uptime
 */

// ─────────────────────────────────────────────────────────────────────────────
// Page entry points
// ─────────────────────────────────────────────────────────────────────────────

frappe.pages["frothiq-command-center"].on_page_load = function (wrapper) {
	frappe.ui.make_app_page({
		parent: wrapper,
		title: "FrothIQ Command Center",
		single_column: true,
	});
	_inject_css(wrapper);
	wrapper.cc = new FrothIQCommandCenter(wrapper);
};

frappe.pages["frothiq-command-center"].on_page_show = function (wrapper) {
	if (wrapper.cc) wrapper.cc.on_show();
};

frappe.pages["frothiq-command-center"].on_page_hide = function (wrapper) {
	if (wrapper.cc) wrapper.cc.on_hide();
};

// ─────────────────────────────────────────────────────────────────────────────
// CSS
// ─────────────────────────────────────────────────────────────────────────────

function _inject_css(wrapper) {
	if (document.getElementById("fiq-cc-css")) return;
	const style = document.createElement("style");
	style.id = "fiq-cc-css";
	style.textContent = `
/* ── Layout ── */
.fiq-cc { font-family: var(--font-stack); padding: 0 0 40px; background: var(--bg-color); }

/* ── Tab bar ── */
.fiq-tabs { display: flex; gap: 2px; border-bottom: 2px solid var(--border-color); margin-bottom: 20px; padding-top: 10px; }
.fiq-tab { padding: 8px 18px; font-size: 0.85rem; font-weight: 500; cursor: pointer;
  border: none; background: transparent; color: var(--text-muted); border-bottom: 3px solid transparent;
  margin-bottom: -2px; border-radius: 4px 4px 0 0; transition: color .15s, border-color .15s; }
.fiq-tab:hover { color: var(--text-color); }
.fiq-tab.active { color: var(--primary); border-bottom-color: var(--primary); }

/* ── Section panels ── */
.fiq-section { display: none; }
.fiq-section.active { display: block; }

/* ── Stat cards ── */
.fiq-stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 20px; }
@media (max-width: 1100px) { .fiq-stats { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 650px)  { .fiq-stats { grid-template-columns: 1fr; } }
.fiq-stat { background: var(--card-bg); border: 1px solid var(--border-color);
  border-radius: 10px; padding: 18px 20px; position: relative; overflow: hidden; }
.fiq-stat::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--primary); }
.fiq-stat.danger::before { background: #ef4444; }
.fiq-stat.warning::before { background: #f59e0b; }
.fiq-stat.success::before { background: #22c55e; }
.fiq-stat-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: .05em; }
.fiq-stat-value { font-size: 2rem; font-weight: 700; color: var(--heading-color); line-height: 1.2; margin: 4px 0 2px; }
.fiq-stat-sub { font-size: 0.78rem; color: var(--text-muted); }

/* ── Section toolbar ── */
.fiq-toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 14px; }
.fiq-toolbar .fiq-title { font-size: 1rem; font-weight: 600; color: var(--heading-color); flex: 1; }
.fiq-btn { height: 30px; padding: 0 14px; border-radius: 6px; border: 1px solid var(--border-color);
  background: var(--control-bg); color: var(--text-color); font-size: 0.82rem; cursor: pointer; }
.fiq-btn.primary { background: var(--primary); color: #fff; border-color: var(--primary); font-weight: 500; }
.fiq-btn.danger  { background: #ef4444;          color: #fff; border-color: #ef4444; }
.fiq-btn.success { background: #22c55e;          color: #fff; border-color: #22c55e; }
.fiq-btn:disabled { opacity: .5; cursor: not-allowed; }

/* ── Live dot ── */
.fiq-dot { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; display: inline-block;
  margin-right: 5px; animation: fiq-pulse 1.8s infinite; }
.fiq-dot.red { background: #ef4444; }
@keyframes fiq-pulse { 0%,100%{opacity:1} 50%{opacity:.2} }

/* ── Tables ── */
.fiq-table-wrap { overflow-x: auto; border: 1px solid var(--border-color); border-radius: 8px; }
.fiq-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
.fiq-table th { background: var(--subtle-fg); color: var(--text-muted); font-weight: 600;
  padding: 9px 12px; text-align: left; border-bottom: 1px solid var(--border-color); }
.fiq-table td { padding: 8px 12px; border-bottom: 1px solid var(--border-color); color: var(--text-color); vertical-align: middle; }
.fiq-table tr:last-child td { border-bottom: none; }
.fiq-table tr:hover td { background: var(--subtle-fg); }
.fiq-table tr.clickable { cursor: pointer; }

/* ── Badges / severity chips ── */
.fiq-badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.72rem; font-weight: 600; }
.fiq-badge.critical { background: #fef2f2; color: #dc2626; }
.fiq-badge.high     { background: #fff7ed; color: #d97706; }
.fiq-badge.medium   { background: #fefce8; color: #ca8a04; }
.fiq-badge.low      { background: #f0fdf4; color: #16a34a; }
.fiq-badge.info     { background: #eff6ff; color: #2563eb; }
.fiq-badge.blocked  { background: #fef2f2; color: #dc2626; }
.fiq-badge.active   { background: #f0fdf4; color: #16a34a; }
.fiq-badge.observe  { background: #eff6ff; color: #2563eb; }

/* ── IP Intel ── */
.fiq-search-bar { display: flex; gap: 8px; margin-bottom: 16px; }
.fiq-search-bar input { flex: 1; height: 34px; border-radius: 6px; border: 1px solid var(--border-color);
  background: var(--control-bg); color: var(--text-color); padding: 0 12px; font-size: 0.85rem; }
.fiq-intel-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media (max-width: 900px) { .fiq-intel-grid { grid-template-columns: 1fr; } }

/* ── Cards ── */
.fiq-card { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 10px;
  padding: 16px 18px; margin-bottom: 14px; }
.fiq-card-title { font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: .06em;
  color: var(--text-muted); margin-bottom: 10px; }
.fiq-kv { display: flex; justify-content: space-between; padding: 4px 0;
  border-bottom: 1px solid var(--border-color); font-size: 0.82rem; }
.fiq-kv:last-child { border-bottom: none; }
.fiq-kv-key { color: var(--text-muted); }
.fiq-kv-val { color: var(--text-color); font-weight: 500; text-align: right; max-width: 60%; word-break: break-all; }

/* ── Campaign rows ── */
.fiq-camp-row { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px;
  margin-bottom: 8px; }
.fiq-camp-header { display: flex; align-items: center; gap: 10px; padding: 12px 16px; cursor: pointer; }
.fiq-camp-type { font-weight: 600; font-size: 0.85rem; color: var(--heading-color); flex: 1; }
.fiq-camp-meta { font-size: 0.78rem; color: var(--text-muted); }
.fiq-camp-body { display: none; padding: 0 16px 14px; border-top: 1px solid var(--border-color); }
.fiq-camp-body.open { display: block; }

/* ── Block rows ── */
.fiq-block-row { display: flex; align-items: center; gap: 10px; padding: 10px 14px;
  background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 6px; }
.fiq-block-ip { font-weight: 600; font-size: 0.88rem; color: var(--heading-color); flex: 1; }
.fiq-block-ttl { font-size: 0.78rem; color: var(--text-muted); }
.fiq-block-reason { font-size: 0.78rem; color: var(--text-muted); max-width: 35%; overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap; }

/* ── Health items ── */
.fiq-health-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
@media (max-width: 900px) { .fiq-health-grid { grid-template-columns: 1fr 1fr; } }
.fiq-health-item { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 10px;
  padding: 16px 18px; text-align: center; }
.fiq-health-icon { font-size: 1.6rem; margin-bottom: 6px; }
.fiq-health-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: .05em; }
.fiq-health-value { font-size: 1rem; font-weight: 700; color: var(--heading-color); margin-top: 2px; }
.fiq-health-ok    { color: #22c55e; }
.fiq-health-warn  { color: #f59e0b; }
.fiq-health-err   { color: #ef4444; }

/* ── Placeholder / empty ── */
.fiq-empty { text-align: center; color: var(--text-muted); padding: 32px; font-size: 0.88rem; }

/* ── Modal overlay ── */
.fiq-modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.45); z-index: 1000;
  display: flex; align-items: center; justify-content: center; }
.fiq-modal { background: var(--card-bg); border-radius: 12px; border: 1px solid var(--border-color);
  max-width: 620px; width: 95%; max-height: 80vh; overflow-y: auto; padding: 24px; position: relative; }
.fiq-modal-close { position: absolute; top: 14px; right: 16px; background: none; border: none;
  font-size: 1.2rem; cursor: pointer; color: var(--text-muted); }

/* ── Select / hours filter ── */
.fiq-select { height: 30px; border-radius: 6px; border: 1px solid var(--border-color);
  background: var(--control-bg); color: var(--text-color); padding: 0 8px; font-size: 0.82rem; }

/* ── Score bar ── */
.fiq-score-bar { height: 6px; border-radius: 3px; background: var(--border-color); overflow: hidden; margin-top: 4px; }
.fiq-score-fill { height: 100%; border-radius: 3px; background: var(--primary); transition: width .4s; }
.fiq-score-fill.danger { background: #ef4444; }
.fiq-score-fill.warning { background: #f59e0b; }
`;
	document.head.appendChild(style);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function _severity(score) {
	if (score >= 80) return "critical";
	if (score >= 60) return "high";
	if (score >= 40) return "medium";
	return "low";
}

function _score_color(score) {
	if (score >= 80) return "danger";
	if (score >= 50) return "warning";
	return "";
}

function _strategy_badge(s) {
	const map = {
		observe: "observe", soft_rate_limit: "low", hard_rate_limit: "medium",
		temporary_block: "high", permanent_block: "critical", escalate_to_dashboard: "info",
	};
	return `<span class="fiq-badge ${map[s] || "info"}">${s || "—"}</span>`;
}

function _fmt_ts(ts) {
	if (!ts) return "—";
	if (typeof ts === "number") return new Date(ts * 1000).toLocaleString();
	return frappe.datetime.str_to_user(ts);
}

function _ttl(expires_at) {
	if (!expires_at) return "permanent";
	const rem = Math.round(expires_at - Date.now() / 1000);
	if (rem <= 0) return "expired";
	const m = Math.floor(rem / 60), s = rem % 60;
	return `${m}m ${s}s`;
}

function _call(method, args, cb) {
	frappe.call({
		method: `orbweaver_frothiq.frothiq.api.command_center_api.${method}`,
		args: args || {},
		callback: (r) => cb(r && r.message),
	});
}

function _is_admin() {
	return (frappe.user_roles || []).some(r => r === "FrothIQ Admin" || r === "System Manager");
}

// ─────────────────────────────────────────────────────────────────────────────
// Main controller class
// ─────────────────────────────────────────────────────────────────────────────

class FrothIQCommandCenter {
	constructor(wrapper) {
		this.wrapper = wrapper;
		this.$page = $(wrapper).find(".page-content");
		this._poll_timer = null;
		this._feed_latest = null;
		this._active_tab = "overview";
		this._tabs = {};
		this._sections = {};
		this._render();
		this._setup_realtime();
	}

	// ── Render shell ──────────────────────────────────────────────────────────

	_render() {
		const tabs = [
			{ id: "overview",  label: "Overview" },
			{ id: "feed",      label: "Live Feed" },
			{ id: "ip",        label: "IP Intel" },
			{ id: "campaigns", label: "Campaigns" },
			{ id: "response",  label: "Response Engine" },
			{ id: "agents",    label: "Agents" },
			{ id: "health",    label: "System Health" },
		];

		const $root = $(`<div class="fiq-cc"></div>`);

		// Tab bar
		const $tabbar = $(`<div class="fiq-tabs"></div>`);
		tabs.forEach(t => {
			const $tab = $(`<button class="fiq-tab" data-tab="${t.id}">${t.label}</button>`);
			$tab.on("click", () => this._switch_tab(t.id));
			this._tabs[t.id] = $tab;
			$tabbar.append($tab);
		});
		$root.append($tabbar);

		// Sections
		tabs.forEach(t => {
			const $s = $(`<div class="fiq-section" data-section="${t.id}"></div>`);
			this._sections[t.id] = $s;
			$root.append($s);
		});

		this.$page.empty().append($root);
		this._switch_tab("overview");
	}

	_switch_tab(id) {
		this._active_tab = id;
		Object.values(this._tabs).forEach($t => $t.removeClass("active"));
		Object.values(this._sections).forEach($s => $s.removeClass("active"));
		this._tabs[id].addClass("active");
		this._sections[id].addClass("active");
		this._load_section(id);
	}

	_load_section(id) {
		const fn = {
			overview:  () => this._render_overview(),
			feed:      () => this._render_feed(),
			ip:        () => this._render_ip(),
			campaigns: () => this._render_campaigns(),
			response:  () => this._render_response(),
			agents:    () => this._render_agents(),
			health:    () => this._render_health(),
		}[id];
		if (fn) fn();
	}

	// ── Page lifecycle ────────────────────────────────────────────────────────

	on_show() {
		this._load_section(this._active_tab);
		this._start_poll();
	}

	on_hide() {
		this._stop_poll();
	}

	refresh() {
		this._load_section(this._active_tab);
	}

	_start_poll() {
		this._stop_poll();
		this._poll_timer = setInterval(() => {
			if (this._active_tab === "feed")    this._poll_feed();
			if (this._active_tab === "overview") this._poll_overview();
			if (this._active_tab === "agents")   this._load_agents();
		}, 10000);
	}

	_stop_poll() {
		if (this._poll_timer) { clearInterval(this._poll_timer); this._poll_timer = null; }
	}

	// ── Real-time ─────────────────────────────────────────────────────────────

	_setup_realtime() {
		frappe.realtime.on("frothiq_new_log", (msg) => {
			if (this._active_tab === "feed") this._prepend_feed_row(msg);
		});
		frappe.realtime.on("frothiq_block_action", (msg) => {
			if (this._active_tab === "response") this._render_response();
			frappe.show_alert({
				message: `Block action: ${msg.strategy} → ${msg.ip}`,
				indicator: msg.strategy.includes("block") ? "red" : "blue",
			}, 5);
		});
		frappe.realtime.on("frothiq_campaign_update", (msg) => {
			if (this._active_tab === "campaigns") this._render_campaigns();
		});
		frappe.realtime.on("frothiq_agent_update", (msg) => {
			if (this._active_tab === "agents") this._load_agents();
			frappe.show_alert({
				message: `Agent ${msg.agent_type}: ${msg.agent_id} → ${msg.status}`,
				indicator: msg.status === "online" ? "green" : "orange",
			}, 4);
		});
	}

	// =========================================================================
	// SECTION 1 — Overview
	// =========================================================================

	_render_overview() {
		const $s = this._sections.overview;
		$s.html(`<div class="fiq-toolbar">
			<span class="fiq-title"><span class="fiq-dot"></span>Overview</span>
			<select class="fiq-select" id="fiq-hours-sel">
				<option value="1">Last 1 hour</option>
				<option value="6">Last 6 hours</option>
				<option value="24" selected>Last 24 hours</option>
				<option value="72">Last 3 days</option>
			</select>
			<button class="fiq-btn primary" id="fiq-ov-refresh">Refresh</button>
		</div>
		<div class="fiq-stats" id="fiq-stat-cards">
			${this._stat_skeleton(6)}
		</div>
		<div id="fiq-ov-extra"></div>`);

		$s.find("#fiq-ov-refresh").on("click", () => this._poll_overview());
		$s.find("#fiq-hours-sel").on("change", () => this._poll_overview());
		this._poll_overview();
	}

	_stat_skeleton(n) {
		return Array(n).fill(0).map(() =>
			`<div class="fiq-stat"><div class="fiq-stat-label">Loading…</div><div class="fiq-stat-value">—</div></div>`
		).join("");
	}

	_poll_overview() {
		const $s = this._sections.overview;
		if (!$s.hasClass("active")) return;
		const hours = $s.find("#fiq-hours-sel").val() || 24;
		_call("get_overview_stats", { hours }, (data) => {
			if (!data) return;
			const core_ok = data.core_status === "ok" || data.core_status === "healthy";

			$s.find("#fiq-stat-cards").html(`
				<div class="fiq-stat">
					<div class="fiq-stat-label">Total Requests</div>
					<div class="fiq-stat-value">${(data.total_requests || 0).toLocaleString()}</div>
					<div class="fiq-stat-sub">Last ${hours}h</div>
				</div>
				<div class="fiq-stat danger">
					<div class="fiq-stat-label">Blocked</div>
					<div class="fiq-stat-value">${(data.blocked_count || 0).toLocaleString()}</div>
					<div class="fiq-stat-sub">Active blocks: ${data.active_blocks || 0}</div>
				</div>
				<div class="fiq-stat">
					<div class="fiq-stat-label">Unique IPs</div>
					<div class="fiq-stat-value">${(data.unique_ips || 0).toLocaleString()}</div>
					<div class="fiq-stat-sub">Distinct sources</div>
				</div>
				<div class="fiq-stat warning">
					<div class="fiq-stat-label">Active Campaigns</div>
					<div class="fiq-stat-value">${data.active_campaigns || 0}</div>
					<div class="fiq-stat-sub">Coordinated attacks</div>
				</div>
				<div class="fiq-stat">
					<div class="fiq-stat-label">Top Offender</div>
					<div class="fiq-stat-value" style="font-size:1.1rem">${data.top_offender?.ip_address || "—"}</div>
					<div class="fiq-stat-sub">Score: ${data.top_offender?.top_score || 0}</div>
				</div>
				<div class="fiq-stat ${core_ok ? 'success' : 'danger'}">
					<div class="fiq-stat-label">Core Status</div>
					<div class="fiq-stat-value" style="font-size:1.1rem">${data.core_status || "unknown"}</div>
					<div class="fiq-stat-sub">frothiq-core engine</div>
				</div>
			`);
		});
	}

	// =========================================================================
	// SECTION 2 — Live Feed
	// =========================================================================

	_render_feed() {
		const $s = this._sections.feed;
		$s.html(`<div class="fiq-toolbar">
			<span class="fiq-title"><span class="fiq-dot"></span>Live Threat Feed</span>
			<button class="fiq-btn primary" id="fiq-feed-refresh">Refresh</button>
			<button class="fiq-btn" id="fiq-feed-pause">Pause</button>
		</div>
		<div class="fiq-table-wrap">
			<table class="fiq-table">
				<thead><tr>
					<th>Time</th><th>IP</th><th>Score</th><th>Status</th>
					<th>Type</th><th>Method</th><th>Path</th><th>Reason</th>
				</tr></thead>
				<tbody id="fiq-feed-body"></tbody>
			</table>
		</div>`);

		this._feed_paused = false;
		$s.find("#fiq-feed-refresh").on("click", () => this._load_feed_full());
		$s.find("#fiq-feed-pause").on("click", (e) => {
			this._feed_paused = !this._feed_paused;
			$(e.currentTarget).text(this._feed_paused ? "Resume" : "Pause");
		});
		this._load_feed_full();
	}

	_load_feed_full() {
		_call("get_live_feed", { limit: 80 }, (rows) => {
			if (!rows || !rows.length) {
				this._sections.feed.find("#fiq-feed-body").html(
					`<tr><td colspan="8" class="fiq-empty">No log entries yet.</td></tr>`
				);
				return;
			}
			this._feed_latest = rows[0]?.name;
			this._sections.feed.find("#fiq-feed-body").html(
				rows.map(r => this._feed_row_html(r)).join("")
			);
			this._bind_feed_clicks();
		});
	}

	_poll_feed() {
		if (this._feed_paused) return;
		if (!this._sections.feed.hasClass("active")) return;
		_call("get_live_feed", { limit: 30, after_name: this._feed_latest }, (rows) => {
			if (!rows || !rows.length) return;
			this._feed_latest = rows[0]?.name;
			rows.reverse().forEach(r => this._prepend_feed_row(r));
		});
	}

	_prepend_feed_row(r) {
		if (this._feed_paused) return;
		const $body = this._sections.feed.find("#fiq-feed-body");
		const $placeholder = $body.find("td[colspan]");
		if ($placeholder.length) $body.empty();
		$body.prepend(this._feed_row_html(r));
		this._bind_feed_clicks();
		// trim to 200 rows
		const rows = $body.find("tr");
		if (rows.length > 200) rows.slice(200).remove();
	}

	_feed_row_html(r) {
		const sev = r.severity || _severity(r.threat_score || 0);
		const blocked_badge = r.blocked
			? `<span class="fiq-badge blocked">BLOCKED</span>`
			: `<span class="fiq-badge observe">allowed</span>`;
		return `<tr class="clickable" data-name="${r.name}">
			<td style="white-space:nowrap;font-size:.76rem">${frappe.datetime.str_to_user(r.creation)}</td>
			<td><code style="font-size:.8rem">${r.ip_address || "—"}</code></td>
			<td>
				<strong style="color:${r.threat_score>=80?'#ef4444':r.threat_score>=50?'#d97706':'inherit'}">${r.threat_score || 0}</strong>
				<div class="fiq-score-bar"><div class="fiq-score-fill ${_score_color(r.threat_score||0)}" style="width:${Math.min(r.threat_score||0,100)}%"></div></div>
			</td>
			<td>${blocked_badge}</td>
			<td><span class="fiq-badge ${sev}">${r.event_type || "—"}</span></td>
			<td style="font-size:.78rem">${r.request_method || "—"}</td>
			<td style="font-size:.76rem;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${r.request_path || ""}">${r.request_path || "—"}</td>
			<td style="font-size:.76rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${r.reason || ""}">${r.reason || "—"}</td>
		</tr>`;
	}

	_bind_feed_clicks() {
		this._sections.feed.find("tr.clickable").off("click").on("click", (e) => {
			const name = $(e.currentTarget).data("name");
			this._show_log_modal(name);
		});
	}

	_show_log_modal(name) {
		_call("get_log_detail", { log_name: name }, (doc) => {
			if (!doc) return;
			const $modal = $(`<div class="fiq-modal-backdrop">
				<div class="fiq-modal">
					<button class="fiq-modal-close">&times;</button>
					<h4 style="margin:0 0 12px">Log: ${doc.name}</h4>
					${Object.entries({
						"IP Address": doc.ip_address,
						"Threat Score": doc.threat_score,
						"Blocked": doc.blocked ? "Yes" : "No",
						"Event Type": doc.event_type,
						"Severity": doc.severity,
						"Method": doc.request_method,
						"Path": doc.request_path,
						"Reason": doc.reason,
						"Source": doc.source,
						"Created": doc.creation,
					}).map(([k, v]) => `<div class="fiq-kv"><span class="fiq-kv-key">${k}</span><span class="fiq-kv-val">${v ?? "—"}</span></div>`).join("")}
					<div style="margin-top:14px;display:flex;gap:8px">
						<button class="fiq-btn primary fiq-goto-ip" data-ip="${doc.ip_address}">IP Intel →</button>
					</div>
				</div>
			</div>`);
			$modal.find(".fiq-modal-close").on("click", () => $modal.remove());
			$modal.on("click", (e) => { if ($(e.target).hasClass("fiq-modal-backdrop")) $modal.remove(); });
			$modal.find(".fiq-goto-ip").on("click", (e) => {
				$modal.remove();
				this._switch_tab("ip");
				this._sections.ip.find("#fiq-ip-input").val($(e.currentTarget).data("ip"));
				this._load_ip_intel($(e.currentTarget).data("ip"));
			});
			$("body").append($modal);
		});
	}

	// =========================================================================
	// SECTION 3 — IP Intelligence
	// =========================================================================

	_render_ip() {
		const $s = this._sections.ip;
		if ($s.find(".fiq-search-bar").length) return; // already rendered shell
		$s.html(`<div class="fiq-toolbar">
			<span class="fiq-title">IP Intelligence</span>
		</div>
		<div class="fiq-search-bar">
			<input id="fiq-ip-input" type="text" placeholder="Enter IP address (e.g. 192.168.1.1)" />
			<button class="fiq-btn primary" id="fiq-ip-search">Search</button>
		</div>
		<div id="fiq-ip-result"></div>`);

		const doSearch = () => {
			const ip = $s.find("#fiq-ip-input").val().trim();
			if (ip) this._load_ip_intel(ip);
		};
		$s.find("#fiq-ip-search").on("click", doSearch);
		$s.find("#fiq-ip-input").on("keydown", (e) => { if (e.key === "Enter") doSearch(); });
	}

	_load_ip_intel(ip) {
		const $r = this._sections.ip.find("#fiq-ip-result");
		$r.html(`<div class="fiq-empty">Loading intelligence for ${ip}…</div>`);
		_call("get_ip_intelligence", { ip }, (data) => {
			if (!data) { $r.html(`<div class="fiq-empty">No data returned.</div>`); return; }
			$r.html(this._ip_intel_html(data));
			// bind action buttons
			if (_is_admin()) {
				$r.find("#fiq-btn-unblock").on("click", () => {
					if (!confirm(`Unblock ${ip}?`)) return;
					_call("unblock_ip", { ip }, (res) => {
						frappe.show_alert({ message: `Unblocked ${ip}`, indicator: "green" }, 4);
						this._load_ip_intel(ip);
					});
				});
				$r.find("#fiq-btn-trust").on("click", () => {
					if (!confirm(`Add ${ip} to trusted set? It will always be observed, never blocked.`)) return;
					_call("trust_ip", { ip }, (res) => {
						frappe.show_alert({ message: `${ip} trusted`, indicator: "green" }, 4);
						this._load_ip_intel(ip);
					});
				});
				$r.find("#fiq-btn-untrust").on("click", () => {
					_call("untrust_ip", { ip }, (res) => {
						frappe.show_alert({ message: `${ip} removed from trusted set`, indicator: "orange" }, 4);
						this._load_ip_intel(ip);
					});
				});
			}
		});
	}

	_ip_intel_html(d) {
		const ip = d.ip;
		const rep = d.reputation || {};
		const adp = d.adaptive || {};
		const tmp = d.temporal || {};
		const camps = Array.isArray(d.campaign) ? d.campaign : [];
		const actions = Array.isArray(d.response_action) ? d.response_action : [];
		const logs = d.recent_logs || [];
		const blocks = d.blocklist || [];

		const admin = _is_admin();

		return `
		<div style="display:flex;gap:8px;align-items:center;margin-bottom:14px">
			<h4 style="margin:0;flex:1"><code>${ip}</code></h4>
			${admin ? `
			<button class="fiq-btn danger"  id="fiq-btn-unblock">Unblock</button>
			<button class="fiq-btn success" id="fiq-btn-trust">Trust IP</button>
			<button class="fiq-btn"         id="fiq-btn-untrust">Untrust</button>
			` : ""}
		</div>
		<div class="fiq-intel-grid">

		<div>
			<div class="fiq-card">
				<div class="fiq-card-title">Reputation</div>
				${this._kv("Score", rep.reputation_score ?? rep.score ?? "—")}
				${this._kv("Source", rep.source || "—")}
				${this._kv("Category", rep.category || "—")}
				${this._kv("Country", rep.country_code || "—")}
				${this._kv("ISP", rep.isp || "—")}
				${this._kv("Known Attacker", rep.is_known_attacker ? "Yes" : "No")}
				${this._kv("TOR Exit", rep.is_tor ? "Yes" : "No")}
				${this._kv("VPN", rep.is_vpn ? "Yes" : "No")}
			</div>

			<div class="fiq-card">
				<div class="fiq-card-title">Adaptive State</div>
				${this._kv("Behavior State", adp.behavior_state || adp.state || "—")}
				${this._kv("Trust Bonus", adp.trust_bonus ?? "—")}
				${this._kv("Events (1h)", adp.events_1h ?? "—")}
				${this._kv("Burst (5min)", adp.burst_5min ?? "—")}
				${this._kv("Velocity Score", adp.velocity_score ?? "—")}
				${this._kv("State Since", _fmt_ts(adp.state_since))}
			</div>
		</div>

		<div>
			<div class="fiq-card">
				<div class="fiq-card-title">Temporal Context</div>
				${this._kv("Diurnal Pattern", tmp.diurnal_pattern || "—")}
				${this._kv("Active Hours", tmp.active_hours_summary || "—")}
				${this._kv("Off-Hours Activity", tmp.off_hours_fraction != null ? (tmp.off_hours_fraction * 100).toFixed(1) + "%" : "—")}
				${this._kv("Recency Score", tmp.recency_score ?? "—")}
				${this._kv("Temporal Risk", tmp.temporal_risk || "—")}
			</div>

			<div class="fiq-card">
				<div class="fiq-card-title">Response Actions (recent)</div>
				${actions.length ? actions.map(a => `
					<div class="fiq-kv">
						<span class="fiq-kv-key">${_fmt_ts(a.triggered_at)}</span>
						<span class="fiq-kv-val">${_strategy_badge(a.strategy)}</span>
					</div>
					<div style="font-size:.76rem;color:var(--text-muted);padding:0 0 6px">${a.reason || ""}</div>
				`).join("") : `<div class="fiq-empty" style="padding:10px">No actions recorded.</div>`}
			</div>
		</div>

		</div><!-- grid end -->

		${camps.length ? `
		<div class="fiq-card" style="margin-top:14px">
			<div class="fiq-card-title">Active Campaigns</div>
			${camps.map(c => `
				<div class="fiq-kv">
					<span class="fiq-kv-key">${c.campaign_type} <span class="fiq-badge info">${c.confidence_score}%</span></span>
					<span class="fiq-kv-val">${c.participating_ip_count} IPs · started ${_fmt_ts(c.start_time)}</span>
				</div>
			`).join("")}
		</div>` : ""}

		${logs.length ? `
		<div class="fiq-card" style="margin-top:14px">
			<div class="fiq-card-title">Recent Log Entries</div>
			<div class="fiq-table-wrap">
				<table class="fiq-table">
					<thead><tr><th>Time</th><th>Score</th><th>Blocked</th><th>Type</th><th>Path</th></tr></thead>
					<tbody>${logs.map(l => `<tr>
						<td style="font-size:.76rem;white-space:nowrap">${frappe.datetime.str_to_user(l.creation)}</td>
						<td><strong style="color:${l.threat_score>=80?'#ef4444':l.threat_score>=50?'#d97706':'inherit'}">${l.threat_score||0}</strong></td>
						<td>${l.blocked ? '<span class="fiq-badge blocked">Yes</span>' : '<span class="fiq-badge observe">No</span>'}</td>
						<td><span class="fiq-badge ${_severity(l.threat_score||0)}">${l.event_type||"—"}</span></td>
						<td style="font-size:.76rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${l.request_path||"—"}</td>
					</tr>`).join("")}</tbody>
				</table>
			</div>
		</div>` : ""}`;
	}

	_kv(k, v) {
		return `<div class="fiq-kv"><span class="fiq-kv-key">${k}</span><span class="fiq-kv-val">${v ?? "—"}</span></div>`;
	}

	// =========================================================================
	// SECTION 4 — Campaigns
	// =========================================================================

	_render_campaigns() {
		const $s = this._sections.campaigns;
		$s.html(`<div class="fiq-toolbar">
			<span class="fiq-title"><span class="fiq-dot"></span>Active Campaigns</span>
			<button class="fiq-btn primary" id="fiq-camp-refresh">Refresh</button>
		</div>
		<div id="fiq-camp-summary" style="margin-bottom:14px"></div>
		<div id="fiq-camp-list"></div>`);

		$s.find("#fiq-camp-refresh").on("click", () => this._load_campaigns());
		this._load_campaigns();
	}

	_load_campaigns() {
		const $s = this._sections.campaigns;

		// summary
		_call("get_campaigns_summary", {}, (sum) => {
			$s.find("#fiq-camp-summary").html(sum && !sum.error ? `
				<div class="fiq-stats" style="grid-template-columns:repeat(4,1fr)">
					<div class="fiq-stat warning"><div class="fiq-stat-label">Active</div><div class="fiq-stat-value">${sum.active_campaigns||0}</div></div>
					<div class="fiq-stat"><div class="fiq-stat-label">Archived</div><div class="fiq-stat-value">${sum.archived_campaigns||0}</div></div>
					<div class="fiq-stat"><div class="fiq-stat-label">Total Events</div><div class="fiq-stat-value">${sum.total_events||0}</div></div>
					<div class="fiq-stat"><div class="fiq-stat-label">Unique IPs</div><div class="fiq-stat-value">${sum.unique_participating_ips||0}</div></div>
				</div>` : "");
		});

		// list
		_call("get_campaigns", { status: "active" }, (data) => {
			const camps = Array.isArray(data) ? data : (data?.campaigns || []);
			const $list = $s.find("#fiq-camp-list");
			if (!camps.length) {
				$list.html(`<div class="fiq-empty">No active campaigns detected.</div>`);
				return;
			}
			$list.html(camps.map(c => this._campaign_row_html(c)).join(""));
			$list.find(".fiq-camp-header").on("click", function () {
				$(this).next(".fiq-camp-body").toggleClass("open");
			});
		});
	}

	_campaign_row_html(c) {
		const ips = Array.isArray(c.participating_ips)
			? c.participating_ips
			: Object.keys(c.participating_ips || {});
		const vectors = Array.isArray(c.attack_vectors) ? c.attack_vectors : [];
		const paths   = Array.isArray(c.target_paths)   ? c.target_paths   : [];

		return `<div class="fiq-camp-row">
			<div class="fiq-camp-header">
				<span class="fiq-badge ${c.confidence_score>=70?'high':'medium'}">${c.confidence_score}%</span>
				<span class="fiq-camp-type">${c.campaign_type?.replace(/_/g, " ") || "—"}</span>
				<span class="fiq-camp-meta">${ips.length} IPs · ${c.event_count||0} events</span>
				<span class="fiq-camp-meta">▾</span>
			</div>
			<div class="fiq-camp-body">
				${this._kv("Campaign ID", c.campaign_id)}
				${this._kv("Started", _fmt_ts(c.start_time))}
				${this._kv("Last Activity", _fmt_ts(c.last_activity))}
				${this._kv("Confidence", c.confidence_score + "%")}
				${this._kv("Event Count", c.event_count || 0)}
				${this._kv("Participating IPs", ips.slice(0, 10).join(", ") + (ips.length > 10 ? ` +${ips.length - 10} more` : ""))}
				${vectors.length ? this._kv("Attack Vectors", vectors.join(", ")) : ""}
				${paths.length ? this._kv("Target Paths", paths.slice(0, 5).join(", ")) : ""}
			</div>
		</div>`;
	}

	// =========================================================================
	// SECTION 5 — Response Engine
	// =========================================================================

	_render_response() {
		const $s = this._sections.response;
		$s.html(`<div class="fiq-toolbar">
			<span class="fiq-title">Response Engine</span>
			<button class="fiq-btn primary" id="fiq-resp-refresh">Refresh</button>
		</div>
		<div id="fiq-resp-summary" style="margin-bottom:14px"></div>
		<h5 style="margin:0 0 8px;color:var(--heading-color)">Active Blocks</h5>
		<div id="fiq-active-blocks" style="margin-bottom:20px"></div>
		<h5 style="margin:0 0 8px;color:var(--heading-color)">Recent Action Timeline</h5>
		<div class="fiq-table-wrap" style="margin-bottom:20px">
			<table class="fiq-table">
				<thead><tr><th>IP</th><th>Strategy</th><th>Score</th><th>Reason</th><th>Time</th></tr></thead>
				<tbody id="fiq-resp-timeline"></tbody>
			</table>
		</div>
		<h5 style="margin:0 0 8px;color:var(--heading-color)">Reversal Log</h5>
		<div id="fiq-reversal-log"></div>`);

		$s.find("#fiq-resp-refresh").on("click", () => this._load_response());
		this._load_response();
	}

	_load_response() {
		const $s = this._sections.response;

		// summary
		_call("get_response_summary", {}, (sum) => {
			if (!sum || sum.error) return;
			$s.find("#fiq-resp-summary").html(`
				<div class="fiq-stats" style="grid-template-columns:repeat(4,1fr)">
					<div class="fiq-stat danger"><div class="fiq-stat-label">Active Blocks</div><div class="fiq-stat-value">${sum.active_blocks||0}</div></div>
					<div class="fiq-stat"><div class="fiq-stat-label">Trusted IPs</div><div class="fiq-stat-value">${sum.trusted_ips||0}</div></div>
					<div class="fiq-stat"><div class="fiq-stat-label">Total Actions (24h)</div><div class="fiq-stat-value">${sum.total_actions_24h||0}</div></div>
					<div class="fiq-stat"><div class="fiq-stat-label">Safeguard Overrides</div><div class="fiq-stat-value">${sum.safeguard_overrides||0}</div></div>
				</div>`);
		});

		// active blocks
		_call("get_active_blocks", {}, (data) => {
			const blocks = Array.isArray(data) ? data : (data?.blocks || []);
			const $ab = $s.find("#fiq-active-blocks");
			if (!blocks.length) {
				$ab.html(`<div class="fiq-empty">No active blocks.</div>`);
				return;
			}
			$ab.html(blocks.map(b => `
				<div class="fiq-block-row">
					<span class="fiq-block-ip"><code>${b.ip}</code></span>
					<span class="fiq-badge ${b.strategy === 'permanent_block' ? 'critical' : 'high'}">${b.strategy}</span>
					<span class="fiq-block-ttl">TTL: ${_ttl(b.expires_at)}</span>
					<span class="fiq-block-reason" title="${b.reason || ""}">${b.reason || "—"}</span>
					${_is_admin() ? `<button class="fiq-btn danger fiq-unblock-btn" data-ip="${b.ip}" style="margin-left:auto">Unblock</button>` : ""}
				</div>`).join(""));

			if (_is_admin()) {
				$ab.find(".fiq-unblock-btn").on("click", (e) => {
					const ip = $(e.currentTarget).data("ip");
					if (!confirm(`Unblock ${ip}?`)) return;
					_call("unblock_ip", { ip }, () => {
						frappe.show_alert({ message: `Unblocked ${ip}`, indicator: "green" }, 4);
						this._load_response();
					});
				});
			}
		});

		// timeline
		_call("get_response_timeline", { limit: 30 }, (data) => {
			const rows = Array.isArray(data) ? data : (data?.timeline || []);
			const $tbody = $s.find("#fiq-resp-timeline");
			if (!rows.length) {
				$tbody.html(`<tr><td colspan="5" class="fiq-empty">No actions recorded.</td></tr>`);
				return;
			}
			$tbody.html(rows.map(a => `<tr>
				<td><code style="font-size:.8rem">${a.ip}</code></td>
				<td>${_strategy_badge(a.strategy)}</td>
				<td><strong>${a.score||0}</strong></td>
				<td style="font-size:.76rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${a.reason||""}">${a.reason||"—"}</td>
				<td style="font-size:.76rem;white-space:nowrap">${_fmt_ts(a.triggered_at)}</td>
			</tr>`).join(""));
		});

		// reversal log
		_call("get_reversal_log", { limit: 20 }, (data) => {
			const revs = Array.isArray(data) ? data : (data?.reversals || []);
			const $rev = $s.find("#fiq-reversal-log");
			if (!revs.length) {
				$rev.html(`<div class="fiq-empty">No reversals recorded.</div>`);
				return;
			}
			$rev.html(`<div class="fiq-table-wrap"><table class="fiq-table">
				<thead><tr><th>IP</th><th>Reason</th><th>Time</th></tr></thead>
				<tbody>${revs.map(r => `<tr>
					<td><code style="font-size:.8rem">${r.ip}</code></td>
					<td style="font-size:.78rem">${r.reason||"—"}</td>
					<td style="font-size:.76rem;white-space:nowrap">${_fmt_ts(r.reversed_at||r.timestamp)}</td>
				</tr>`).join("")}</tbody>
			</table></div>`);
		});
	}

	// =========================================================================
	// SECTION 6 — System Health
	// =========================================================================

	_render_health() {
		const $s = this._sections.health;
		$s.html(`<div class="fiq-toolbar">
			<span class="fiq-title">System Health</span>
			<button class="fiq-btn primary" id="fiq-health-refresh">Refresh</button>
		</div>
		<div id="fiq-health-grid" class="fiq-health-grid"></div>
		<div id="fiq-intel-stats" style="margin-top:20px"></div>`);

		$s.find("#fiq-health-refresh").on("click", () => this._load_health());
		this._load_health();
	}

	_load_health() {
		const $s = this._sections.health;

		_call("get_system_health", {}, (h) => {
			if (!h) return;
			const ok = (v) => v ? "fiq-health-ok" : "fiq-health-err";
			const status_ok = (h.status === "ok" || h.status === "healthy");
			const csf_ok = h.csf_available !== false;
			const agent_ok = h.agent_running !== false;

			$s.find("#fiq-health-grid").html(`
				<div class="fiq-health-item">
					<div class="fiq-health-icon">🔮</div>
					<div class="fiq-health-label">Core Engine</div>
					<div class="fiq-health-value ${status_ok ? 'fiq-health-ok' : 'fiq-health-err'}">${h.status || "unknown"}</div>
				</div>
				<div class="fiq-health-item">
					<div class="fiq-health-icon">🛡️</div>
					<div class="fiq-health-label">CSF Agent</div>
					<div class="fiq-health-value ${csf_ok ? 'fiq-health-ok' : 'fiq-health-warn'}">${csf_ok ? "available" : "not found"}</div>
				</div>
				<div class="fiq-health-item">
					<div class="fiq-health-icon">⚙️</div>
					<div class="fiq-health-label">Agent Running</div>
					<div class="fiq-health-value ${agent_ok ? 'fiq-health-ok' : 'fiq-health-warn'}">${agent_ok ? "yes" : "no"}</div>
				</div>
				<div class="fiq-health-item">
					<div class="fiq-health-icon">📦</div>
					<div class="fiq-health-label">frothiq-core Version</div>
					<div class="fiq-health-value">${h.version || "—"}</div>
				</div>
				<div class="fiq-health-item">
					<div class="fiq-health-icon">🌐</div>
					<div class="fiq-health-label">Frappe Version</div>
					<div class="fiq-health-value">${h.frappe_version || "—"}</div>
				</div>
				<div class="fiq-health-item">
					<div class="fiq-health-icon">⏱️</div>
					<div class="fiq-health-label">Uptime</div>
					<div class="fiq-health-value">${h.uptime_seconds ? Math.round(h.uptime_seconds / 3600) + "h" : "—"}</div>
				</div>
				${h.site ? `<div class="fiq-health-item">
					<div class="fiq-health-icon">🏠</div>
					<div class="fiq-health-label">Site</div>
					<div class="fiq-health-value" style="font-size:.85rem">${h.site}</div>
				</div>` : ""}
				${h.ip_store_size != null ? `<div class="fiq-health-item">
					<div class="fiq-health-icon">📊</div>
					<div class="fiq-health-label">IPs in Store</div>
					<div class="fiq-health-value">${h.ip_store_size}</div>
				</div>` : ""}
				${h.queue_depth != null ? `<div class="fiq-health-item">
					<div class="fiq-health-icon">📬</div>
					<div class="fiq-health-label">Queue Depth</div>
					<div class="fiq-health-value ${h.queue_depth > 100 ? 'fiq-health-warn' : 'fiq-health-ok'}">${h.queue_depth}</div>
				</div>` : ""}
			`);
		});

		_call("get_intelligence_stats", {}, (stats) => {
			if (!stats || stats.error) return;
			const $el = $s.find("#fiq-intel-stats");
			const entries = Object.entries(stats).filter(([k]) => !["error"].includes(k));
			if (!entries.length) return;
			$el.html(`<div class="fiq-card">
				<div class="fiq-card-title">Intelligence Engine Stats</div>
				${entries.map(([k, v]) => this._kv(k.replace(/_/g, " "), v)).join("")}
			</div>`);
		});
	}

	// =========================================================================
	// SECTION 7 — Agents Overview (Phase 7)
	// =========================================================================

	_render_agents() {
		const $s = this._sections.agents;
		$s.html(`<div class="fiq-toolbar">
			<span class="fiq-title">Connected Agents</span>
			<select class="fiq-select" id="fiq-agent-filter">
				<option value="all">All Statuses</option>
				<option value="online">Online</option>
				<option value="stale">Stale</option>
				<option value="offline">Offline</option>
			</select>
			<button class="fiq-btn primary" id="fiq-agent-refresh">Refresh</button>
		</div>
		<div id="fiq-agent-summary" style="margin-bottom:16px"></div>
		<div id="fiq-agent-list"></div>`);

		$s.find("#fiq-agent-refresh").on("click", () => this._load_agents());
		$s.find("#fiq-agent-filter").on("change", () => this._load_agents());
		this._load_agents();
	}

	_load_agents() {
		const $s = this._sections.agents;
		if (!$s.hasClass("active")) return;
		const status_filter = $s.find("#fiq-agent-filter").val() || "all";

		// Summary cards
		_call("get_agents_summary", {}, (sum) => {
			if (!sum || sum.error) return;
			const by_type = sum.by_type || {};
			const by_status = sum.by_status || {};

			$s.find("#fiq-agent-summary").html(`
				<div class="fiq-stats" style="grid-template-columns:repeat(5,1fr)">
					<div class="fiq-stat">
						<div class="fiq-stat-label">Total Agents</div>
						<div class="fiq-stat-value">${sum.total_agents || 0}</div>
					</div>
					<div class="fiq-stat success">
						<div class="fiq-stat-label">Online</div>
						<div class="fiq-stat-value">${by_status.online || 0}</div>
					</div>
					<div class="fiq-stat warning">
						<div class="fiq-stat-label">Stale / Lost</div>
						<div class="fiq-stat-value">${(by_status.stale || 0) + (by_status.lost || 0)}</div>
					</div>
					<div class="fiq-stat">
						<div class="fiq-stat-label">WordPress</div>
						<div class="fiq-stat-value">${by_type.wordpress || 0}</div>
					</div>
					<div class="fiq-stat">
						<div class="fiq-stat-label">Frappe</div>
						<div class="fiq-stat-value">${by_type.frappe || 0}</div>
					</div>
				</div>
				<div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:8px">
					${Object.entries(sum.version_distribution || {}).map(([v, c]) =>
						`<span class="fiq-badge info">v${v}: ${c}</span>`
					).join("")}
				</div>
			`);
		});

		// Agent list
		_call("get_agents", { status_filter }, (data) => {
			const agents = data?.agents || [];
			const $list = $s.find("#fiq-agent-list");

			if (!agents.length) {
				$list.html(`<div class="fiq-empty">No agents registered. Deploy a FrothIQ plugin to a WordPress or Frappe site to see it here.</div>`);
				return;
			}

			$list.html(`<div class="fiq-table-wrap">
				<table class="fiq-table">
					<thead><tr>
						<th>Agent ID</th><th>Type</th><th>Version</th><th>Hostname</th>
						<th>Status</th><th>Last Seen</th>
						<th>Requests</th><th>Blocks</th><th>Events</th>
						<th>Capabilities</th>
					</tr></thead>
					<tbody id="fiq-agent-tbody"></tbody>
				</table>
			</div>`);

			$list.find("#fiq-agent-tbody").html(
				agents.map(a => this._agent_row_html(a)).join("")
			);

			// Click → detail modal
			$list.find("tr.clickable").off("click").on("click", (e) => {
				const id = $(e.currentTarget).data("agent-id");
				this._show_agent_modal(id, agents);
			});
		});
	}

	_agent_row_html(a) {
		const status_cls = {online: "active", stale: "medium", lost: "high", offline: "critical"}[a.status] || "info";
		const type_icon  = {wordpress: "🌐", frappe: "🔧", joomla: "🧩", linux: "🖥️"}[a.agent_type] || "❓";
		const caps = a.capabilities || {};
		const cap_badges = [
			caps.csf_integration   && `<span class="fiq-badge info">CSF</span>`,
			caps.wp_hooks          && `<span class="fiq-badge info">WP</span>`,
			caps.frappe_hooks      && `<span class="fiq-badge info">Frappe</span>`,
			caps.local_firewall    && `<span class="fiq-badge info">Firewall</span>`,
			caps.apply_actions     && `<span class="fiq-badge low">Apply</span>`,
		].filter(Boolean).join(" ");

		const age = a.last_seen ? Math.round((Date.now() / 1000) - a.last_seen) : null;
		const age_str = age == null ? "—" : age < 60 ? `${age}s ago` : age < 3600 ? `${Math.round(age/60)}m ago` : `${Math.round(age/3600)}h ago`;

		return `<tr class="clickable" data-agent-id="${a.agent_id}">
			<td><code style="font-size:.76rem">${a.agent_id}</code></td>
			<td>${type_icon} ${a.agent_type}</td>
			<td style="font-size:.78rem">${a.version || "—"}</td>
			<td style="font-size:.76rem;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${a.hostname||""}">${a.hostname || "—"}</td>
			<td><span class="fiq-badge ${status_cls}">${a.status}</span></td>
			<td style="font-size:.76rem;white-space:nowrap">${age_str}</td>
			<td>${(a.requests_total || 0).toLocaleString()}</td>
			<td style="color:${a.blocks_total>0?'#ef4444':'inherit'}">${(a.blocks_total || 0).toLocaleString()}</td>
			<td>${(a.events_reported || 0).toLocaleString()}</td>
			<td>${cap_badges || "—"}</td>
		</tr>`;
	}

	_show_agent_modal(agent_id, agents) {
		const a = agents.find(x => x.agent_id === agent_id);
		if (!a) return;
		const type_icon = {wordpress: "🌐", frappe: "🔧", joomla: "🧩", linux: "🖥️"}[a.agent_type] || "❓";
		const caps = a.capabilities || {};

		const $modal = $(`<div class="fiq-modal-backdrop">
			<div class="fiq-modal">
				<button class="fiq-modal-close">&times;</button>
				<h4 style="margin:0 0 6px">${type_icon} ${a.agent_type} Agent</h4>
				<code style="font-size:.78rem;color:var(--text-muted)">${a.agent_id}</code>
				<div style="margin-top:14px">
					${this._kv("Hostname",       a.hostname || "—")}
					${this._kv("Version",        a.version || "—")}
					${this._kv("Tenant",         a.tenant_id || "—")}
					${this._kv("Protocol",       "v1.0")}
					${this._kv("Status",         `<span class="fiq-badge ${a.status === 'online' ? 'active' : 'high'}">${a.status}</span>`)}
					${this._kv("Registered",     _fmt_ts(a.registered_at))}
					${this._kv("Last Seen",      _fmt_ts(a.last_seen))}
					<div style="margin:12px 0 4px;font-weight:600;font-size:.8rem;color:var(--text-muted);text-transform:uppercase">Traffic</div>
					${this._kv("Requests Total", (a.requests_total || 0).toLocaleString())}
					${this._kv("Blocks Total",   (a.blocks_total || 0).toLocaleString())}
					${this._kv("Events Reported", (a.events_reported || 0).toLocaleString())}
					${this._kv("Actions Applied", (a.actions_applied || 0).toLocaleString())}
					${this._kv("Requests/min",   a.requests_1m || 0)}
					${this._kv("Blocks/min",     a.blocks_1m || 0)}
					<div style="margin:12px 0 4px;font-weight:600;font-size:.8rem;color:var(--text-muted);text-transform:uppercase">Capabilities</div>
					${Object.entries(caps).map(([k, v]) =>
						`<div class="fiq-kv"><span class="fiq-kv-key">${k.replace(/_/g, " ")}</span>
						<span class="fiq-kv-val">${v ? '<span class="fiq-badge low">Yes</span>' : '<span class="fiq-badge critical">No</span>'}</span></div>`
					).join("")}
				</div>
			</div>
		</div>`);
		$modal.find(".fiq-modal-close").on("click", () => $modal.remove());
		$modal.on("click", (e) => { if ($(e.target).hasClass("fiq-modal-backdrop")) $modal.remove(); });
		$("body").append($modal);
	}
}
