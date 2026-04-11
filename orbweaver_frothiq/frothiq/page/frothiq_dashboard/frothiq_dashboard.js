/**
 * FrothIQ Security Dashboard
 *
 * Panels:
 *   - Stat cards (requests / blocked / unique IPs / active blocks)
 *   - Live request feed  (real-time via Socket.IO + 5s poll fallback)
 *   - Attack category breakdown (horizontal bar chart)
 *   - IP tracking timeline / top offenders
 *   - CSF action history
 */

frappe.pages["frothiq-dashboard"].on_page_load = function (wrapper) {
	frappe.ui.make_app_page({
		parent: wrapper,
		title: "FrothIQ Security Dashboard",
		single_column: true,
	});
	wrapper.dashboard = new FrothIQDashboard(wrapper);
};

frappe.pages["frothiq-dashboard"].on_page_show = function (wrapper) {
	if (wrapper.dashboard) wrapper.dashboard.refresh();
};

// ─────────────────────────────────────────────────────────────────────────────
// Styles
// ─────────────────────────────────────────────────────────────────────────────

const CSS = `
<style id="frothiq-dash-css">
.fiq-dash {
	font-family: var(--font-stack);
	padding: 0 0 32px 0;
	background: var(--bg-color);
}

/* ── Toolbar ── */
.fiq-toolbar {
	display: flex;
	align-items: center;
	gap: 10px;
	padding: 14px 0 18px 0;
	flex-wrap: wrap;
}
.fiq-toolbar .fiq-title {
	font-size: 1.15rem;
	font-weight: 600;
	color: var(--heading-color);
	flex: 1;
}
.fiq-toolbar select,
.fiq-toolbar button {
	height: 32px;
	border-radius: 6px;
	border: 1px solid var(--border-color);
	background: var(--control-bg);
	color: var(--text-color);
	padding: 0 12px;
	font-size: 0.82rem;
	cursor: pointer;
}
.fiq-toolbar button.fiq-refresh {
	background: var(--primary);
	color: #fff;
	border-color: var(--primary);
	font-weight: 500;
}
.fiq-live-dot {
	width: 9px; height: 9px;
	border-radius: 50%;
	background: #22c55e;
	display: inline-block;
	margin-right: 5px;
	animation: fiq-pulse 1.8s infinite;
}
@keyframes fiq-pulse {
	0%,100% { opacity: 1; }
	50%      { opacity: 0.25; }
}

/* ── Stat cards ── */
.fiq-stats {
	display: grid;
	grid-template-columns: repeat(4, 1fr);
	gap: 14px;
	margin-bottom: 18px;
}
@media (max-width: 900px) { .fiq-stats { grid-template-columns: repeat(2,1fr); } }
.fiq-stat-card {
	background: var(--card-bg);
	border: 1px solid var(--border-color);
	border-radius: 10px;
	padding: 18px 20px;
	position: relative;
	overflow: hidden;
}
.fiq-stat-card::before {
	content: '';
	position: absolute;
	top: 0; left: 0; right: 0;
	height: 3px;
}
.fiq-stat-card.c-blue::before   { background: #3b82f6; }
.fiq-stat-card.c-red::before    { background: #ef4444; }
.fiq-stat-card.c-purple::before { background: #8b5cf6; }
.fiq-stat-card.c-orange::before { background: #f97316; }
.fiq-stat-label {
	font-size: 0.72rem;
	text-transform: uppercase;
	letter-spacing: .07em;
	color: var(--text-muted);
	margin-bottom: 6px;
}
.fiq-stat-value {
	font-size: 2rem;
	font-weight: 700;
	color: var(--heading-color);
	line-height: 1;
}
.fiq-stat-sub {
	font-size: 0.78rem;
	color: var(--text-muted);
	margin-top: 4px;
}

/* ── Two-column grid ── */
.fiq-grid {
	display: grid;
	grid-template-columns: 1fr 380px;
	gap: 16px;
	margin-bottom: 16px;
}
.fiq-grid-bottom {
	display: grid;
	grid-template-columns: 1fr 1fr;
	gap: 16px;
}
@media (max-width: 1100px) {
	.fiq-grid, .fiq-grid-bottom { grid-template-columns: 1fr; }
}

/* ── Panel ── */
.fiq-panel {
	background: var(--card-bg);
	border: 1px solid var(--border-color);
	border-radius: 10px;
	overflow: hidden;
}
.fiq-panel-header {
	padding: 12px 16px;
	border-bottom: 1px solid var(--border-color);
	font-size: 0.8rem;
	font-weight: 600;
	text-transform: uppercase;
	letter-spacing: .07em;
	color: var(--text-muted);
	display: flex;
	align-items: center;
	gap: 8px;
}
.fiq-panel-body {
	padding: 0;
	overflow-y: auto;
	max-height: 360px;
}
.fiq-panel-body.fiq-chart-body {
	padding: 16px;
	max-height: none;
}

/* ── Feed rows ── */
.fiq-feed-row {
	display: grid;
	grid-template-columns: 68px 110px 72px 56px 52px 1fr 60px;
	align-items: center;
	gap: 0;
	padding: 7px 14px;
	border-bottom: 1px solid var(--border-color);
	font-size: 0.78rem;
	transition: background 0.2s;
}
.fiq-feed-row:last-child { border-bottom: none; }
.fiq-feed-row.fiq-new {
	animation: fiq-slide-in 0.4s ease;
}
@keyframes fiq-slide-in {
	from { background: color-mix(in srgb, var(--primary) 12%, transparent); }
	to   { background: transparent; }
}
.fiq-feed-row:hover { background: var(--hover-bg); }
.fiq-feed-ts { color: var(--text-muted); font-size: 0.73rem; font-variant-numeric: tabular-nums; }
.fiq-feed-ip { font-weight: 500; color: var(--text-color); }
.fiq-feed-src { color: var(--text-muted); font-size: 0.73rem; }
.fiq-feed-type { font-size: 0.7rem; }
.fiq-feed-path {
	color: var(--text-muted);
	font-size: 0.72rem;
	white-space: nowrap;
	overflow: hidden;
	text-overflow: ellipsis;
}

/* ── Score badges ── */
.fiq-score {
	display: inline-flex;
	align-items: center;
	justify-content: center;
	font-size: 0.72rem;
	font-weight: 700;
	border-radius: 5px;
	padding: 2px 7px;
	font-variant-numeric: tabular-nums;
}
.fiq-score.s-clean    { background: #dcfce7; color: #166534; }
.fiq-score.s-monitor  { background: #fef9c3; color: #854d0e; }
.fiq-score.s-ratelimit{ background: #ffedd5; color: #9a3412; }
.fiq-score.s-block    { background: #fee2e2; color: #991b1b; }

/* dark mode */
@media (prefers-color-scheme: dark) {
	.fiq-score.s-clean    { background: #14532d; color: #86efac; }
	.fiq-score.s-monitor  { background: #713f12; color: #fde68a; }
	.fiq-score.s-ratelimit{ background: #7c2d12; color: #fdba74; }
	.fiq-score.s-block    { background: #7f1d1d; color: #fca5a5; }
}

.fiq-blocked-badge {
	display: inline-block;
	font-size: 0.67rem;
	font-weight: 700;
	border-radius: 4px;
	padding: 1px 6px;
}
.fiq-blocked-badge.yes { background: #fee2e2; color: #991b1b; }
.fiq-blocked-badge.no  { background: #f1f5f9; color: #64748b; }

/* ── Horizontal bar chart ── */
.fiq-bar-row {
	display: grid;
	grid-template-columns: 100px 1fr 46px;
	align-items: center;
	gap: 10px;
	margin-bottom: 11px;
}
.fiq-bar-label {
	font-size: 0.78rem;
	color: var(--text-color);
	text-align: right;
	white-space: nowrap;
	overflow: hidden;
	text-overflow: ellipsis;
}
.fiq-bar-track {
	height: 14px;
	background: var(--border-color);
	border-radius: 7px;
	overflow: hidden;
}
.fiq-bar-fill {
	height: 100%;
	border-radius: 7px;
	transition: width 0.5s ease;
}
.fiq-bar-count {
	font-size: 0.78rem;
	font-weight: 600;
	color: var(--text-muted);
	text-align: right;
}

/* ── IP timeline table ── */
.fiq-ip-row {
	display: grid;
	grid-template-columns: 120px 50px 50px 70px 1fr;
	align-items: center;
	gap: 0;
	padding: 7px 14px;
	border-bottom: 1px solid var(--border-color);
	font-size: 0.78rem;
}
.fiq-ip-row:last-child { border-bottom: none; }
.fiq-ip-row:hover { background: var(--hover-bg); }
.fiq-ip-addr { font-weight: 600; }
.fiq-ip-count { color: var(--text-muted); text-align: center; }
.fiq-ip-blocks { text-align: center; }
.fiq-ip-types { font-size: 0.7rem; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* ── Score bar (IP panel) ── */
.fiq-score-bar {
	height: 6px;
	border-radius: 3px;
	background: var(--border-color);
	width: 100%;
}
.fiq-score-bar-fill {
	height: 100%;
	border-radius: 3px;
}

/* ── CSF history ── */
.fiq-csf-row {
	display: grid;
	grid-template-columns: 68px 120px 50px 70px 1fr;
	align-items: center;
	gap: 0;
	padding: 7px 14px;
	border-bottom: 1px solid var(--border-color);
	font-size: 0.78rem;
}
.fiq-csf-row:last-child { border-bottom: none; }
.fiq-csf-row:hover { background: var(--hover-bg); }
.fiq-csf-action {
	display: inline-block;
	font-size: 0.67rem;
	font-weight: 700;
	border-radius: 4px;
	padding: 1px 6px;
}
.fiq-csf-action.deny  { background: #fee2e2; color: #991b1b; }
.fiq-csf-action.allow { background: #dcfce7; color: #166534; }
.fiq-status-badge {
	display: inline-block;
	font-size: 0.67rem;
	border-radius: 4px;
	padding: 1px 6px;
}
.fiq-status-badge.active   { background: #dbeafe; color: #1e40af; }
.fiq-status-badge.expired  { background: #f1f5f9; color: #64748b; }
.fiq-status-badge.removed  { background: #fef9c3; color: #854d0e; }

/* ── Column headers ── */
.fiq-col-header {
	display: grid;
	padding: 6px 14px;
	border-bottom: 1px solid var(--border-color);
	font-size: 0.68rem;
	font-weight: 600;
	text-transform: uppercase;
	letter-spacing: .06em;
	color: var(--text-muted);
	background: var(--subtle-bg);
}

/* ── Empty state ── */
.fiq-empty {
	padding: 32px;
	text-align: center;
	color: var(--text-muted);
	font-size: 0.85rem;
}

/* ── Spinner ── */
.fiq-spinner {
	text-align: center;
	padding: 24px;
	color: var(--text-muted);
	font-size: 0.82rem;
}
</style>`;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function scoreClass(score) {
	if (score >= 80) return "s-block";
	if (score >= 60) return "s-ratelimit";
	if (score >= 30) return "s-monitor";
	return "s-clean";
}

function scoreBarColor(score) {
	if (score >= 80) return "#ef4444";
	if (score >= 60) return "#f97316";
	if (score >= 30) return "#eab308";
	return "#22c55e";
}

function attackColor(type) {
	const map = {
		sqli: "#ef4444", xss: "#f97316", path_traversal: "#8b5cf6",
		rfi: "#ec4899", cmd_injection: "#dc2626",
		failed_login: "#eab308", high_frequency: "#3b82f6",
		malicious_payload: "#f43f5e", manual: "#6366f1",
	};
	return map[type] || "#94a3b8";
}

function shortTs(creation) {
	// Returns HH:MM:SS from creation string
	if (!creation) return "—";
	const d = new Date(creation + (creation.endsWith("Z") ? "" : "Z"));
	if (isNaN(d)) {
		// Try without Z
		const d2 = new Date(creation.replace(" ", "T"));
		if (!isNaN(d2)) {
			return d2.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
		}
		return creation.slice(11, 19) || "—";
	}
	return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function esc(s) {
	return String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard class
// ─────────────────────────────────────────────────────────────────────────────

class FrothIQDashboard {
	constructor(wrapper) {
		this.wrapper = wrapper;
		this.page    = wrapper.page;
		this.$main   = $(wrapper).find(".layout-main-section");
		this.hours   = 24;
		this.feedRows = [];       // cached feed rows (newest first)
		this.lastLogName = null;  // for incremental feed polling
		this._pollTimer = null;

		if (!document.getElementById("frothiq-dash-css")) {
			$("head").append(CSS);
		}

		this._buildShell();
		this._bindRealtime();
		this.refresh();
	}

	// ── Shell ──────────────────────────────────────────────────────────────

	_buildShell() {
		this.$main.html(`
		<div class="fiq-dash">
			<div class="fiq-toolbar">
				<span class="fiq-title">
					<span class="fiq-live-dot"></span> Live Security Monitor
				</span>
				<select class="fiq-hours-select">
					<option value="1">Last 1 hour</option>
					<option value="6">Last 6 hours</option>
					<option value="24" selected>Last 24 hours</option>
					<option value="72">Last 72 hours</option>
				</select>
				<button class="fiq-refresh btn btn-primary btn-sm">↻ Refresh</button>
			</div>

			<!-- Stat cards -->
			<div class="fiq-stats" id="fiq-stats">
				<div class="fiq-stat-card c-blue">
					<div class="fiq-stat-label">Total Requests</div>
					<div class="fiq-stat-value" id="fiq-total">—</div>
					<div class="fiq-stat-sub" id="fiq-period">Last 24h</div>
				</div>
				<div class="fiq-stat-card c-red">
					<div class="fiq-stat-label">Blocked</div>
					<div class="fiq-stat-value" id="fiq-blocked">—</div>
					<div class="fiq-stat-sub" id="fiq-block-pct">—% of traffic</div>
				</div>
				<div class="fiq-stat-card c-purple">
					<div class="fiq-stat-label">Unique IPs</div>
					<div class="fiq-stat-value" id="fiq-unique">—</div>
					<div class="fiq-stat-sub" id="fiq-active-blocks">— active blocks</div>
				</div>
				<div class="fiq-stat-card c-orange">
					<div class="fiq-stat-label">Top Threat Score</div>
					<div class="fiq-stat-value" id="fiq-top-score">—</div>
					<div class="fiq-stat-sub" id="fiq-top-ip">—</div>
				</div>
			</div>

			<!-- Feed + Attack breakdown -->
			<div class="fiq-grid">
				<!-- Live feed -->
				<div class="fiq-panel" id="fiq-feed-panel">
					<div class="fiq-panel-header">
						📡 Live Request Feed
						<span style="font-size:0.68rem;font-weight:400;margin-left:auto;color:var(--text-muted)">
							auto-updates
						</span>
					</div>
					<div class="fiq-col-header" style="grid-template-columns:68px 110px 72px 56px 52px 1fr 60px">
						<span>Time</span><span>IP</span><span>Source</span>
						<span>Type</span><span>Score</span><span>Path</span><span>Status</span>
					</div>
					<div class="fiq-panel-body" id="fiq-feed-body">
						<div class="fiq-spinner">Loading feed…</div>
					</div>
				</div>

				<!-- Attack breakdown chart -->
				<div class="fiq-panel" id="fiq-breakdown-panel">
					<div class="fiq-panel-header">🎯 Attack Category Breakdown</div>
					<div class="fiq-panel-body fiq-chart-body" id="fiq-breakdown-body">
						<div class="fiq-spinner">Loading…</div>
					</div>
				</div>
			</div>

			<!-- Top IPs + CSF history -->
			<div class="fiq-grid-bottom">
				<!-- IP timeline -->
				<div class="fiq-panel" id="fiq-ip-panel">
					<div class="fiq-panel-header">🌐 IP Tracking Timeline</div>
					<div class="fiq-col-header" style="grid-template-columns:120px 50px 50px 70px 1fr">
						<span>IP Address</span><span style="text-align:center">Reqs</span>
						<span style="text-align:center">Blocked</span><span>Max Score</span>
						<span>Attack Types</span>
					</div>
					<div class="fiq-panel-body" id="fiq-ip-body">
						<div class="fiq-spinner">Loading…</div>
					</div>
				</div>

				<!-- CSF history -->
				<div class="fiq-panel" id="fiq-csf-panel">
					<div class="fiq-panel-header">🔒 CSF Action History</div>
					<div class="fiq-col-header" style="grid-template-columns:68px 120px 50px 70px 1fr">
						<span>Time</span><span>IP</span><span>Action</span>
						<span>Status</span><span>Reason</span>
					</div>
					<div class="fiq-panel-body" id="fiq-csf-body">
						<div class="fiq-spinner">Loading…</div>
					</div>
				</div>
			</div>
		</div>`);

		// Toolbar events
		this.$main.find(".fiq-hours-select").on("change", (e) => {
			this.hours = parseInt(e.target.value);
			this.refresh();
		});
		this.$main.find(".fiq-refresh").on("click", () => this.refresh());
	}

	// ── Public refresh (loads all panels) ─────────────────────────────────

	refresh() {
		this._loadStats();
		this._loadFeed();
		this._loadBreakdown();
		this._loadTopIPs();
		this._loadCSFHistory();
		this._schedulePoll();
	}

	// ── Polling ────────────────────────────────────────────────────────────

	_schedulePoll() {
		if (this._pollTimer) clearInterval(this._pollTimer);
		this._pollTimer = setInterval(() => {
			this._pollFeed();
			this._loadStats();
		}, 5000);
	}

	/** Poll for NEW feed entries since the last known record. */
	_pollFeed() {
		if (!this.lastLogName) return;
		frappe.call({
			method: "orbweaver_frothiq.frothiq.api.dashboard_api.get_live_feed",
			args: { limit: 30, after_name: this.lastLogName },
			freeze: false,
			callback: (r) => {
				if (r.message && r.message.length) {
					this._prependFeedRows(r.message, true);
				}
			},
		});
	}

	// ── Realtime (instant push on new log) ────────────────────────────────

	_bindRealtime() {
		frappe.realtime.on("frothiq_new_log", (data) => {
			if (data) this._prependFeedRows([data], true);
		});
	}

	// ── Stat cards ─────────────────────────────────────────────────────────

	_loadStats() {
		frappe.call({
			method: "orbweaver_frothiq.frothiq.api.dashboard_api.get_dashboard_stats",
			args: { hours: this.hours },
			freeze: false,
			callback: (r) => {
				if (!r.message) return;
				const d = r.message;
				const pct = d.total_requests
					? ((d.blocked_count / d.total_requests) * 100).toFixed(1)
					: "0.0";
				this.$main.find("#fiq-total").text(d.total_requests.toLocaleString());
				this.$main.find("#fiq-blocked").text(d.blocked_count.toLocaleString());
				this.$main.find("#fiq-block-pct").text(`${pct}% of traffic`);
				this.$main.find("#fiq-period").text(`Last ${d.hours}h`);
				this.$main.find("#fiq-unique").text(d.unique_ips.toLocaleString());
				this.$main.find("#fiq-active-blocks").text(`${d.active_blocks} active blocks`);
				this.$main.find("#fiq-top-score").text(d.top_score.threat_score || 0);
				this.$main.find("#fiq-top-ip").text(d.top_score.ip_address || "—");
			},
		});
	}

	// ── Live feed ──────────────────────────────────────────────────────────

	_loadFeed() {
		this.lastLogName = null;
		this.feedRows = [];
		frappe.call({
			method: "orbweaver_frothiq.frothiq.api.dashboard_api.get_live_feed",
			args: { limit: 60 },
			freeze: false,
			callback: (r) => {
				const rows = r.message || [];
				this.feedRows = rows;
				if (rows.length) this.lastLogName = rows[0].name;
				this._renderFeed();
			},
		});
	}

	_prependFeedRows(newRows, highlight) {
		// Deduplicate by name
		const existingNames = new Set(this.feedRows.map(r => r.name));
		const fresh = newRows.filter(r => !existingNames.has(r.name));
		if (!fresh.length) return;

		this.feedRows = [...fresh, ...this.feedRows].slice(0, 200);
		this.lastLogName = this.feedRows[0].name;

		// Fast DOM prepend (no full re-render)
		const $body = this.$main.find("#fiq-feed-body");
		if ($body.find(".fiq-spinner").length) {
			$body.empty();
		}
		fresh.reverse().forEach(row => {
			const $row = $(this._feedRowHtml(row));
			if (highlight) $row.addClass("fiq-new");
			$body.prepend($row);
		});
		// Cap DOM nodes
		const $rows = $body.find(".fiq-feed-row");
		if ($rows.length > 100) $rows.slice(100).remove();
	}

	_renderFeed() {
		const $body = this.$main.find("#fiq-feed-body");
		if (!this.feedRows.length) {
			$body.html('<div class="fiq-empty">No requests in this period</div>');
			return;
		}
		$body.html(this.feedRows.map(r => this._feedRowHtml(r)).join(""));
	}

	_feedRowHtml(r) {
		const sc = scoreClass(r.threat_score || 0);
		const blockedHtml = r.blocked
			? '<span class="fiq-blocked-badge yes">BLOCK</span>'
			: '<span class="fiq-blocked-badge no">pass</span>';
		const typeColor = attackColor(r.event_type);
		const typeLabel = (r.event_type || "—").replace("_", " ").toUpperCase().slice(0, 8);
		return `<div class="fiq-feed-row">
			<span class="fiq-feed-ts">${esc(shortTs(r.creation))}</span>
			<span class="fiq-feed-ip">${esc(r.ip_address)}</span>
			<span class="fiq-feed-src" style="color:var(--text-muted)">${esc(r.source||"—")}</span>
			<span class="fiq-feed-type" style="color:${typeColor};font-weight:600;font-size:0.68rem">${esc(typeLabel)}</span>
			<span class="fiq-score ${sc}">${r.threat_score || 0}</span>
			<span class="fiq-feed-path" title="${esc(r.request_path||"")}">${esc((r.request_path||"").slice(0,40)||"—")}</span>
			${blockedHtml}
		</div>`;
	}

	// ── Attack breakdown chart ─────────────────────────────────────────────

	_loadBreakdown() {
		frappe.call({
			method: "orbweaver_frothiq.frothiq.api.dashboard_api.get_attack_breakdown",
			args: { hours: this.hours },
			freeze: false,
			callback: (r) => {
				const rows = r.message || [];
				const $body = this.$main.find("#fiq-breakdown-body");
				if (!rows.length) {
					$body.html('<div class="fiq-empty">No attack events in this period</div>');
					return;
				}
				const maxCnt = Math.max(...rows.map(x => x.cnt), 1);
				const html = rows.map(row => {
					const pct = Math.round((row.cnt / maxCnt) * 100);
					const color = attackColor(row.event_type);
					const label = (row.event_type || "other")
						.replace(/_/g, " ")
						.replace(/\b\w/g, c => c.toUpperCase());
					return `<div class="fiq-bar-row">
						<span class="fiq-bar-label" title="${esc(label)}">${esc(label)}</span>
						<div class="fiq-bar-track">
							<div class="fiq-bar-fill" style="width:${pct}%;background:${color}"></div>
						</div>
						<span class="fiq-bar-count">${row.cnt}</span>
					</div>`;
				}).join("");
				$body.html(html || '<div class="fiq-empty">No data</div>');
			},
		});
	}

	// ── Top IPs ────────────────────────────────────────────────────────────

	_loadTopIPs() {
		frappe.call({
			method: "orbweaver_frothiq.frothiq.api.dashboard_api.get_top_ips",
			args: { hours: this.hours, limit: 12 },
			freeze: false,
			callback: (r) => {
				const rows = r.message || [];
				const $body = this.$main.find("#fiq-ip-body");
				if (!rows.length) {
					$body.html('<div class="fiq-empty">No IP activity in this period</div>');
					return;
				}
				const maxScore = Math.max(...rows.map(x => x.max_score || 0), 1);
				const html = rows.map(row => {
					const score = row.max_score || 0;
					const pct = Math.round((score / 100) * 100);
					const color = scoreBarColor(score);
					const scoreHtml = `<div style="display:flex;align-items:center;gap:6px">
						<span class="fiq-score ${scoreClass(score)}">${score}</span>
					</div>`;
					return `<div class="fiq-ip-row">
						<span class="fiq-ip-addr">${esc(row.ip_address)}</span>
						<span class="fiq-ip-count">${row.request_count}</span>
						<span class="fiq-ip-blocks">
							${row.blocked_count
								? `<span class="fiq-blocked-badge yes">${row.blocked_count}</span>`
								: `<span style="color:var(--text-muted)">0</span>`}
						</span>
						${scoreHtml}
						<span class="fiq-ip-types" title="${esc(row.attack_types||"")}">${esc((row.attack_types||"—").slice(0,40))}</span>
					</div>`;
				}).join("");
				$body.html(html);
			},
		});
	}

	// ── CSF history ────────────────────────────────────────────────────────

	_loadCSFHistory() {
		frappe.call({
			method: "orbweaver_frothiq.frothiq.api.dashboard_api.get_csf_history",
			args: { limit: 25 },
			freeze: false,
			callback: (r) => {
				const rows = r.message || [];
				const $body = this.$main.find("#fiq-csf-body");
				if (!rows.length) {
					$body.html('<div class="fiq-empty">No CSF actions recorded</div>');
					return;
				}
				const html = rows.map(row => {
					const actionHtml = `<span class="fiq-csf-action ${row.list_type === "deny" ? "deny" : "allow"}">
						${row.list_type === "deny" ? "DENY" : "ALLOW"}
					</span>`;
					const statusHtml = `<span class="fiq-status-badge ${row.status}">
						${esc(row.status)}
					</span>`;
					const pushedDot = row.pushed_to_csf
						? `<span title="Pushed to CSF" style="color:#22c55e;font-size:1rem">●</span> `
						: `<span title="Not pushed" style="color:#94a3b8;font-size:1rem">○</span> `;
					return `<div class="fiq-csf-row">
						<span class="fiq-feed-ts">${esc(shortTs(row.creation))}</span>
						<span style="font-weight:500">${esc(row.ip_address)}</span>
						${actionHtml}
						${statusHtml}
						<span style="font-size:0.72rem;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
							${pushedDot}${esc((row.reason||"—").slice(0,50))}
						</span>
					</div>`;
				}).join("");
				$body.html(html);
			},
		});
	}

	// ── Cleanup ────────────────────────────────────────────────────────────

	destroy() {
		if (this._pollTimer) clearInterval(this._pollTimer);
		frappe.realtime.off("frothiq_new_log");
	}
}
