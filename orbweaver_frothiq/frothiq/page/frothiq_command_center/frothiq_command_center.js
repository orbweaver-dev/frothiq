/**
 * FrothIQ Command Center — redirects to the standalone Control Center.
 *
 * The admin dashboard has been migrated to the FrothIQ Control Center
 * (standalone FastAPI + Next.js service). This Frappe page now redirects
 * operators to that service automatically.
 */

frappe.pages["frothiq-command-center"].on_page_load = function (wrapper) {
	frappe.ui.make_app_page({
		parent: wrapper,
		title: "FrothIQ Control Center",
		single_column: true,
	});

	const cc_url = frappe.boot.frothiq_control_center_url || "http://localhost:3000";

	$(wrapper).find(".page-content").html(`
		<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;
		            min-height:320px;gap:20px;font-family:var(--font-stack);">
			<div style="font-size:48px;">🛡️</div>
			<h2 style="margin:0;color:var(--heading-color);">FrothIQ Control Center</h2>
			<p style="margin:0;color:var(--text-muted);max-width:420px;text-align:center;">
				The operator dashboard has moved to the standalone Control Center.
				Click below to open it — your session is not shared; you'll be prompted to log in.
			</p>
			<a href="${frappe.utils.escape_html(cc_url)}" target="_blank" rel="noopener noreferrer"
			   class="btn btn-primary btn-lg">
				Open Control Center ↗
			</a>
			<small style="color:var(--text-muted);">${frappe.utils.escape_html(cc_url)}</small>
		</div>
	`);
};
