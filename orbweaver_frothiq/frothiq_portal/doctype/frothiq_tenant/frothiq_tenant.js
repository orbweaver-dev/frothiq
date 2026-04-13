// Copyright (c) 2026, OrbWeaver — Proprietary
// FrothIQ Tenant — form controller
// Phase 7: plan info, usage bars, Upgrade Plan button

frappe.ui.form.on("FrothIQ Tenant", {
    // -----------------------------------------------------------------
    // Form load
    // -----------------------------------------------------------------
    refresh(frm) {
        frm.trigger("render_plan_badge");
        frm.trigger("add_custom_buttons");

        if (!frm.is_new()) {
            frm.trigger("render_usage_bars");
        }
    },

    plan(frm) {
        frm.trigger("render_plan_badge");
    },

    // -----------------------------------------------------------------
    // Plan badge in the form header area
    // -----------------------------------------------------------------
    render_plan_badge(frm) {
        const PLAN_COLORS = {
            free:       { bg: "#f3f4f6", text: "#374151", label: "Free" },
            pro:        { bg: "#dbeafe", text: "#1d4ed8", label: "Pro" },
            enterprise: { bg: "#f3e8ff", text: "#7c3aed", label: "Enterprise" },
        };
        const plan  = frm.doc.plan || "free";
        const cfg   = PLAN_COLORS[plan] || PLAN_COLORS.free;
        const badge = `<span style="background:${cfg.bg};color:${cfg.text};
            padding:2px 10px;border-radius:100px;font-size:0.8rem;font-weight:700;
            text-transform:uppercase;letter-spacing:.05em;">${cfg.label}</span>`;

        frm.set_intro(
            `${badge}&nbsp;&nbsp;${__("Plan limits")}: ` +
            frm.trigger("plan_limits_text"),
            "blue"
        );
    },

    plan_limits_text(frm) {
        const LIMITS = {
            free:       { rpm: 120,  max_sites: 1,   features: "Monitor only" },
            pro:        { rpm: 600,  max_sites: 10,  features: "Federation, Campaigns" },
            enterprise: { rpm: 2000, max_sites: 100, features: "Full suite" },
        };
        const p = LIMITS[frm.doc.plan || "free"] || LIMITS.free;
        return `${p.max_sites} site${p.max_sites !== 1 ? "s" : ""} · ${p.rpm} rpm · ${p.features}`;
    },

    // -----------------------------------------------------------------
    // Custom buttons
    // -----------------------------------------------------------------
    add_custom_buttons(frm) {
        if (frm.is_new()) return;

        // "Upgrade Plan" — only for Customer Admin; opens Subscription in ERPNext
        if (frappe.user_roles.includes("FrothIQ Customer Admin") ||
            frappe.user_roles.includes("System Manager") ||
            frappe.user_roles.includes("FrothIQ Admin")) {

            frm.add_custom_button(__("Upgrade Plan"), function () {
                frm.trigger("show_upgrade_dialog");
            }, __("Billing"));
        }

        // "View Subscription" — opens ERPNext Subscription if linked
        if (frm.doc.subscription &&
            (frappe.user_roles.includes("System Manager") ||
             frappe.user_roles.includes("FrothIQ Admin"))) {
            frm.add_custom_button(__("View Subscription"), function () {
                frappe.set_route("Form", "Subscription", frm.doc.subscription);
            }, __("Billing"));
        }

        // "Sync to Core" — admin only, manually triggers a core sync
        if (frappe.user_roles.includes("System Manager") ||
            frappe.user_roles.includes("FrothIQ Admin")) {
            frm.add_custom_button(__("Sync to Core"), function () {
                frappe.call({
                    method: "orbweaver_frothiq.frothiq_portal.api.billing_api.sync_tenants_to_core",
                    callback(r) {
                        frappe.show_alert({ message: __("Sync triggered."), indicator: "green" });
                    },
                });
            }, __("Tools"));
        }

        // "Test Alert" — sends a synthetic event through the full alerting pipeline
        if (frappe.user_roles.includes("FrothIQ Customer Admin") ||
            frappe.user_roles.includes("System Manager") ||
            frappe.user_roles.includes("FrothIQ Admin")) {
            frm.add_custom_button(__("Test Alert"), function () {
                frappe.call({
                    method: "orbweaver_frothiq.frothiq_portal.api.portal_api.send_test_alert",
                    callback(r) {
                        if (r.message && r.message.sent) {
                            frappe.show_alert({
                                message: __("Test alert sent ({0})", [r.message.event_name]),
                                indicator: "blue",
                            }, 5);
                        }
                    },
                });
            }, __("Alerts"));
        }

        // "View Alerts" — navigate to the FrothIQ Event list for this tenant
        if (!frm.is_new()) {
            frm.add_custom_button(__("View Alerts"), function () {
                frappe.set_route("List", "FrothIQ Event", { tenant: frm.docname });
            }, __("Alerts"));
        }
    },

    // -----------------------------------------------------------------
    // Usage vs Limits bars
    // -----------------------------------------------------------------
    render_usage_bars(frm) {
        frappe.call({
            method: "orbweaver_frothiq.frothiq_portal.api.portal_api.get_usage_summary",
            args: { window: "24h" },
            callback(r) {
                if (!r.message) return;
                const data = r.message;
                frm.trigger("inject_usage_html", data);
            },
        });

        frappe.call({
            method: "orbweaver_frothiq.frothiq_portal.api.portal_api.get_tenant_sites",
            callback(r) {
                if (!r.message) return;
                const sites = r.message.sites || [];
                frm.trigger("inject_sites_bar", sites.length);
            },
        });
    },

    inject_usage_html(frm, data) {
        // Remove previous widget if re-rendering
        frm.fields_dict.notes.$wrapper.closest(".form-section").find(".fq-usage-widget").remove();

        const LIMITS = {
            free:       { rpm: 120 },
            pro:        { rpm: 600 },
            enterprise: { rpm: 2000 },
        };
        const planRpm = (LIMITS[frm.doc.plan] || LIMITS.free).rpm;
        const blocked = data.total_blocked || 0;
        const requests = data.total_requests || 0;
        const blockRate = requests > 0 ? Math.round(blocked / requests * 100) : 0;

        const html = `
        <div class="fq-usage-widget" style="margin:12px 0;padding:14px 16px;
            background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;">
            <h6 style="margin:0 0 12px;font-size:.8rem;text-transform:uppercase;
                letter-spacing:.05em;color:#64748b;">${__("Usage (24h)")}</h6>
            ${_bar(__("Requests"), requests, 86400 * planRpm / 60, "#2563eb")}
            ${_bar(__("Blocked"), blocked, Math.max(blocked, requests) || 1, "#dc2626")}
            <p style="margin:8px 0 0;font-size:.75rem;color:#94a3b8;">
                ${__("Block rate")}: <strong>${blockRate}%</strong> &nbsp;·&nbsp;
                ${__("Window")}: ${data.window || "24h"}
            </p>
        </div>`;

        // Inject after the notes field
        frm.fields_dict.notes.$wrapper.after(html);
    },

    inject_sites_bar(frm, site_count) {
        const LIMITS = { free: 1, pro: 10, enterprise: 100 };
        const maxSites = LIMITS[frm.doc.plan] || 1;
        const bar = _bar(__("Sites Used"), site_count, maxSites, "#16a34a");
        frm.fields_dict.notes.$wrapper.find(".fq-usage-widget").append(bar);
    },

    // -----------------------------------------------------------------
    // Upgrade dialog
    // -----------------------------------------------------------------
    show_upgrade_dialog(frm) {
        const currentPlan = frm.doc.plan || "free";
        const plans = [
            { key: "free",       label: "Free — $0/mo",        desc: "1 site · 120 rpm · Monitor only" },
            { key: "pro",        label: "Pro — $49/mo",        desc: "10 sites · 600 rpm · Federation + Campaigns" },
            { key: "enterprise", label: "Enterprise — $199/mo", desc: "100 sites · 2000 rpm · Full suite" },
        ].filter(p => p.key !== currentPlan);

        const d = new frappe.ui.Dialog({
            title: __("Upgrade / Change Plan"),
            fields: [
                {
                    fieldtype: "Select",
                    fieldname: "new_plan",
                    label: __("Select Plan"),
                    options: plans.map(p => ({ label: p.label, value: p.key })),
                    reqd: 1,
                },
            ],
            primary_action_label: __("Confirm Change"),
            primary_action({ new_plan }) {
                d.hide();
                frappe.confirm(
                    __("Change plan from <b>{0}</b> to <b>{1}</b>? This will update your ERPNext subscription.",
                       [currentPlan, new_plan]),
                    () => {
                        frappe.call({
                            method: "frappe.client.set_value",
                            args: {
                                doctype: "FrothIQ Tenant",
                                name: frm.docname,
                                fieldname: "plan",
                                value: new_plan,
                            },
                            callback() {
                                frm.reload_doc();
                                frappe.show_alert({
                                    message: __("Plan updated. Subscription will sync in the next 5 minutes."),
                                    indicator: "green",
                                }, 6);
                            },
                        });
                    }
                );
            },
        });
        d.show();
    },
});

// ---------------------------------------------------------------------------
// Tiny helper — renders an HTML progress bar row
// ---------------------------------------------------------------------------
function _bar(label, value, max, color) {
    const pct = max > 0 ? Math.min(Math.round(value / max * 100), 100) : 0;
    return `
    <div style="margin-bottom:8px;">
        <div style="display:flex;justify-content:space-between;
            font-size:.78rem;margin-bottom:3px;color:#475569;">
            <span>${label}</span>
            <span>${value} / ${max}</span>
        </div>
        <div style="background:#e2e8f0;border-radius:100px;height:6px;overflow:hidden;">
            <div style="width:${pct}%;background:${color};height:100%;border-radius:100px;
                transition:width .3s;"></div>
        </div>
    </div>`;
}
