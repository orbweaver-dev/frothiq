// Copyright (c) 2026, OrbWeaver — Proprietary

frappe.ui.form.on("FrothIQ Tenant Site", {
    refresh(frm) {
        frm.set_intro("");

        // ── Status indicator ──────────────────────────────────────────────
        const statusColors = { online: "green", stale: "orange", offline: "red" };
        const color = statusColors[frm.doc.status] || "gray";
        frm.dashboard.set_headline_alert(
            `<span class="indicator ${color}"> ${(frm.doc.status || "offline").toUpperCase()}</span>`
        );

        // ── Mode toggle buttons ───────────────────────────────────────────
        if (!frm.is_new() && frappe.user.has_role(["FrothIQ Customer Admin", "FrothIQ Admin", "System Manager"])) {
            const modes = [
                { label: "Monitor", mode: "monitor", type: "default" },
                { label: "Protect", mode: "protect", type: "warning" },
                { label: "Block",   mode: "block",   type: "danger"  },
            ];
            modes.forEach(({ label, mode, type }) => {
                const isCurrent = frm.doc.mode === mode;
                frm.add_custom_button(
                    `${isCurrent ? "✓ " : ""}${label}`,
                    () => {
                        if (isCurrent) return;
                        frappe.confirm(
                            `Set protection mode to <strong>${label}</strong> for <em>${frm.doc.domain}</em>?`,
                            () => {
                                frappe.call({
                                    method: "orbweaver_frothiq.frothiq_portal.api.portal_api.set_site_mode",
                                    args: { site_name: frm.doc.name, mode },
                                    freeze: true,
                                    freeze_message: `Switching to ${label} mode…`,
                                    callback(r) {
                                        if (r.message) {
                                            frm.set_value("mode", mode);
                                            frm.refresh();
                                            frappe.show_alert({
                                                message: `Mode changed to <strong>${label}</strong>`,
                                                indicator: type === "danger" ? "red" : type === "warning" ? "orange" : "green",
                                            });
                                        }
                                    },
                                });
                            }
                        );
                    },
                    "Mode"
                );
            });
        }

        // ── Copy Agent ID ─────────────────────────────────────────────────
        if (frm.doc.agent_id) {
            frm.add_custom_button("Copy Agent ID", () => {
                navigator.clipboard.writeText(frm.doc.agent_id).then(() => {
                    frappe.show_alert({ message: "Agent ID copied to clipboard", indicator: "green" });
                });
            }, "Actions");
        }
    },

    mode(frm) {
        // Colour-code the mode selector for quick visual feedback
        const el = frm.fields_dict.mode.$wrapper.find("select, .frappe-control input");
        el.css("color", { monitor: "#0ea5e9", protect: "#f59e0b", block: "#ef4444" }[frm.doc.mode] || "");
    },
});
