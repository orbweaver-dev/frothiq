// Copyright (c) 2026, OrbWeaver — Proprietary

frappe.ui.form.on("FrothIQ API Key", {
    refresh(frm) {
        // ── Status badge ──────────────────────────────────────────────────
        if (frm.doc.revoked) {
            frm.dashboard.set_headline_alert(
                '<span class="indicator red"> REVOKED — this key is inactive</span>'
            );
        } else {
            frm.dashboard.set_headline_alert(
                '<span class="indicator green"> ACTIVE</span>'
            );
        }

        // ── Copy key button ───────────────────────────────────────────────
        if (frm.doc.key && !frm.is_new()) {
            frm.add_custom_button("Copy API Key", () => {
                navigator.clipboard.writeText(frm.doc.key).then(() => {
                    frappe.show_alert({ message: "API key copied to clipboard", indicator: "green" });
                }).catch(() => {
                    // Fallback for browsers without clipboard API
                    const tmp = document.createElement("textarea");
                    tmp.value = frm.doc.key;
                    document.body.appendChild(tmp);
                    tmp.select();
                    document.execCommand("copy");
                    document.body.removeChild(tmp);
                    frappe.show_alert({ message: "API key copied", indicator: "green" });
                });
            }, "Actions");
        }

        // ── Revoke button (Customer Admin only) ───────────────────────────
        if (!frm.is_new() && !frm.doc.revoked &&
            frappe.user.has_role(["FrothIQ Customer Admin", "FrothIQ Admin", "System Manager"])) {
            frm.add_custom_button("Revoke Key", () => {
                frappe.confirm(
                    "Are you sure you want to <strong>revoke</strong> this API key? "
                    + "Any agents using it will lose connectivity immediately.",
                    () => {
                        frappe.call({
                            method: "orbweaver_frothiq.frothiq_portal.api.portal_api.revoke_api_key",
                            args: { key_name: frm.doc.name },
                            freeze: true,
                            freeze_message: "Revoking key…",
                            callback(r) {
                                if (r.message && r.message.revoked) {
                                    frm.reload_doc();
                                    frappe.show_alert({ message: "API key revoked", indicator: "red" });
                                }
                            },
                        });
                    }
                );
            }, "Actions");
        }

        // ── New key alert ─────────────────────────────────────────────────
        // Show the full key once right after creation via portal_api.create_api_key
        const savedKey = sessionStorage.getItem(`frothiq_new_key_${frm.doc.name}`);
        if (savedKey) {
            frappe.msgprint({
                title: "Save your API Key",
                message: `
                    <p>Your new API key has been generated. <strong>Copy it now</strong> —
                    it will not be shown again in full.</p>
                    <pre style="background:#f3f4f6;padding:12px;border-radius:6px;
                                font-family:monospace;font-size:0.9rem;word-break:break-all;">
${savedKey}</pre>
                    <button class="btn btn-sm btn-default" onclick="
                        navigator.clipboard.writeText('${savedKey}');
                        frappe.show_alert({message:'Copied!',indicator:'green'});
                    ">Copy</button>
                `,
                indicator: "blue",
            });
            sessionStorage.removeItem(`frothiq_new_key_${frm.doc.name}`);
        }
    },
});
