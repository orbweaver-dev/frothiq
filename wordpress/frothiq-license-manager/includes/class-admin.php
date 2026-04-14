<?php
/**
 * FrothIQ WordPress SDK — Admin Settings Page
 *
 * Provides a WordPress admin page at:
 *   Settings → FrothIQ License
 *
 * Fields
 * ------
 *   Control Center URL   — base URL of the FrothIQ control center
 *   Tenant ID            — FrothIQ tenant identifier (FT-YYYY-XXXXX)
 *   Agent ID             — this plugin instance's agent identifier
 *   License Secret       — HMAC signing key (if not defined in wp-config.php)
 *
 * The license secret should be set via wp-config.php when possible:
 *   define( 'FROTHIQ_LICENSE_SECRET', 'your-secret-key' );
 *
 * @package   FrothIQ\WordPress
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class FrothIQ_Admin
{
    private const PAGE_SLUG   = 'frothiq-license';
    private const OPTION_GROUP = 'frothiq_license_settings';
    private const SECTION_ID   = 'frothiq_main_section';

    private const FIELDS = [
        'frothiq_control_center_url' => [
            'label'       => 'Control Center URL',
            'type'        => 'url',
            'placeholder' => 'https://your-site.frappe.io',
            'description' => 'Base URL of the FrothIQ control center (Frappe site).',
        ],
        'frothiq_tenant_id' => [
            'label'       => 'Tenant ID',
            'type'        => 'text',
            'placeholder' => 'FT-2026-12345',
            'description' => 'Your FrothIQ tenant identifier. Found in FrothIQ Tenant record.',
        ],
        'frothiq_agent_id' => [
            'label'       => 'Agent ID',
            'type'        => 'text',
            'placeholder' => 'wp-mysite-001',
            'description' => 'Unique identifier for this WordPress plugin instance.',
        ],
        'frothiq_license_secret' => [
            'label'       => 'License Secret (fallback)',
            'type'        => 'password',
            'placeholder' => '',
            'description' => 'HMAC signing key. Prefer setting FROTHIQ_LICENSE_SECRET in wp-config.php instead.',
        ],
    ];

    public function __construct()
    {
        add_action( 'admin_menu',    [ $this, 'addMenuPage' ] );
        add_action( 'admin_init',    [ $this, 'registerSettings' ] );
        add_action( 'admin_notices', [ $this, 'renderLicenseNotice' ] );
    }

    // ------------------------------------------------------------------
    // Menu + page registration
    // ------------------------------------------------------------------

    public function addMenuPage(): void
    {
        add_options_page(
            'FrothIQ License',
            'FrothIQ License',
            'manage_options',
            self::PAGE_SLUG,
            [ $this, 'renderPage' ]
        );
    }

    public function registerSettings(): void
    {
        foreach ( array_keys( self::FIELDS ) as $option_name ) {
            register_setting(
                self::OPTION_GROUP,
                $option_name,
                [ 'sanitize_callback' => 'sanitize_text_field' ]
            );
        }

        add_settings_section(
            self::SECTION_ID,
            'License Configuration',
            [ $this, 'renderSectionDescription' ],
            self::PAGE_SLUG
        );

        foreach ( self::FIELDS as $option_name => $field ) {
            add_settings_field(
                $option_name,
                esc_html( $field['label'] ),
                [ $this, 'renderField' ],
                self::PAGE_SLUG,
                self::SECTION_ID,
                array_merge( $field, [ 'option_name' => $option_name ] )
            );
        }
    }

    // ------------------------------------------------------------------
    // Render
    // ------------------------------------------------------------------

    public function renderSectionDescription(): void
    {
        echo '<p>Connect this WordPress site to the FrothIQ control center.</p>';
    }

    public function renderField( array $args ): void
    {
        $option_name = esc_attr( $args['option_name'] );
        $value       = ( $args['type'] === 'password' && defined( 'FROTHIQ_LICENSE_SECRET' ) )
            ? ''
            : esc_attr( (string) get_option( $option_name, '' ) );
        $type        = esc_attr( $args['type'] );
        $placeholder = esc_attr( $args['placeholder'] );
        $description = esc_html( $args['description'] );

        if ( $args['type'] === 'password' && defined( 'FROTHIQ_LICENSE_SECRET' ) ) {
            echo '<p><em>FROTHIQ_LICENSE_SECRET is defined in wp-config.php — this field is ignored.</em></p>';
            return;
        }

        echo "<input type=\"{$type}\" name=\"{$option_name}\" id=\"{$option_name}\" "
           . "value=\"{$value}\" placeholder=\"{$placeholder}\" class=\"regular-text\">";
        echo "<p class=\"description\">{$description}</p>";
    }

    public function renderPage(): void
    {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        // Handle manual sync request
        if ( isset( $_POST['frothiq_do_sync'] ) && check_admin_referer( 'frothiq_sync' ) ) {
            $manager = frothiq_get_license_manager();
            $updated = $manager ? $manager->heartbeat() : false;
            add_settings_error(
                'frothiq_license',
                'frothiq_sync',
                $updated ? '✓ License token refreshed successfully.' : '✗ Sync failed — check URL and tenant ID.',
                $updated ? 'updated' : 'error'
            );
        }

        settings_errors( 'frothiq_license' );

        // Show current license status
        $manager = frothiq_get_license_manager();
        $summary = $manager ? $manager->getEnforcementSummary() : null;

        echo '<div class="wrap">';
        echo '<h1>FrothIQ License</h1>';

        if ( $summary ) {
            $mode  = esc_html( $summary['enforcement_mode'] );
            $plan  = esc_html( strtoupper( $summary['plan'] ) );
            $color = match ( $summary['enforcement_mode'] ) {
                'full_enforcement' => '#46b450',
                'monitor_only'     => '#ffb900',
                default            => '#dc3232',
            };
            echo "<div style=\"padding:12px 16px;border-left:4px solid {$color};background:#fff;margin-bottom:16px;\">"
               . "<strong>Status:</strong> {$mode} &nbsp;|&nbsp; <strong>Plan:</strong> {$plan}"
               . ( $summary['is_in_grace'] ? ' &nbsp;<em>(offline grace period active)</em>' : '' )
               . '</div>';
        }

        echo '<form method="post" action="options.php">';
        settings_fields( self::OPTION_GROUP );
        do_settings_sections( self::PAGE_SLUG );
        submit_button( 'Save Settings' );
        echo '</form>';

        // Manual sync button
        echo '<hr>';
        echo '<h2>Manual Sync</h2>';
        echo '<form method="post">';
        wp_nonce_field( 'frothiq_sync' );
        echo '<p>Fetch the latest license token from the control center immediately.</p>';
        echo '<input type="hidden" name="frothiq_do_sync" value="1">';
        submit_button( 'Sync License Now', 'secondary' );
        echo '</form>';
        echo '</div>';
    }

    // ------------------------------------------------------------------
    // Admin notice — shown on all admin pages when license is not healthy
    // ------------------------------------------------------------------

    public function renderLicenseNotice(): void
    {
        $manager = frothiq_get_license_manager();
        if ( ! $manager ) {
            echo '<div class="notice notice-warning is-dismissible">'
               . '<p><strong>FrothIQ:</strong> License key not configured. '
               . 'Go to <a href="' . esc_url( admin_url( 'options-general.php?page=' . self::PAGE_SLUG ) ) . '">Settings → FrothIQ License</a>.</p>'
               . '</div>';
            return;
        }

        $result = $manager->validate();
        if ( $result->enforcementMode === 'quarantine' && $result->reason !== 'signing_key_not_configured' ) {
            echo '<div class="notice notice-error is-dismissible">'
               . '<p><strong>FrothIQ:</strong> License is not active (' . esc_html( $result->reason ) . '). '
               . 'Protection features are disabled.</p>'
               . '</div>';
        } elseif ( $result->enforcementMode === 'monitor_only' ) {
            echo '<div class="notice notice-warning is-dismissible">'
               . '<p><strong>FrothIQ:</strong> License expired — running in monitor-only mode. '
               . 'Blocking actions are disabled.</p>'
               . '</div>';
        }
    }
}
