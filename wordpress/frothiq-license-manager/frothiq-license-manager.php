<?php
/**
 * Plugin Name:  FrothIQ License Manager
 * Plugin URI:   https://frothiq.com
 * Description:  Edge license enforcement for the FrothIQ security platform.
 *               Validates signed license tokens from the FrothIQ control center,
 *               enforces feature gating, and runs a 6-hour heartbeat sync.
 * Version:      1.0.0
 * Requires PHP: 8.1
 * Author:       OrbWeaver
 * License:      Proprietary
 *
 * DESIGN CONTRACT
 * ===============
 *  FAIL CLOSED:  missing / invalid / unsigned token → quarantine mode.
 *  NO ONLINE CHECK ON EVERY REQUEST: local HMAC verify + TTL check only.
 *  CACHE FALLBACK: last valid token cached in wp_options for up to 4 hours
 *                  during control center outages.
 *
 * @package   FrothIQ\WordPress
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'FROTHIQ_WP_VERSION',  '1.0.0' );
define( 'FROTHIQ_WP_SDK_DIR',  plugin_dir_path( __FILE__ ) . '../../../edge_sdk/php/' );
define( 'FROTHIQ_WP_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

// ---------------------------------------------------------------------------
// Autoload the FrothIQ Edge SDK PHP classes
// ---------------------------------------------------------------------------

$_frothiq_sdk_files = [
    'Exceptions.php',
    'LicenseResult.php',
    'TokenValidator.php',
    'FeatureGate.php',
    'OfflineGraceManager.php',
    'SyncClient.php',
    'AuditEmitter.php',
    'FrothIQSDKBase.php',
];

foreach ( $_frothiq_sdk_files as $_file ) {
    $path = FROTHIQ_WP_SDK_DIR . $_file;
    if ( file_exists( $path ) ) {
        require_once $path;
    }
}
unset( $_frothiq_sdk_files, $_file, $path );

// Plugin-specific classes
require_once FROTHIQ_WP_PLUGIN_DIR . 'includes/class-wp-storage.php';
require_once FROTHIQ_WP_PLUGIN_DIR . 'includes/class-admin.php';


// ---------------------------------------------------------------------------
// Singleton accessor
// ---------------------------------------------------------------------------

/**
 * Return the singleton FrothIQ_WP_LicenseManager instance.
 * Returns null if the signing key is not configured — callers
 * must handle null (license will fail closed inside the manager anyway,
 * but returning null avoids instantiating the class unnecessarily).
 */
function frothiq_get_license_manager(): ?FrothIQ_WP_LicenseManager {
    static $instance = null;
    if ( $instance === null ) {
        $instance = new FrothIQ_WP_LicenseManager();
    }
    return $instance;
}

/**
 * Shortcut: return the current LicenseResult.
 * FAIL CLOSED: returns a quarantine result if manager is unavailable.
 */
function frothiq_get_license(): \FrothIQ\EdgeSDK\LicenseResult {
    $manager = frothiq_get_license_manager();
    return $manager
        ? $manager->validate()
        : \FrothIQ\EdgeSDK\LicenseResult::quarantine( 'manager_unavailable' );
}

/**
 * Shortcut: check if a feature is available in the current license.
 * FAIL CLOSED: returns false if manager is unavailable.
 *
 * @param  string $feature  e.g. 'defense_mesh', 'campaigns'
 * @return bool
 */
function frothiq_has_feature( string $feature ): bool {
    $manager = frothiq_get_license_manager();
    return $manager ? $manager->hasFeature( $feature ) : false;
}


// ---------------------------------------------------------------------------
// Plugin lifecycle hooks
// ---------------------------------------------------------------------------

register_activation_hook( __FILE__, 'frothiq_wp_activate' );
register_deactivation_hook( __FILE__, 'frothiq_wp_deactivate' );

function frothiq_wp_activate(): void {
    // Register 6-hour cron schedule
    if ( ! wp_next_scheduled( 'frothiq_license_heartbeat' ) ) {
        wp_schedule_event( time(), 'frothiq_6h', 'frothiq_license_heartbeat' );
    }
}

function frothiq_wp_deactivate(): void {
    wp_clear_scheduled_hook( 'frothiq_license_heartbeat' );
}


// ---------------------------------------------------------------------------
// Custom cron schedule — 6 hours
// ---------------------------------------------------------------------------

add_filter( 'cron_schedules', function ( array $schedules ): array {
    $schedules['frothiq_6h'] = [
        'interval' => 6 * 3600,
        'display'  => 'Every 6 Hours (FrothIQ)',
    ];
    return $schedules;
} );


// ---------------------------------------------------------------------------
// Heartbeat cron callback
// ---------------------------------------------------------------------------

add_action( 'frothiq_license_heartbeat', 'frothiq_wp_do_heartbeat' );

function frothiq_wp_do_heartbeat(): void {
    $manager = frothiq_get_license_manager();
    if ( $manager ) {
        $manager->heartbeat();
    }
}


// ---------------------------------------------------------------------------
// Admin UI
// ---------------------------------------------------------------------------

if ( is_admin() ) {
    add_action( 'plugins_loaded', function (): void {
        new FrothIQ_Admin();
    } );
}
