<?php
/**
 * FrothIQ License Manager — WordPress Plugin Stub
 *
 * Phase 3 stub: License validation integration for the WordPress edge plugin.
 * Implements the FrothIQ License SDK contract in PHP, mirroring the Python
 * reference implementation in frothiq_license_sdk.py.
 *
 * DESIGN CONTRACT (mirrors Python SDK)
 * =====================================
 *   FAIL CLOSED:  missing / invalid / unsigned token → quarantine mode.
 *   NO ONLINE CHECK ON EVERY REQUEST: local HMAC verify + TTL check only.
 *   CACHE FALLBACK: last valid token cached in wp_options for up to 4 hours
 *                   during control center outages.
 *
 * Enforcement modes
 * -----------------
 *   full_enforcement — active valid license; all protection actions enabled
 *   monitor_only     — expired token; log only, no block actions
 *   quarantine       — suspended or missing; read-only logs, no actions
 *
 * Token sync
 * ----------
 *   Heartbeat runs via wp-cron every 6 hours calling:
 *     POST {control_center}/api/method/orbweaver_frothiq.license_system.license_api.sync_license
 *   Payload: { agent_id, tenant_id, current_license_version, request_reason }
 *
 * @package   FrothIQ\LicenseManager
 * @version   1.0.0-stub
 * @copyright 2026, OrbWeaver — Proprietary
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'FROTHIQ_LICENSE_VERSION', '1.0.0-stub' );
define( 'FROTHIQ_LICENSE_OPTION_KEY', 'frothiq_license_token' );
define( 'FROTHIQ_LICENSE_TS_KEY', 'frothiq_license_last_valid_ts' );
define( 'FROTHIQ_LICENSE_OFFLINE_GRACE', 4 * 3600 ); // 4 hours in seconds
define( 'FROTHIQ_LICENSE_SCHEMA_VERSION', 1 );

// ---------------------------------------------------------------------------
// Enforcement mode constants (mirrors Python SDK)
// ---------------------------------------------------------------------------
define( 'FROTHIQ_MODE_FULL',      'full_enforcement' );
define( 'FROTHIQ_MODE_MONITOR',   'monitor_only' );
define( 'FROTHIQ_MODE_QUARANTINE','quarantine' );


// ---------------------------------------------------------------------------
// FrothIQ_License_Result — validation result value object
// ---------------------------------------------------------------------------

class FrothIQ_License_Result {
    /** @var bool */
    public $valid;
    /** @var string full_enforcement | monitor_only | quarantine */
    public $enforcement_mode;
    /** @var string human-readable reason */
    public $reason;
    /** @var string free | pro | enterprise */
    public $plan;
    /** @var array feature flag map */
    public $features;
    /** @var array rate/site limit map */
    public $limits;
    /** @var string tenant identifier (verified) */
    public $tenant_id;

    public function __construct(
        bool   $valid,
        string $enforcement_mode,
        string $reason,
        string $plan      = 'free',
        array  $features  = [],
        array  $limits    = [],
        string $tenant_id = ''
    ) {
        $this->valid            = $valid;
        $this->enforcement_mode = $enforcement_mode;
        $this->reason           = $reason;
        $this->plan             = $plan;
        $this->features         = $features;
        $this->limits           = $limits;
        $this->tenant_id        = $tenant_id;
    }

    /** True only when the license allows active blocking. */
    public function can_block(): bool {
        return $this->enforcement_mode === FROTHIQ_MODE_FULL;
    }

    /** True when the license allows event logging. */
    public function can_log(): bool {
        return in_array( $this->enforcement_mode, [ FROTHIQ_MODE_FULL, FROTHIQ_MODE_MONITOR ], true );
    }

    /** Check whether a named feature flag is enabled. */
    public function has_feature( string $feature ): bool {
        return ! empty( $this->features[ $feature ] );
    }

    /** Fail-closed quarantine singleton. */
    public static function quarantine( string $reason = 'missing_or_invalid_license' ): self {
        return new self( false, FROTHIQ_MODE_QUARANTINE, $reason );
    }

    /** Monitor-only result. */
    public static function monitor( string $reason, string $plan = 'free', array $features = [], array $limits = [], string $tenant_id = '' ): self {
        return new self( false, FROTHIQ_MODE_MONITOR, $reason, $plan, $features, $limits, $tenant_id );
    }
}


// ---------------------------------------------------------------------------
// FrothIQ_License_Manager — main validator
// ---------------------------------------------------------------------------

class FrothIQ_License_Manager {

    /** @var string HMAC-SHA256 signing key (bytes) — loaded from wp_options or env */
    private string $signing_key;

    public function __construct( string $signing_key ) {
        $this->signing_key = $signing_key;
    }

    /**
     * Primary entry point — validates the current stored license token.
     *
     * Mirrors Python SDK validate_license_token() semantics:
     *   1. Load token from wp_options cache
     *   2. Parse + schema check
     *   3. Tenant binding check (if configured)
     *   4. HMAC-SHA256 signature verification
     *   5. Expiry check + offline grace fallback
     *   6. Status check
     *
     * @param string|null $expected_tenant_id  Optional tenant binding.
     * @return FrothIQ_License_Result          NEVER throws.
     */
    public function validate( ?string $expected_tenant_id = null ): FrothIQ_License_Result {
        $token_json = get_option( FROTHIQ_LICENSE_OPTION_KEY, '' );
        $last_valid = (float) get_option( FROTHIQ_LICENSE_TS_KEY, 0 );

        if ( empty( $token_json ) ) {
            return FrothIQ_License_Result::quarantine( 'missing_license_token' );
        }

        try {
            $token = $this->parse_token( $token_json );
        } catch ( Exception $e ) {
            return $this->offline_fallback( $token_json, $last_valid, 'parse_error: ' . $e->getMessage() );
        }

        // Schema version check
        if ( (int) ( $token['schema_version'] ?? 1 ) !== FROTHIQ_LICENSE_SCHEMA_VERSION ) {
            return FrothIQ_License_Result::quarantine( 'unknown_schema_version' );
        }

        // Tenant binding
        if ( $expected_tenant_id !== null && ( $token['tenant_id'] ?? '' ) !== $expected_tenant_id ) {
            return FrothIQ_License_Result::quarantine( 'tenant_id_mismatch' );
        }

        // Signature verification (FAIL CLOSED)
        if ( ! $this->verify_signature( $token ) ) {
            return FrothIQ_License_Result::quarantine( 'signature_invalid' );
        }

        // Expiry check
        if ( time() >= (float) ( $token['expires_at'] ?? 0 ) ) {
            return $this->offline_fallback( $token_json, $last_valid, 'token_expired', $token );
        }

        // Status check
        $status = strtolower( $token['status'] ?? '' );
        if ( $status === 'suspended' ) {
            return new FrothIQ_License_Result(
                false,
                FROTHIQ_MODE_QUARANTINE,
                'license_suspended',
                $token['plan'] ?? 'free',
                (array) ( $token['features'] ?? [] ),
                (array) ( $token['limits']   ?? [] ),
                $token['tenant_id'] ?? ''
            );
        }

        $mode = in_array( $status, [ 'active', 'trial' ], true )
            ? FROTHIQ_MODE_FULL
            : FROTHIQ_MODE_MONITOR;

        // Update last-valid timestamp on successful validation
        update_option( FROTHIQ_LICENSE_TS_KEY, time() );

        return new FrothIQ_License_Result(
            true,
            $mode,
            'ok',
            $token['plan']      ?? 'free',
            (array) ( $token['features'] ?? [] ),
            (array) ( $token['limits']   ?? [] ),
            $token['tenant_id'] ?? ''
        );
    }

    /**
     * Store a raw license token JSON string received from the control center.
     * Called by the sync heartbeat after a successful /sync_license response.
     */
    public function store_token( string $token_json ): bool {
        // Validate before storing — reject tampered tokens
        $result = $this->validate_json( $token_json );
        if ( $result->enforcement_mode === FROTHIQ_MODE_QUARANTINE ) {
            return false;
        }
        update_option( FROTHIQ_LICENSE_OPTION_KEY, $token_json );
        update_option( FROTHIQ_LICENSE_TS_KEY, time() );
        return true;
    }

    /**
     * Validate an arbitrary token JSON string (used by store_token).
     * Signature is verified but no tenant binding check is applied.
     */
    public function validate_json( string $token_json, ?string $expected_tenant_id = null ): FrothIQ_License_Result {
        try {
            $token = $this->parse_token( $token_json );
        } catch ( Exception $e ) {
            return FrothIQ_License_Result::quarantine( 'parse_error' );
        }
        if ( ! $this->verify_signature( $token ) ) {
            return FrothIQ_License_Result::quarantine( 'signature_invalid' );
        }
        if ( $expected_tenant_id !== null && ( $token['tenant_id'] ?? '' ) !== $expected_tenant_id ) {
            return FrothIQ_License_Result::quarantine( 'tenant_id_mismatch' );
        }
        return new FrothIQ_License_Result(
            true, FROTHIQ_MODE_FULL, 'ok',
            $token['plan'] ?? 'free',
            (array) ( $token['features'] ?? [] ),
            (array) ( $token['limits']   ?? [] ),
            $token['tenant_id'] ?? ''
        );
    }

    // ------------------------------------------------------------------
    // Private: signature verification
    // ------------------------------------------------------------------

    /**
     * Verify the HMAC-SHA256 signature on a decoded token array.
     *
     * Canonical form: JSON-encode payload (minus "signature") with
     * keys sorted alphabetically, no whitespace, UTF-8.  Must exactly
     * match the Python SDK _compute_signature() logic.
     */
    private function verify_signature( array $token ): bool {
        $submitted = $token['signature'] ?? '';
        if ( empty( $submitted ) ) {
            return false;
        }
        $payload  = $token;
        unset( $payload['signature'] );
        $canonical = $this->canonical_json( $payload );
        $expected  = hash_hmac( 'sha256', $canonical, $this->signing_key );
        // Constant-time comparison
        return hash_equals( $expected, $submitted );
    }

    /**
     * Produce canonical JSON: sorted keys, no whitespace, UTF-8.
     * Recursively sorts nested arrays/objects.
     */
    private function canonical_json( array $data ): string {
        ksort( $data );
        foreach ( $data as $key => $val ) {
            if ( is_array( $val ) ) {
                $data[ $key ] = $this->canonical_json( $val );
            }
        }
        return json_encode( $data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES );
    }

    // ------------------------------------------------------------------
    // Private: parsing
    // ------------------------------------------------------------------

    /**
     * Parse token JSON and validate required fields.
     *
     * @throws RuntimeException on parse failure or missing fields.
     */
    private function parse_token( string $token_json ): array {
        if ( empty( $token_json ) ) {
            throw new RuntimeException( 'empty token_json' );
        }
        $data = json_decode( $token_json, true );
        if ( ! is_array( $data ) ) {
            throw new RuntimeException( 'token must be a JSON object' );
        }
        $required = [ 'tenant_id', 'license_id', 'plan', 'status', 'signature',
                       'issued_at', 'expires_at', 'features', 'limits' ];
        foreach ( $required as $field ) {
            if ( ! array_key_exists( $field, $data ) ) {
                throw new RuntimeException( "missing required field: {$field}" );
            }
        }
        return $data;
    }

    // ------------------------------------------------------------------
    // Private: offline fallback
    // ------------------------------------------------------------------

    private function offline_fallback(
        string  $cached_json,
        float   $last_valid_ts,
        string  $reason,
        ?array  $expired_token = null
    ): FrothIQ_License_Result {
        // If we have an expired token's data, return monitor_only with that plan
        if ( $expired_token !== null && $last_valid_ts <= 0 ) {
            return FrothIQ_License_Result::monitor(
                $reason,
                $expired_token['plan']      ?? 'free',
                (array) ( $expired_token['features'] ?? [] ),
                (array) ( $expired_token['limits']   ?? [] ),
                $expired_token['tenant_id'] ?? ''
            );
        }

        // No valid cached state
        if ( $last_valid_ts <= 0 ) {
            return FrothIQ_License_Result::quarantine( $reason );
        }

        $grace_elapsed = time() - $last_valid_ts;
        if ( $grace_elapsed <= FROTHIQ_LICENSE_OFFLINE_GRACE ) {
            try {
                $cached = $this->parse_token( $cached_json );
                return FrothIQ_License_Result::monitor(
                    $reason . '_offline_grace',
                    $cached['plan']      ?? 'free',
                    (array) ( $cached['features'] ?? [] ),
                    (array) ( $cached['limits']   ?? [] ),
                    $cached['tenant_id'] ?? ''
                );
            } catch ( Exception $e ) {
                // Cache corrupt — fall through to quarantine
            }
        }

        return FrothIQ_License_Result::quarantine( $reason );
    }
}


// ---------------------------------------------------------------------------
// Sync heartbeat (wp-cron)
// ---------------------------------------------------------------------------

/**
 * Register the heartbeat cron schedule if not already present.
 * Called on plugin activation.
 */
function frothiq_license_activate(): void {
    if ( ! wp_next_scheduled( 'frothiq_license_heartbeat' ) ) {
        wp_schedule_event( time(), 'frothiq_6h', 'frothiq_license_heartbeat' );
    }
}
register_activation_hook( __FILE__, 'frothiq_license_activate' );

/**
 * Add a custom 6-hour cron interval.
 */
add_filter( 'cron_schedules', function ( array $schedules ): array {
    $schedules['frothiq_6h'] = [
        'interval' => 6 * 3600,
        'display'  => 'Every 6 Hours (FrothIQ)',
    ];
    return $schedules;
} );

/**
 * Heartbeat callback — syncs license with control center.
 * TODO (Phase 4): implement full HTTP sync using WP_Http.
 */
add_action( 'frothiq_license_heartbeat', 'frothiq_license_do_sync' );
function frothiq_license_do_sync(): void {
    $control_center = get_option( 'frothiq_control_center_url', '' );
    $tenant_id      = get_option( 'frothiq_tenant_id', '' );
    $agent_id       = get_option( 'frothiq_agent_id', '' );

    if ( empty( $control_center ) || empty( $tenant_id ) ) {
        return; // Not configured yet
    }

    $current_version = (int) get_option( 'frothiq_license_version', 0 );

    $response = wp_remote_post(
        trailingslashit( $control_center ) . 'api/method/orbweaver_frothiq.license_system.license_api.sync_license',
        [
            'timeout' => 10,
            'headers' => [ 'Content-Type' => 'application/json' ],
            'body'    => wp_json_encode( [
                'payload' => [
                    'agent_id'                => $agent_id,
                    'tenant_id'               => $tenant_id,
                    'current_license_version' => $current_version,
                    'request_reason'          => 'wp_heartbeat',
                ],
            ] ),
        ]
    );

    if ( is_wp_error( $response ) ) {
        return; // Offline — grace period kicks in automatically
    }

    $body = json_decode( wp_remote_retrieve_body( $response ), true );
    if ( ! empty( $body['message']['license_token'] ) ) {
        $token_json = wp_json_encode( $body['message']['license_token'] );
        // TODO: Retrieve signing key securely and pass to manager
        // frothiq_get_license_manager()->store_token( $token_json );
        update_option( 'frothiq_license_version', $current_version + 1 );
    }
}


// ---------------------------------------------------------------------------
// Global accessor
// ---------------------------------------------------------------------------

/**
 * Return the singleton FrothIQ_License_Manager instance.
 * Signing key must be configured in wp-config.php:
 *   define( 'FROTHIQ_LICENSE_SECRET', 'your-secret-key-here' );
 */
function frothiq_get_license_manager(): ?FrothIQ_License_Manager {
    static $instance = null;
    if ( $instance === null ) {
        $key = defined( 'FROTHIQ_LICENSE_SECRET' ) ? FROTHIQ_LICENSE_SECRET : '';
        if ( empty( $key ) ) {
            $key = get_option( 'frothiq_license_secret', '' );
        }
        if ( empty( $key ) ) {
            return null; // Not configured — validation will fail closed
        }
        $instance = new FrothIQ_License_Manager( $key );
    }
    return $instance;
}
