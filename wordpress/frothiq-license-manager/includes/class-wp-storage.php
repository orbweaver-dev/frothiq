<?php
/**
 * FrothIQ WordPress SDK — WordPress Storage Adapter
 *
 * Implements the 5 abstract storage methods required by FrothIQSDKBase
 * using WordPress's wp_options table.
 *
 * Options used
 * ------------
 *   frothiq_license_token          — license token JSON
 *   frothiq_license_last_valid_ts  — last successful validation Unix timestamp
 *
 * Signing key resolution order
 * ----------------------------
 *   1. FROTHIQ_LICENSE_SECRET constant (wp-config.php)
 *   2. frothiq_license_secret wp_option (admin settings page)
 *   3. Empty string → signing_key_not_configured → quarantine
 *
 * @package   FrothIQ\WordPress
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

use FrothIQ\EdgeSDK\FrothIQSDKBase;
use FrothIQ\EdgeSDK\AuditEmitterBase;
use FrothIQ\EdgeSDK\FileAuditEmitter;
use FrothIQ\EdgeSDK\SyncClient;

class FrothIQ_WP_LicenseManager extends FrothIQSDKBase
{
    // wp_options keys
    private const OPT_TOKEN      = 'frothiq_license_token';
    private const OPT_LAST_TS    = 'frothiq_license_last_valid_ts';
    private const OPT_SECRET     = 'frothiq_license_secret';
    private const OPT_TENANT_ID  = 'frothiq_tenant_id';
    private const OPT_AGENT_ID   = 'frothiq_agent_id';
    private const OPT_CC_URL     = 'frothiq_control_center_url';
    private const OPT_VERSION    = 'frothiq_license_version';

    // ------------------------------------------------------------------
    // FrothIQSDKBase — storage implementation
    // ------------------------------------------------------------------

    protected function getSigningKey(): string
    {
        // wp-config.php constant takes priority
        if ( defined( 'FROTHIQ_LICENSE_SECRET' ) && FROTHIQ_LICENSE_SECRET !== '' ) {
            return FROTHIQ_LICENSE_SECRET;
        }
        return (string) get_option( self::OPT_SECRET, '' );
    }

    protected function loadTokenJson(): string
    {
        return (string) get_option( self::OPT_TOKEN, '' );
    }

    protected function saveTokenJson( string $json ): void
    {
        update_option( self::OPT_TOKEN, $json, false /* not autoload */ );
    }

    protected function loadLastValidTs(): float
    {
        return (float) get_option( self::OPT_LAST_TS, 0 );
    }

    protected function saveLastValidTs( float $ts ): void
    {
        update_option( self::OPT_LAST_TS, $ts, false );
    }

    // ------------------------------------------------------------------
    // FrothIQSDKBase — optional overrides
    // ------------------------------------------------------------------

    protected function getExpectedTenantId(): ?string
    {
        $tid = (string) get_option( self::OPT_TENANT_ID, '' );
        return $tid !== '' ? $tid : null;
    }

    protected function getAgentId(): string
    {
        return (string) get_option( self::OPT_AGENT_ID, '' );
    }

    protected function createAuditEmitter(): AuditEmitterBase
    {
        // Write to WordPress uploads/frothiq/ directory
        $upload_dir = wp_upload_dir();
        $log_dir    = trailingslashit( $upload_dir['basedir'] ) . 'frothiq/';
        wp_mkdir_p( $log_dir );
        return new FileAuditEmitter( $log_dir . 'license_audit.jsonl' );
    }

    protected function createSyncClient( string $controlCenterUrl ): SyncClient
    {
        return new WP_FrothIQ_SyncClient( $controlCenterUrl );
    }

    // ------------------------------------------------------------------
    // WordPress-specific helpers
    // ------------------------------------------------------------------

    public function getControlCenterUrl(): string
    {
        return (string) get_option( self::OPT_CC_URL, '' );
    }

    public function getCurrentVersion(): int
    {
        return (int) get_option( self::OPT_VERSION, 0 );
    }

    public function incrementVersion(): void
    {
        update_option( self::OPT_VERSION, $this->getCurrentVersion() + 1, false );
    }

    /** Perform heartbeat using stored configuration. */
    public function heartbeat(): bool
    {
        $ccUrl    = $this->getControlCenterUrl();
        $tenantId = (string) get_option( self::OPT_TENANT_ID, '' );
        $agentId  = (string) get_option( self::OPT_AGENT_ID, '' );

        if ( $ccUrl === '' || $tenantId === '' ) {
            return false;
        }

        $updated = $this->refresh( $ccUrl, $tenantId, $agentId, $this->getCurrentVersion() );
        if ( $updated ) {
            $this->incrementVersion();
        }
        return $updated;
    }
}


// ---------------------------------------------------------------------------
// WordPress-specific HTTP client (uses WP_Http instead of stream context)
// ---------------------------------------------------------------------------

use FrothIQ\EdgeSDK\SyncResult;

class WP_FrothIQ_SyncClient extends SyncClient
{
    private string $url;

    public function __construct( string $controlCenterUrl )
    {
        parent::__construct( $controlCenterUrl );
        $this->url = rtrim( $controlCenterUrl, '/' );
    }

    public function sync(
        string $tenantId,
        string $agentId,
        string $currentTokenJson = '',
        int    $currentVersion   = 0,
        string $requestReason    = 'wp_heartbeat'
    ): SyncResult {
        if ( $tenantId === '' ) {
            return SyncResult::failure( 'tenant_id_required' );
        }

        $endpoint = $this->url . '/api/method/orbweaver_frothiq.license_system.license_api.sync_license';
        $body     = wp_json_encode( [
            'payload' => [
                'agent_id'                => $agentId,
                'tenant_id'               => $tenantId,
                'current_license_version' => $currentVersion,
                'token_json'              => $currentTokenJson,
                'request_reason'          => $requestReason,
            ],
        ] );

        $response = wp_remote_post( $endpoint, [
            'timeout' => 10,
            'headers' => [ 'Content-Type' => 'application/json' ],
            'body'    => $body,
        ] );

        if ( is_wp_error( $response ) ) {
            return SyncResult::failure( 'http_error: ' . $response->get_error_message() );
        }

        $parsed = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( ! is_array( $parsed ) ) {
            return SyncResult::failure( 'invalid_response_json' );
        }

        $msg = $parsed['message'] ?? $parsed;
        if ( empty( $msg['license_token'] ) ) {
            return SyncResult::failure( 'no_license_token_in_response' );
        }

        $tokenJson = wp_json_encode( $msg['license_token'] );
        return new SyncResult(
            success:    true,
            updated:    (bool) ( $msg['updated'] ?? false ),
            tokenJson:  $tokenJson ?: null,
            serverTime: (float) ( $msg['server_time'] ?? 0.0 ),
        );
    }
}
