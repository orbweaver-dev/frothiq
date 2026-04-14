<?php
/**
 * FrothIQ Edge SDK — Sync Client
 *
 * Handles license token heartbeat synchronisation with the FrothIQ
 * control center.  All network operations are best-effort and never
 * raise exceptions to the caller — offline grace handles degradation.
 *
 * Sync endpoint
 * -------------
 *   POST {control_center}/api/method/orbweaver_frothiq.license_system.license_api.sync_license
 *
 * Request payload
 * ---------------
 *   {
 *     "payload": {
 *       "agent_id":                string,
 *       "tenant_id":               string,
 *       "current_license_version": int,
 *       "request_reason":          string
 *     }
 *   }
 *
 * Response (on success)
 * ---------------------
 *   { "message": { "license_token": {...}, "updated": bool, "server_time": float } }
 *
 * @package   FrothIQ\EdgeSDK
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 */

declare(strict_types=1);

namespace FrothIQ\EdgeSDK;

final class SyncResult
{
    public function __construct(
        public readonly bool    $success,
        public readonly bool    $updated,
        public readonly ?string $tokenJson,
        public readonly ?string $error    = null,
        public readonly float   $serverTime = 0.0,
    ) {}

    public static function failure(string $error): self
    {
        return new self(success: false, updated: false, tokenJson: null, error: $error);
    }
}


final class SyncClient
{
    /** Default request timeout in seconds. */
    public const DEFAULT_TIMEOUT = 10;

    /** Sync endpoint path relative to control center base URL. */
    private const SYNC_PATH = '/api/method/orbweaver_frothiq.license_system.license_api.sync_license';

    private string $controlCenterUrl;
    private int    $timeoutSeconds;

    public function __construct(string $controlCenterUrl, int $timeoutSeconds = self::DEFAULT_TIMEOUT)
    {
        $this->controlCenterUrl = rtrim($controlCenterUrl, '/');
        $this->timeoutSeconds   = $timeoutSeconds;
    }

    // ------------------------------------------------------------------
    // Primary API
    // ------------------------------------------------------------------

    /**
     * Perform a heartbeat sync with the FrothIQ control center.
     *
     * Submits the agent's current token for authentication (control center
     * verifies HMAC to prove the agent holds a legitimately issued token).
     *
     * @param  string $tenantId        FrothIQ tenant identifier.
     * @param  string $agentId         Edge plugin agent identifier.
     * @param  string $currentTokenJson Current token JSON (used for auth).
     * @param  int    $currentVersion  Current token version (for update detection).
     * @param  string $requestReason   Human-readable reason string.
     * @return SyncResult              Always returns — never throws.
     */
    public function sync(
        string $tenantId,
        string $agentId,
        string $currentTokenJson = '',
        int    $currentVersion   = 0,
        string $requestReason    = 'sdk_heartbeat'
    ): SyncResult {
        if (empty($tenantId)) {
            return SyncResult::failure('tenant_id_required');
        }
        if (empty($this->controlCenterUrl)) {
            return SyncResult::failure('control_center_url_not_configured');
        }

        $url     = $this->controlCenterUrl . self::SYNC_PATH;
        $payload = json_encode([
            'payload' => [
                'agent_id'                => $agentId,
                'tenant_id'               => $tenantId,
                'current_license_version' => $currentVersion,
                'token_json'              => $currentTokenJson,
                'request_reason'          => $requestReason,
            ],
        ]);

        $responseBody = $this->httpPost($url, $payload);
        if ($responseBody === null) {
            return SyncResult::failure('http_request_failed');
        }

        $body = json_decode($responseBody, true);
        if (!is_array($body)) {
            return SyncResult::failure('invalid_response_json');
        }

        // Frappe wraps the response in "message"
        $msg = $body['message'] ?? $body;
        if (empty($msg['license_token'])) {
            return SyncResult::failure('no_license_token_in_response');
        }

        $tokenJson = json_encode($msg['license_token']);
        if ($tokenJson === false) {
            return SyncResult::failure('token_json_encode_failed');
        }

        return new SyncResult(
            success:    true,
            updated:    (bool) ($msg['updated'] ?? false),
            tokenJson:  $tokenJson,
            serverTime: (float) ($msg['server_time'] ?? 0.0),
        );
    }

    // ------------------------------------------------------------------
    // Private: HTTP transport
    // ------------------------------------------------------------------

    /**
     * Perform an HTTP POST and return the response body, or null on failure.
     *
     * Uses PHP stream context (no cURL dependency).  Platform-specific
     * subclasses (WordPress, Joomla) may override via the SDK base class
     * by providing their own SyncClient subclass.
     */
    private function httpPost(string $url, string $body): ?string
    {
        try {
            $context = stream_context_create([
                'http' => [
                    'method'        => 'POST',
                    'header'        => "Content-Type: application/json\r\n"
                                     . 'Content-Length: ' . strlen($body) . "\r\n",
                    'content'       => $body,
                    'timeout'       => $this->timeoutSeconds,
                    'ignore_errors' => true,
                ],
                'ssl' => [
                    'verify_peer'      => true,
                    'verify_peer_name' => true,
                ],
            ]);
            $response = @file_get_contents($url, false, $context);
            return ($response !== false) ? $response : null;
        } catch (\Throwable) {
            return null;
        }
    }
}
