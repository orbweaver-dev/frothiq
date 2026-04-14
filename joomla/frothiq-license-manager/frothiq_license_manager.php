<?php
/**
 * FrothIQ License Manager — Joomla Plugin Stub
 *
 * Phase 3 stub: License validation integration for the Joomla edge plugin.
 * Implements the FrothIQ License SDK contract in PHP, mirroring the Python
 * reference implementation in frothiq_license_sdk.py.
 *
 * DESIGN CONTRACT (mirrors Python SDK)
 * =====================================
 *   FAIL CLOSED:  missing / invalid / unsigned token → quarantine mode.
 *   NO ONLINE CHECK ON EVERY REQUEST: local HMAC verify + TTL check only.
 *   CACHE FALLBACK: last valid token cached in #__extensions params for up
 *                   to 4 hours during control center outages.
 *
 * Enforcement modes
 * -----------------
 *   full_enforcement — active valid license; all protection actions enabled
 *   monitor_only     — expired token; log only, no block actions
 *   quarantine       — suspended or missing; read-only logs, no actions
 *
 * Token sync
 * ----------
 *   Heartbeat runs via Joomla task scheduler every 6 hours calling:
 *     POST {control_center}/api/method/orbweaver_frothiq.license_system.license_api.sync_license
 *   Payload: { agent_id, tenant_id, current_license_version, request_reason }
 *
 * @package   FrothIQ\LicenseManager\Joomla
 * @version   1.0.0-stub
 * @copyright 2026, OrbWeaver — Proprietary
 */

defined('_JEXEC') or die;

use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Factory;
use Joomla\CMS\Http\HttpFactory;

// ---------------------------------------------------------------------------
// Enforcement mode constants (mirrors Python SDK)
// ---------------------------------------------------------------------------
define('FROTHIQ_MODE_FULL',       'full_enforcement');
define('FROTHIQ_MODE_MONITOR',    'monitor_only');
define('FROTHIQ_MODE_QUARANTINE', 'quarantine');
define('FROTHIQ_OFFLINE_GRACE',   4 * 3600);  // 4 hours


// ---------------------------------------------------------------------------
// FrothIQLicenseResult — validation result value object
// ---------------------------------------------------------------------------

final class FrothIQLicenseResult
{
    public readonly bool   $valid;
    public readonly string $enforcement_mode;
    public readonly string $reason;
    public readonly string $plan;
    public readonly array  $features;
    public readonly array  $limits;
    public readonly string $tenant_id;

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

    public function canBlock(): bool
    {
        return $this->enforcement_mode === FROTHIQ_MODE_FULL;
    }

    public function canLog(): bool
    {
        return in_array($this->enforcement_mode, [FROTHIQ_MODE_FULL, FROTHIQ_MODE_MONITOR], true);
    }

    public function hasFeature(string $feature): bool
    {
        return !empty($this->features[$feature]);
    }

    public static function quarantine(string $reason = 'missing_or_invalid_license'): self
    {
        return new self(false, FROTHIQ_MODE_QUARANTINE, $reason);
    }

    public static function monitorOnly(
        string $reason,
        string $plan      = 'free',
        array  $features  = [],
        array  $limits    = [],
        string $tenant_id = ''
    ): self {
        return new self(false, FROTHIQ_MODE_MONITOR, $reason, $plan, $features, $limits, $tenant_id);
    }
}


// ---------------------------------------------------------------------------
// FrothIQLicenseManager — main validator
// ---------------------------------------------------------------------------

final class FrothIQLicenseManager
{
    private string $signingKey;
    private string $paramsKey = 'frothiq_license_token';
    private string $tsKey     = 'frothiq_license_last_valid_ts';

    public function __construct(string $signingKey)
    {
        $this->signingKey = $signingKey;
    }

    /**
     * Primary entry point — validates the current cached license token.
     * Mirrors Python SDK validate_license_token() semantics exactly.
     *
     * @param string|null $expectedTenantId  Optional tenant binding check.
     * @return FrothIQLicenseResult           NEVER throws.
     */
    public function validate(?string $expectedTenantId = null): FrothIQLicenseResult
    {
        $tokenJson  = $this->loadCachedToken();
        $lastValid  = (float) $this->loadLastValidTs();

        if (empty($tokenJson)) {
            return FrothIQLicenseResult::quarantine('missing_license_token');
        }

        try {
            $token = $this->parseToken($tokenJson);
        } catch (\Exception $e) {
            return $this->offlineFallback($tokenJson, $lastValid, 'parse_error: ' . $e->getMessage());
        }

        // Schema version
        if ((int) ($token['schema_version'] ?? 1) !== 1) {
            return FrothIQLicenseResult::quarantine('unknown_schema_version');
        }

        // Tenant binding
        if ($expectedTenantId !== null && ($token['tenant_id'] ?? '') !== $expectedTenantId) {
            return FrothIQLicenseResult::quarantine('tenant_id_mismatch');
        }

        // Signature (FAIL CLOSED)
        if (!$this->verifySignature($token)) {
            return FrothIQLicenseResult::quarantine('signature_invalid');
        }

        // Expiry
        if (time() >= (float) ($token['expires_at'] ?? 0)) {
            return $this->offlineFallback($tokenJson, $lastValid, 'token_expired', $token);
        }

        // Status
        $status = strtolower($token['status'] ?? '');
        if ($status === 'suspended') {
            return new FrothIQLicenseResult(
                false,
                FROTHIQ_MODE_QUARANTINE,
                'license_suspended',
                $token['plan']      ?? 'free',
                (array) ($token['features'] ?? []),
                (array) ($token['limits']   ?? []),
                $token['tenant_id'] ?? ''
            );
        }

        $mode = in_array($status, ['active', 'trial'], true)
            ? FROTHIQ_MODE_FULL
            : FROTHIQ_MODE_MONITOR;

        $this->updateLastValidTs();

        return new FrothIQLicenseResult(
            true,
            $mode,
            'ok',
            $token['plan']      ?? 'free',
            (array) ($token['features'] ?? []),
            (array) ($token['limits']   ?? []),
            $token['tenant_id'] ?? ''
        );
    }

    /**
     * Store a raw license token JSON string received from the control center.
     * Verifies signature before persisting.
     */
    public function storeToken(string $tokenJson): bool
    {
        try {
            $token = $this->parseToken($tokenJson);
        } catch (\Exception $e) {
            return false;
        }
        if (!$this->verifySignature($token)) {
            return false;
        }
        $this->persistToken($tokenJson);
        $this->updateLastValidTs();
        return true;
    }

    // ------------------------------------------------------------------
    // Private: signature
    // ------------------------------------------------------------------

    /**
     * Verify HMAC-SHA256 signature.
     * Canonical form: sorted keys, no whitespace JSON — same as Python SDK.
     */
    private function verifySignature(array $token): bool
    {
        $submitted = $token['signature'] ?? '';
        if (empty($submitted)) {
            return false;
        }
        $payload = $token;
        unset($payload['signature']);
        $canonical = $this->canonicalJson($payload);
        $expected  = hash_hmac('sha256', $canonical, $this->signingKey);
        return hash_equals($expected, $submitted);
    }

    private function canonicalJson(array $data): string
    {
        ksort($data);
        foreach ($data as $key => $val) {
            if (is_array($val)) {
                $data[$key] = $this->canonicalJson($val);
            }
        }
        return json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    // ------------------------------------------------------------------
    // Private: parsing
    // ------------------------------------------------------------------

    private function parseToken(string $tokenJson): array
    {
        if (empty($tokenJson)) {
            throw new \RuntimeException('empty token_json');
        }
        $data = json_decode($tokenJson, true);
        if (!is_array($data)) {
            throw new \RuntimeException('token must be a JSON object');
        }
        foreach (['tenant_id', 'license_id', 'plan', 'status', 'signature',
                  'issued_at', 'expires_at', 'features', 'limits'] as $field) {
            if (!array_key_exists($field, $data)) {
                throw new \RuntimeException("missing required field: {$field}");
            }
        }
        return $data;
    }

    // ------------------------------------------------------------------
    // Private: offline fallback
    // ------------------------------------------------------------------

    private function offlineFallback(
        string $cachedJson,
        float  $lastValidTs,
        string $reason,
        ?array $expiredToken = null
    ): FrothIQLicenseResult {
        if ($expiredToken !== null && $lastValidTs <= 0) {
            return FrothIQLicenseResult::monitorOnly(
                $reason,
                $expiredToken['plan']      ?? 'free',
                (array) ($expiredToken['features'] ?? []),
                (array) ($expiredToken['limits']   ?? []),
                $expiredToken['tenant_id'] ?? ''
            );
        }

        if ($lastValidTs <= 0) {
            return FrothIQLicenseResult::quarantine($reason);
        }

        $elapsed = time() - $lastValidTs;
        if ($elapsed <= FROTHIQ_OFFLINE_GRACE) {
            try {
                $cached = $this->parseToken($cachedJson);
                return FrothIQLicenseResult::monitorOnly(
                    $reason . '_offline_grace',
                    $cached['plan']      ?? 'free',
                    (array) ($cached['features'] ?? []),
                    (array) ($cached['limits']   ?? []),
                    $cached['tenant_id'] ?? ''
                );
            } catch (\Exception $e) {
                // Cache corrupt
            }
        }

        return FrothIQLicenseResult::quarantine($reason);
    }

    // ------------------------------------------------------------------
    // Private: Joomla storage (stub — uses #__extensions params via db)
    // ------------------------------------------------------------------

    private function loadCachedToken(): string
    {
        // TODO (Phase 3 full): load from Joomla #__extensions or custom table
        // Stub returns empty string — sync heartbeat must populate on first run
        return '';
    }

    private function loadLastValidTs(): float
    {
        return 0.0;
    }

    private function persistToken(string $tokenJson): void
    {
        // TODO: persist to Joomla database
    }

    private function updateLastValidTs(): void
    {
        // TODO: persist timestamp
    }
}


// ---------------------------------------------------------------------------
// Joomla Plugin class (system plugin hook)
// ---------------------------------------------------------------------------

class PlgSystemFrothiqLicense extends CMSPlugin
{
    /**
     * onAfterInitialise — earliest safe hook to validate license.
     * Called on every Joomla request. Uses cached result (no network call).
     */
    public function onAfterInitialise(): void
    {
        // Obtain manager instance (signing key from plugin params)
        $manager = $this->getLicenseManager();
        if ($manager === null) {
            return; // Plugin not configured — fail open during setup
        }

        $tenantId = $this->params->get('tenant_id', '');
        $result   = $manager->validate($tenantId ?: null);

        // Expose result to FrothIQ protection layer via application state
        $app = Factory::getApplication();
        $app->set('frothiq.license', $result);
    }

    /**
     * onAfterRoute — perform heartbeat sync check.
     * Fires sync if last sync was > 6 hours ago (avoids wp-cron dependency).
     */
    public function onAfterRoute(): void
    {
        $lastSync = (int) $this->params->get('last_heartbeat_ts', 0);
        if ((time() - $lastSync) > (6 * 3600)) {
            $this->doHeartbeat();
        }
    }

    // ------------------------------------------------------------------

    private function getLicenseManager(): ?FrothIQLicenseManager
    {
        $secret = $this->params->get('license_secret', '');
        if (empty($secret)) {
            return null;
        }
        return new FrothIQLicenseManager($secret);
    }

    private function doHeartbeat(): void
    {
        $controlCenter = $this->params->get('control_center_url', '');
        $tenantId      = $this->params->get('tenant_id', '');
        $agentId       = $this->params->get('agent_id', '');

        if (empty($controlCenter) || empty($tenantId)) {
            return;
        }

        try {
            $http     = HttpFactory::getHttp();
            $endpoint = rtrim($controlCenter, '/') . '/api/method/orbweaver_frothiq.license_system.license_api.sync_license';
            $payload  = json_encode([
                'payload' => [
                    'agent_id'                => $agentId,
                    'tenant_id'               => $tenantId,
                    'current_license_version' => (int) $this->params->get('license_version', 0),
                    'request_reason'          => 'joomla_heartbeat',
                ],
            ]);
            $response = $http->post($endpoint, $payload, ['Content-Type' => 'application/json'], 10);

            if ($response->code === 200) {
                $body = json_decode($response->body, true);
                if (!empty($body['message']['license_token'])) {
                    $manager = $this->getLicenseManager();
                    if ($manager) {
                        $manager->storeToken(json_encode($body['message']['license_token']));
                    }
                }
            }
        } catch (\Exception $e) {
            // Offline — grace period handles degradation automatically
        }

        // Update heartbeat timestamp regardless of outcome
        $this->params->set('last_heartbeat_ts', time());
        // TODO: persist params via extension update query
    }
}
