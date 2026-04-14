<?php
/**
 * FrothIQ Edge SDK — Abstract Base Class
 *
 * All edge plugin license managers MUST extend this class.
 * The validation pipeline is FINAL — subclasses provide storage only.
 *
 * Subclass contract
 * -----------------
 * Subclasses implement exactly 5 storage methods:
 *
 *   getSigningKey()     — return HMAC signing key string
 *   loadTokenJson()     — return stored license token JSON ('' if absent)
 *   saveTokenJson()     — persist a new license token JSON
 *   loadLastValidTs()   — return Unix timestamp of last successful validation
 *   saveLastValidTs()   — persist last successful validation timestamp
 *
 * Optionally override:
 *   getExpectedTenantId()   — enforce tenant binding (return null to skip)
 *   getAgentId()            — agent identifier for audit/sync
 *   createAuditEmitter()    — return a platform-specific AuditEmitter
 *   createSyncClient()      — return a platform-specific SyncClient
 *
 * Security contract
 * -----------------
 * The five final public methods (validate, storeToken, hasFeature,
 * getPlanLimits, getEnforcementSummary) are FINAL and cannot be overridden.
 * This prevents plugin authors from accidentally breaking the security
 * contract by overriding validation logic.
 *
 * Validation pipeline (enforce order MUST NOT change)
 * ---------------------------------------------------
 *  1. Load token from storage (fail closed on empty)
 *  2. Parse JSON + required-field check
 *  3. Schema version check
 *  4. Tenant binding check (if configured)
 *  5. HMAC-SHA256 signature verification  ← FAIL CLOSED, no grace
 *  6. Expiry check + offline grace fallback
 *  7. Status check (suspended → quarantine, no grace)
 *  8. Return full_enforcement or monitor_only
 *
 * @package   FrothIQ\EdgeSDK
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 */

declare(strict_types=1);

namespace FrothIQ\EdgeSDK;

abstract class FrothIQSDKBase
{
    // ------------------------------------------------------------------
    // Abstract: storage (MUST implement in subclass)
    // ------------------------------------------------------------------

    /**
     * Return the HMAC-SHA256 signing key string.
     * Must be the same key used by the FrothIQ control center.
     */
    abstract protected function getSigningKey(): string;

    /**
     * Return the stored license token JSON, or '' if not yet stored.
     */
    abstract protected function loadTokenJson(): string;

    /**
     * Persist a license token JSON string received from the control center.
     * Called only after signature verification passes.
     */
    abstract protected function saveTokenJson(string $json): void;

    /**
     * Return the Unix timestamp (float) of the last SUCCESSFUL validation,
     * or 0.0 if never validated.  Used for offline grace period calculation.
     */
    abstract protected function loadLastValidTs(): float;

    /**
     * Persist the last-successful-validation timestamp.
     */
    abstract protected function saveLastValidTs(float $ts): void;

    // ------------------------------------------------------------------
    // Optional: override in subclass for platform-specific behaviour
    // ------------------------------------------------------------------

    /**
     * Return the tenant_id that this plugin instance is bound to,
     * or null to skip tenant binding enforcement.
     */
    protected function getExpectedTenantId(): ?string
    {
        return null;
    }

    /**
     * Return the agent identifier for this plugin instance.
     * Used in audit events and sync requests.
     */
    protected function getAgentId(): string
    {
        return '';
    }

    /**
     * Return an AuditEmitter for this plugin instance.
     * Default: FileAuditEmitter writing to sys_get_temp_dir().
     */
    protected function createAuditEmitter(): AuditEmitterBase
    {
        return new FileAuditEmitter();
    }

    /**
     * Return a SyncClient for this plugin instance.
     * Default: platform-agnostic stream-based HTTP client.
     */
    protected function createSyncClient(string $controlCenterUrl): SyncClient
    {
        return new SyncClient($controlCenterUrl);
    }

    // ------------------------------------------------------------------
    // FINAL public API — enforcement contract
    // ------------------------------------------------------------------

    /**
     * Validate the current stored license token.
     *
     * Runs the full 8-step validation pipeline (see class docblock).
     * NEVER throws — always returns a LicenseResult.
     *
     * @return LicenseResult
     */
    final public function validate(): LicenseResult
    {
        $key = $this->getSigningKey();
        if ($key === '') {
            // Signing key not configured — cannot validate securely.
            // Fail closed: do not allow enforcement until configured.
            return LicenseResult::quarantine('signing_key_not_configured');
        }

        $tokenJson  = $this->loadTokenJson();
        $lastValidTs = $this->loadLastValidTs();
        $grace      = new OfflineGraceManager();

        // Step 1: empty token
        if ($tokenJson === '') {
            return LicenseResult::quarantine('missing_license_token');
        }

        // Step 2: parse
        try {
            $token = TokenValidator::parse($tokenJson);
        } catch (TokenParseException $e) {
            $this->auditEmitter()->emit('quarantine', '', '', 'warning', '', ['reason' => 'parse_error']);
            return $grace->fallback('parse_error', $lastValidTs, $tokenJson);
        }

        // Step 3: schema version
        try {
            TokenValidator::checkSchemaVersion($token);
        } catch (SchemaVersionException $e) {
            return LicenseResult::quarantine('unknown_schema_version');
        }

        // Step 4: tenant binding
        $expectedTenant = $this->getExpectedTenantId();
        if ($expectedTenant !== null) {
            try {
                TokenValidator::checkTenantBinding($token, $expectedTenant);
            } catch (TenantMismatchException $e) {
                $this->auditEmitter()->recordCrossTenant(
                    $expectedTenant,
                    (string) ($token['tenant_id'] ?? ''),
                    $this->getAgentId(),
                    (string) ($token['license_id'] ?? ''),
                );
                return LicenseResult::quarantine('tenant_id_mismatch');
            }
        }

        // Step 5: HMAC signature — FAIL CLOSED, NO GRACE
        try {
            $sigValid = TokenValidator::verifySignature($token, $key);
        } catch (SignatureException $e) {
            $sigValid = false;
        }
        if (!$sigValid) {
            $this->auditEmitter()->recordSigFailure(
                (string) ($token['tenant_id'] ?? ''),
                $this->getAgentId(),
                'hmac_mismatch',
                (string) ($token['license_id'] ?? ''),
            );
            // Signature failure: quarantine immediately, no offline grace.
            return LicenseResult::quarantine('signature_invalid');
        }

        // Step 6: expiry
        if (!TokenValidator::isNotExpired($token)) {
            if ($lastValidTs > 0.0 && $this->auditEmitter() instanceof AuditEmitterBase) {
                $this->auditEmitter()->recordExpiredUse(
                    (string) ($token['tenant_id'] ?? ''),
                    (string) ($token['license_id'] ?? ''),
                    $this->getAgentId(),
                );
            }
            return $grace->fallback('token_expired', $lastValidTs, $tokenJson, $token);
        }

        // Step 7: status
        $status = strtolower((string) ($token['status'] ?? ''));
        if ($status === 'suspended') {
            $this->auditEmitter()->recordQuarantine(
                (string) ($token['tenant_id'] ?? ''),
                (string) ($token['license_id'] ?? ''),
                'license_suspended',
                $this->getAgentId(),
            );
            return new LicenseResult(
                valid:           false,
                enforcementMode: LicenseResult::MODE_QUARANTINE,
                reason:          'license_suspended',
                plan:            (string) ($token['plan']      ?? 'free'),
                features:        (array)  ($token['features']  ?? []),
                limits:          (array)  ($token['limits']    ?? []),
                tenantId:        (string) ($token['tenant_id'] ?? ''),
            );
        }
        if ($status === 'revoked') {
            return LicenseResult::quarantine('license_revoked');
        }

        // Step 8: valid — full_enforcement or monitor_only
        $mode = in_array($status, ['active', 'trial'], true)
            ? LicenseResult::MODE_FULL
            : LicenseResult::MODE_MONITOR;

        // Persist last-valid timestamp on clean validation
        $this->saveLastValidTs((float) time());

        return new LicenseResult(
            valid:           true,
            enforcementMode: $mode,
            reason:          'ok',
            plan:            (string) ($token['plan']      ?? 'free'),
            features:        (array)  ($token['features']  ?? []),
            limits:          (array)  ($token['limits']    ?? []),
            tenantId:        (string) ($token['tenant_id'] ?? ''),
        );
    }

    /**
     * Validate and persist a license token JSON string received from
     * the control center.  Signature is verified before storing.
     *
     * Returns false (and does NOT overwrite existing token) if
     * the supplied token fails signature or parse checks.
     *
     * @param  string $tokenJson  Raw JSON from control center /sync response.
     * @return bool               True if stored; false if rejected.
     */
    final public function storeToken(string $tokenJson): bool
    {
        $key = $this->getSigningKey();
        if ($key === '') {
            return false;
        }
        try {
            $token    = TokenValidator::parse($tokenJson);
            $sigValid = TokenValidator::verifySignature($token, $key);
        } catch (\Throwable) {
            return false;
        }
        if (!$sigValid) {
            return false;
        }

        // Optional tenant binding
        $expected = $this->getExpectedTenantId();
        if ($expected !== null && ($token['tenant_id'] ?? '') !== $expected) {
            return false;
        }

        try {
            $this->saveTokenJson($tokenJson);
            $this->saveLastValidTs((float) time());
        } catch (\Throwable) {
            return false;
        }

        $this->auditEmitter()->recordTokenStored(
            (string) ($token['tenant_id'] ?? ''),
            (string) ($token['license_id'] ?? ''),
            $this->getAgentId(),
        );
        return true;
    }

    /**
     * Shortcut: validate + check a feature flag.
     * FAIL CLOSED: returns false on any validation failure.
     *
     * @param  string $feature  Feature name (e.g. 'defense_mesh').
     * @return bool
     */
    final public function hasFeature(string $feature): bool
    {
        $result = $this->validate();
        if ($result->enforcementMode === LicenseResult::MODE_QUARANTINE) {
            return false;
        }
        return $result->hasFeature($feature);
    }

    /**
     * Return the plan limits from the current license.
     * FAIL CLOSED: returns [] on any validation failure.
     *
     * @return array  e.g. ['rpm' => 600, 'max_sites' => 10, …]
     */
    final public function getPlanLimits(): array
    {
        $result = $this->validate();
        if ($result->enforcementMode === LicenseResult::MODE_QUARANTINE) {
            return [];
        }
        return $result->limits;
    }

    /**
     * Return a structured enforcement summary suitable for plugin UI layers
     * (status badges, feature lock overlays, etc.).
     *
     * @return array
     */
    final public function getEnforcementSummary(): array
    {
        $result = $this->validate();
        return [
            'valid'            => $result->valid,
            'enforcement_mode' => $result->enforcementMode,
            'can_block'        => $result->canBlock(),
            'can_log'          => $result->canLog(),
            'plan'             => $result->plan,
            'tenant_id'        => $result->tenantId,
            'reason'           => $result->reason,
            'is_in_grace'      => $result->isInGrace(),
            'feature_matrix'   => [
                'adaptive_scoring'   => $result->hasFeature('adaptive_scoring'),
                'federation'         => $result->hasFeature('federation'),
                'campaigns'          => $result->hasFeature('campaigns'),
                'defense_mesh'       => $result->hasFeature('defense_mesh'),
                'intel_market'       => $result->hasFeature('intel_market'),
                'policy_mesh'        => $result->hasFeature('policy_mesh'),
                'simulation'         => $result->hasFeature('simulation'),
                'response_engine'    => $result->hasFeature('response_engine'),
            ],
        ];
    }

    /**
     * Perform a heartbeat sync with the FrothIQ control center.
     *
     * Downloads an updated license token and stores it if the HMAC
     * signature verifies correctly.  Returns true if a new token was stored.
     *
     * @param  string $controlCenterUrl  Base URL of the FrothIQ control center.
     * @param  string $tenantId          FrothIQ tenant identifier.
     * @param  string $agentId           Edge plugin agent identifier.
     * @param  int    $currentVersion    Current token version (for update detection).
     * @return bool                      True if token was updated and stored.
     */
    public function refresh(
        string $controlCenterUrl,
        string $tenantId,
        string $agentId,
        int    $currentVersion = 0
    ): bool {
        $client    = $this->createSyncClient($controlCenterUrl);
        $syncResult = $client->sync(
            tenantId:          $tenantId,
            agentId:           $agentId,
            currentTokenJson:  $this->loadTokenJson(),
            currentVersion:    $currentVersion,
            requestReason:     'sdk_heartbeat',
        );

        $this->auditEmitter()->recordSync($tenantId, $agentId, [
            'success'  => $syncResult->success,
            'updated'  => $syncResult->updated,
            'error'    => $syncResult->error,
        ]);

        if (!$syncResult->success || $syncResult->tokenJson === null) {
            return false;
        }

        return $this->storeToken($syncResult->tokenJson);
    }

    // ------------------------------------------------------------------
    // Private: lazy audit emitter cache
    // ------------------------------------------------------------------

    private ?AuditEmitterBase $_auditEmitter = null;

    private function auditEmitter(): AuditEmitterBase
    {
        if ($this->_auditEmitter === null) {
            $this->_auditEmitter = $this->createAuditEmitter();
        }
        return $this->_auditEmitter;
    }
}
