<?php
/**
 * FrothIQ Edge SDK — Offline Grace Manager
 *
 * Handles the degraded-mode fallback when the primary license token is
 * expired or when the control center is unreachable.
 *
 * Policy
 * ------
 *   If the token is expired AND the control center is unreachable:
 *     - While within OFFLINE_GRACE_SECONDS of last successful validation:
 *       → monitor_only (log but don't block; degrade gracefully)
 *     - After OFFLINE_GRACE_SECONDS:
 *       → quarantine (fail closed)
 *
 *   If the token is suspended/revoked: no grace; quarantine immediately.
 *   If the token signature is invalid: no grace; quarantine immediately.
 *
 * Rationale: a control center outage should not simultaneously disable all
 * protected sites.  4 hours gives ops time to restore the control center
 * without causing a mass license failure event.
 *
 * @package   FrothIQ\EdgeSDK
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 */

declare(strict_types=1);

namespace FrothIQ\EdgeSDK;

final class OfflineGraceManager
{
    /** Default offline grace window in seconds (4 hours). */
    public const DEFAULT_GRACE_SECONDS = 4 * 3600;

    private int $graceSeconds;

    public function __construct(int $graceSeconds = self::DEFAULT_GRACE_SECONDS)
    {
        $this->graceSeconds = $graceSeconds;
    }

    // ------------------------------------------------------------------
    // Primary API
    // ------------------------------------------------------------------

    /**
     * Produce a LicenseResult for the offline/expired-token fallback path.
     *
     * Called when:
     *   (a) the primary token is expired (token_expired reason), OR
     *   (b) the token could not be fetched and we have a cached copy.
     *
     * NOT called for signature failures or suspension — those are always quarantine.
     *
     * @param  string      $reason         Why we're falling back ('token_expired', 'parse_error', …).
     * @param  float       $lastValidTs    Unix timestamp of last successful validation (0 = unknown).
     * @param  string|null $cachedTokenJson Last known-good token JSON (may be expired).
     * @param  array|null  $expiredToken   Already-decoded expired token (if available).
     * @return LicenseResult
     */
    public function fallback(
        string  $reason,
        float   $lastValidTs,
        ?string $cachedTokenJson = null,
        ?array  $expiredToken    = null
    ): LicenseResult {
        // Case 1: have expired token data, no stored "last valid" time
        // (first-boot scenario — token expired but we've never had a clean run)
        if ($expiredToken !== null && $lastValidTs <= 0.0) {
            return LicenseResult::monitorOnly(
                $reason,
                (string) ($expiredToken['plan']      ?? 'free'),
                (array)  ($expiredToken['features']  ?? []),
                (array)  ($expiredToken['limits']    ?? []),
                (string) ($expiredToken['tenant_id'] ?? ''),
            );
        }

        // Case 2: no usable cached data at all
        if ($lastValidTs <= 0.0 && $cachedTokenJson === null && $expiredToken === null) {
            return LicenseResult::quarantine($reason);
        }

        // Case 3: check if still within grace window
        $graceElapsed = time() - $lastValidTs;
        if ($graceElapsed <= $this->graceSeconds) {
            // Try to use cached token data for plan/features continuity
            $plan      = 'free';
            $features  = [];
            $limits    = [];
            $tenantId  = '';

            if ($expiredToken !== null) {
                $plan     = (string) ($expiredToken['plan']      ?? 'free');
                $features = (array)  ($expiredToken['features']  ?? []);
                $limits   = (array)  ($expiredToken['limits']    ?? []);
                $tenantId = (string) ($expiredToken['tenant_id'] ?? '');
            } elseif ($cachedTokenJson !== null && $cachedTokenJson !== '') {
                try {
                    $cached   = TokenValidator::parse($cachedTokenJson);
                    $plan     = (string) ($cached['plan']      ?? 'free');
                    $features = (array)  ($cached['features']  ?? []);
                    $limits   = (array)  ($cached['limits']    ?? []);
                    $tenantId = (string) ($cached['tenant_id'] ?? '');
                } catch (TokenParseException) {
                    // Cache is corrupt — use conservative defaults
                }
            }

            return LicenseResult::monitorOnly(
                $reason . '_offline_grace',
                $plan,
                $features,
                $limits,
                $tenantId,
            );
        }

        // Case 4: outside grace window → fail closed
        return LicenseResult::quarantine($reason);
    }

    /**
     * Return true if the current time is still within the offline grace window.
     *
     * @param  float $lastValidTs  Unix timestamp of last successful validation.
     */
    public function isWithinGrace(float $lastValidTs): bool
    {
        if ($lastValidTs <= 0.0) {
            return false;
        }
        return (time() - $lastValidTs) <= $this->graceSeconds;
    }

    /**
     * Return seconds remaining in the grace window, or 0 if expired/not started.
     */
    public function graceSecondsRemaining(float $lastValidTs): int
    {
        if ($lastValidTs <= 0.0) {
            return 0;
        }
        $remaining = $this->graceSeconds - (time() - (int) $lastValidTs);
        return max(0, $remaining);
    }
}
