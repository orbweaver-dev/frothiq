<?php
/**
 * FrothIQ Edge SDK — LicenseResult
 *
 * Immutable value object returned by every validate() call.
 *
 * Mirrors Python SDK's LicenseValidationResult exactly:
 *   valid, enforcement_mode, reason, plan, features, limits, tenant_id
 *
 * @package   FrothIQ\EdgeSDK
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 */

declare(strict_types=1);

namespace FrothIQ\EdgeSDK;

final class LicenseResult
{
    // Enforcement mode constants — must match Python SDK strings exactly
    public const MODE_FULL      = 'full_enforcement';
    public const MODE_MONITOR   = 'monitor_only';
    public const MODE_QUARANTINE = 'quarantine';

    public function __construct(
        public readonly bool   $valid,
        public readonly string $enforcementMode,
        public readonly string $reason,
        public readonly string $plan      = 'free',
        public readonly array  $features  = [],
        public readonly array  $limits    = [],
        public readonly string $tenantId  = '',
    ) {}

    // ------------------------------------------------------------------
    // Behavior queries
    // ------------------------------------------------------------------

    /** True only when the license allows active blocking of requests. */
    public function canBlock(): bool
    {
        return $this->enforcementMode === self::MODE_FULL;
    }

    /** True when the license allows event logging (full or monitor-only). */
    public function canLog(): bool
    {
        return $this->enforcementMode !== self::MODE_QUARANTINE;
    }

    /** True when the license is in the offline grace period. */
    public function isInGrace(): bool
    {
        return str_ends_with($this->reason, '_offline_grace');
    }

    /** Check whether a named feature flag is enabled. FAIL CLOSED. */
    public function hasFeature(string $feature): bool
    {
        return !empty($this->features[$feature]);
    }

    // ------------------------------------------------------------------
    // Factory methods (fail-closed constants)
    // ------------------------------------------------------------------

    /** Quarantine result — no plan/features available. */
    public static function quarantine(string $reason = 'missing_or_invalid_license'): self
    {
        return new self(
            valid:           false,
            enforcementMode: self::MODE_QUARANTINE,
            reason:          $reason,
        );
    }

    /** Monitor-only result with optional plan/feature continuity. */
    public static function monitorOnly(
        string $reason,
        string $plan      = 'free',
        array  $features  = [],
        array  $limits    = [],
        string $tenantId  = '',
    ): self {
        return new self(
            valid:           false,
            enforcementMode: self::MODE_MONITOR,
            reason:          $reason,
            plan:            $plan,
            features:        $features,
            limits:          $limits,
            tenantId:        $tenantId,
        );
    }

    // ------------------------------------------------------------------
    // Serialisation
    // ------------------------------------------------------------------

    public function toArray(): array
    {
        return [
            'valid'            => $this->valid,
            'enforcement_mode' => $this->enforcementMode,
            'reason'           => $this->reason,
            'plan'             => $this->plan,
            'features'         => $this->features,
            'limits'           => $this->limits,
            'tenant_id'        => $this->tenantId,
            'can_block'        => $this->canBlock(),
            'can_log'          => $this->canLog(),
        ];
    }
}
