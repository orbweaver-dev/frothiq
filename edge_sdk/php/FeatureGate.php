<?php
/**
 * FrothIQ Edge SDK — Feature Gate
 *
 * Evaluates whether a feature is accessible given the current license token.
 * Also provides plan-based upgrade path suggestions.
 *
 * This class is the single source of truth for feature-to-plan mapping
 * on the PHP side.  It must stay in sync with:
 *   - license_model.py  (PLAN_FEATURE_MATRIX in orbweaver_frothiq)
 *   - LicensePolicyEnforcer._FEATURE_PLANS  (frothiq-core)
 *
 * @package   FrothIQ\EdgeSDK
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 */

declare(strict_types=1);

namespace FrothIQ\EdgeSDK;

final class FeatureGate
{
    // Plan tier ordering (ascending capability)
    public const PLAN_FREE       = 'free';
    public const PLAN_PRO        = 'pro';
    public const PLAN_ENTERPRISE = 'enterprise';

    private const PLAN_ORDER = [self::PLAN_FREE, self::PLAN_PRO, self::PLAN_ENTERPRISE];

    /**
     * Minimum plan required to unlock each feature.
     * Mirrors LicensePolicyEnforcer._FEATURE_PLANS in frothiq-core.
     */
    private const FEATURE_MINIMUM_PLAN = [
        'adaptive_scoring'        => self::PLAN_FREE,
        'federation'              => self::PLAN_PRO,
        'campaigns'               => self::PLAN_PRO,
        'defense_mesh'            => self::PLAN_PRO,
        'intel_market'            => self::PLAN_PRO,
        'policy_mesh'             => self::PLAN_PRO,
        'simulation'              => self::PLAN_ENTERPRISE,
        'defense_mesh_auto_apply' => self::PLAN_ENTERPRISE,
        'response_engine'         => self::PLAN_ENTERPRISE,
    ];

    // No instantiation — all methods are static.
    private function __construct() {}

    // ------------------------------------------------------------------
    // Primary API
    // ------------------------------------------------------------------

    /**
     * Return true if the feature is enabled in the token AND the license
     * enforcement mode allows it.
     *
     * FAIL CLOSED: returns false for missing tokens, quarantined licenses,
     * or features not present in the token's feature map.
     *
     * @param  array  $token           Validated (parsed) license token array.
     * @param  string $feature         Feature name (e.g. "defense_mesh").
     * @param  string $enforcementMode The enforcement mode from LicenseResult.
     */
    public static function isEnabled(array $token, string $feature, string $enforcementMode): bool
    {
        // Quarantine always blocks feature access
        if ($enforcementMode === 'quarantine') {
            return false;
        }
        // monitor_only: feature flags may still be checked for UI rendering
        // but block actions will be suppressed upstream
        $features = $token['features'] ?? [];
        return !empty($features[$feature]);
    }

    /**
     * Evaluate a feature gate and return a structured decision.
     *
     * @param  array  $token           Validated license token array.
     * @param  string $feature         Feature name.
     * @param  string $enforcementMode Current enforcement mode.
     * @return FeatureGateResult
     */
    public static function evaluate(
        array  $token,
        string $feature,
        string $enforcementMode
    ): FeatureGateResult {
        // Quarantine: hard block regardless
        if ($enforcementMode === 'quarantine') {
            return new FeatureGateResult(
                allowed:      false,
                decision:     FeatureGateResult::DECISION_HARD_BLOCK,
                feature:      $feature,
                plan:         $token['plan'] ?? 'free',
                reason:       'license_quarantined',
            );
        }

        // Monitor-only: soft degrade (log but don't hard-block)
        if ($enforcementMode === 'monitor_only') {
            return new FeatureGateResult(
                allowed:      false,
                decision:     FeatureGateResult::DECISION_SOFT_DEGRADE,
                feature:      $feature,
                plan:         $token['plan'] ?? 'free',
                reason:       'license_expired_monitor_only',
            );
        }

        // Full enforcement: check feature flag
        $features = $token['features'] ?? [];
        if (!empty($features[$feature])) {
            return new FeatureGateResult(
                allowed:  true,
                decision: FeatureGateResult::DECISION_ALLOW,
                feature:  $feature,
                plan:     $token['plan'] ?? 'free',
                reason:   'ok',
            );
        }

        // Feature not in token — check if it's plan-upgradeable
        $currentPlan = $token['plan'] ?? 'free';
        $upgrade     = self::getUpgradeTarget($currentPlan, $feature);
        if ($upgrade !== null) {
            return new FeatureGateResult(
                allowed:       false,
                decision:      FeatureGateResult::DECISION_UPGRADE_PROMPT,
                feature:       $feature,
                plan:          $currentPlan,
                reason:        "feature_{$feature}_requires_{$upgrade}",
                upgradeTarget: $upgrade,
            );
        }

        return new FeatureGateResult(
            allowed:  false,
            decision: FeatureGateResult::DECISION_FEATURE_LOCKED,
            feature:  $feature,
            plan:     $currentPlan,
            reason:   "feature_{$feature}_not_available",
        );
    }

    /**
     * Return the minimum plan that would unlock $feature above $currentPlan,
     * or null if no upgrade path exists.
     */
    public static function getUpgradeTarget(string $currentPlan, string $feature): ?string
    {
        $minimum = self::FEATURE_MINIMUM_PLAN[$feature] ?? null;
        if ($minimum === null) {
            return null;
        }
        $currentIdx = array_search($currentPlan, self::PLAN_ORDER, true);
        $minimumIdx = array_search($minimum, self::PLAN_ORDER, true);

        if ($minimumIdx === false || $currentIdx === false) {
            return null;
        }
        return ($minimumIdx > $currentIdx) ? $minimum : null;
    }

    /**
     * Return all features enabled in the token as a flat array.
     * FAIL CLOSED: returns [] for invalid/missing token.
     */
    public static function getEnabledFeatures(array $token): array
    {
        $features = $token['features'] ?? [];
        if (!is_array($features)) {
            return [];
        }
        return array_keys(array_filter($features));
    }

    /**
     * Return plan limits from the token.
     * FAIL CLOSED: returns conservative defaults for invalid/missing token.
     */
    public static function getLimits(array $token): array
    {
        $limits = $token['limits'] ?? [];
        return is_array($limits) ? $limits : [];
    }
}


// ---------------------------------------------------------------------------
// FeatureGateResult — value object
// ---------------------------------------------------------------------------

final class FeatureGateResult
{
    public const DECISION_ALLOW          = 'allow';
    public const DECISION_SOFT_DEGRADE   = 'soft_degrade';
    public const DECISION_HARD_BLOCK     = 'hard_block';
    public const DECISION_UPGRADE_PROMPT = 'upgrade_prompt';
    public const DECISION_FEATURE_LOCKED = 'feature_locked';

    public function __construct(
        public readonly bool    $allowed,
        public readonly string  $decision,
        public readonly string  $feature,
        public readonly string  $plan,
        public readonly string  $reason,
        public readonly ?string $upgradeTarget = null,
    ) {}

    public function shouldBlock(): bool
    {
        return $this->decision === self::DECISION_HARD_BLOCK;
    }

    public function shouldLogOnly(): bool
    {
        return $this->decision === self::DECISION_SOFT_DEGRADE;
    }

    public function needsUpgrade(): bool
    {
        return $this->decision === self::DECISION_UPGRADE_PROMPT;
    }

    public function toArray(): array
    {
        return [
            'allowed'        => $this->allowed,
            'decision'       => $this->decision,
            'feature'        => $this->feature,
            'plan'           => $this->plan,
            'reason'         => $this->reason,
            'upgrade_target' => $this->upgradeTarget,
            'should_block'   => $this->shouldBlock(),
            'should_allow'   => $this->allowed,
        ];
    }
}
