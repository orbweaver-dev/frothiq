<?php
/**
 * FrothIQ Edge SDK — Audit Emitter
 *
 * Structured audit event emission for edge plugins.  All writes are
 * best-effort — exceptions are silently swallowed to prevent audit
 * logging from interfering with request processing.
 *
 * Event types (subset of the control-center event types)
 * -------------------------------------------------------
 *   sync            — heartbeat sync completed
 *   sig_failure     — HMAC signature verification failed (CRITICAL)
 *   cross_tenant    — tenant_id mismatch attempt (CRITICAL)
 *   expired_use     — protected action attempted with expired license
 *   feature_blocked — access to unavailable/plan-locked feature denied
 *   quarantine      — license in quarantine state
 *   monitor_only    — license in monitor-only/grace state
 *   token_stored    — new token persisted after successful sync
 *
 * Severity levels
 * ---------------
 *   info     — sync, token_stored, monitor_only
 *   warning  — expired_use, feature_blocked, quarantine
 *   critical — sig_failure, cross_tenant
 *
 * @package   FrothIQ\EdgeSDK
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 */

declare(strict_types=1);

namespace FrothIQ\EdgeSDK;

// ---------------------------------------------------------------------------
// Audit event value object
// ---------------------------------------------------------------------------

final class AuditEvent
{
    public function __construct(
        public readonly string $eventType,
        public readonly string $tenantId,
        public readonly string $licenseId,
        public readonly string $severity,
        public readonly array  $details   = [],
        public readonly string $agentId   = '',
        public readonly float  $ts        = 0.0,
    ) {}

    public function toArray(): array
    {
        return [
            'ts'         => $this->ts ?: microtime(true),
            'event_type' => $this->eventType,
            'tenant_id'  => $this->tenantId,
            'license_id' => $this->licenseId,
            'severity'   => $this->severity,
            'agent_id'   => $this->agentId,
            'details'    => $this->details,
        ];
    }
}

// ---------------------------------------------------------------------------
// Abstract base
// ---------------------------------------------------------------------------

abstract class AuditEmitterBase
{
    /** Severity map — mirrors LicenseAuditBridge._EVENT_SEVERITY in Python. */
    protected const SEVERITY_MAP = [
        'sync'            => 'info',
        'token_stored'    => 'info',
        'monitor_only'    => 'info',
        'expired_use'     => 'warning',
        'feature_blocked' => 'warning',
        'quarantine'      => 'warning',
        'sig_failure'     => 'critical',
        'cross_tenant'    => 'critical',
    ];

    // ------------------------------------------------------------------
    // Public convenience methods
    // ------------------------------------------------------------------

    public function recordSync(string $tenantId, string $agentId, array $details = []): void
    {
        $this->emit('sync', $tenantId, '', 'info', $agentId, $details);
    }

    public function recordSigFailure(string $tenantId, string $agentId, string $reason, string $licenseId = ''): void
    {
        $this->emit('sig_failure', $tenantId, $licenseId, 'critical', $agentId, ['reason' => $reason]);
    }

    public function recordCrossTenant(string $claimedTenantId, string $actualTenantId, string $agentId, string $licenseId = ''): void
    {
        $this->emit('cross_tenant', $claimedTenantId, $licenseId, 'critical', $agentId, [
            'claimed_tenant' => $claimedTenantId,
            'actual_tenant'  => $actualTenantId,
        ]);
    }

    public function recordExpiredUse(string $tenantId, string $licenseId, string $agentId = ''): void
    {
        $this->emit('expired_use', $tenantId, $licenseId, 'warning', $agentId, []);
    }

    public function recordFeatureBlocked(string $tenantId, string $feature, string $plan, string $agentId = ''): void
    {
        $this->emit('feature_blocked', $tenantId, '', 'warning', $agentId, [
            'feature' => $feature,
            'plan'    => $plan,
        ]);
    }

    public function recordQuarantine(string $tenantId, string $licenseId, string $reason, string $agentId = ''): void
    {
        $this->emit('quarantine', $tenantId, $licenseId, 'warning', $agentId, ['reason' => $reason]);
    }

    public function recordTokenStored(string $tenantId, string $licenseId, string $agentId = ''): void
    {
        $this->emit('token_stored', $tenantId, $licenseId, 'info', $agentId, []);
    }

    // ------------------------------------------------------------------
    // Core emit — calls platform-specific write method
    // ------------------------------------------------------------------

    public function emit(
        string $eventType,
        string $tenantId,
        string $licenseId,
        string $severity,
        string $agentId  = '',
        array  $details  = [],
    ): void {
        $event = new AuditEvent(
            eventType: $eventType,
            tenantId:  $tenantId,
            licenseId: $licenseId,
            severity:  $severity,
            details:   $details,
            agentId:   $agentId,
            ts:        microtime(true),
        );
        try {
            $this->write($event);
        } catch (\Throwable) {
            // Audit failures must NEVER propagate to request processing
        }
    }

    /**
     * Platform-specific write implementation.
     * Implementations must be best-effort and must not throw.
     */
    abstract protected function write(AuditEvent $event): void;
}

// ---------------------------------------------------------------------------
// File-based emitter (default — any platform)
// ---------------------------------------------------------------------------

final class FileAuditEmitter extends AuditEmitterBase
{
    private string $logPath;

    public function __construct(string $logPath = '')
    {
        $this->logPath = $logPath ?: sys_get_temp_dir() . '/frothiq_license_audit.jsonl';
    }

    protected function write(AuditEvent $event): void
    {
        $line = json_encode($event->toArray(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
        @file_put_contents($this->logPath, $line, FILE_APPEND | LOCK_EX);
    }
}

// ---------------------------------------------------------------------------
// Null emitter (for unit tests / minimal installs)
// ---------------------------------------------------------------------------

final class NullAuditEmitter extends AuditEmitterBase
{
    /** Captured events — useful for test assertions. */
    public array $events = [];

    protected function write(AuditEvent $event): void
    {
        $this->events[] = $event->toArray();
    }
}
