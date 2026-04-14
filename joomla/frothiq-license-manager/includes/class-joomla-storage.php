<?php
/**
 * FrothIQ Joomla SDK — Joomla Storage Adapter
 *
 * Implements the 5 abstract storage methods required by FrothIQSDKBase
 * using Joomla's #__extensions table params column and a custom
 * #__frothiq_license table for persistent token storage.
 *
 * Storage strategy
 * ----------------
 *   Token JSON:   #__frothiq_license table (created by install script)
 *   Last valid ts: #__frothiq_license.last_valid_ts column
 *
 * Signing key resolution order
 * ----------------------------
 *   1. FROTHIQ_LICENSE_SECRET PHP constant (configuration.php / defines)
 *   2. Plugin params: license_secret (Joomla admin interface)
 *   3. Empty string → signing_key_not_configured → quarantine
 *
 * @package   FrothIQ\Joomla
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 */

defined('_JEXEC') or die;

use FrothIQ\EdgeSDK\FrothIQSDKBase;
use FrothIQ\EdgeSDK\AuditEmitterBase;
use FrothIQ\EdgeSDK\FileAuditEmitter;
use FrothIQ\EdgeSDK\SyncClient;
use Joomla\CMS\Factory;
use Joomla\CMS\Http\HttpFactory;

class FrothIQ_Joomla_LicenseManager extends FrothIQSDKBase
{
    /** Joomla plugin params object (passed from PlgSystemFrothiqLicense). */
    private \Joomla\Registry\Registry $params;

    public function __construct(\Joomla\Registry\Registry $params)
    {
        $this->params = $params;
    }

    // ------------------------------------------------------------------
    // FrothIQSDKBase — storage implementation
    // ------------------------------------------------------------------

    protected function getSigningKey(): string
    {
        if (defined('FROTHIQ_LICENSE_SECRET') && FROTHIQ_LICENSE_SECRET !== '') {
            return FROTHIQ_LICENSE_SECRET;
        }
        return (string) $this->params->get('license_secret', '');
    }

    protected function loadTokenJson(): string
    {
        try {
            $db  = Factory::getDbo();
            $row = $db->setQuery(
                $db->getQuery(true)
                    ->select($db->quoteName('token_json'))
                    ->from($db->quoteName('#__frothiq_license'))
                    ->where($db->quoteName('tenant_id') . ' = ' . $db->quote(
                        (string) $this->params->get('tenant_id', '')
                    ))
                    ->setLimit(1)
            )->loadAssoc();
            return (string) ($row['token_json'] ?? '');
        } catch (\Exception) {
            return '';
        }
    }

    protected function saveTokenJson(string $json): void
    {
        try {
            $db       = Factory::getDbo();
            $tenantId = (string) $this->params->get('tenant_id', '');
            if ($tenantId === '') {
                return;
            }
            // Upsert pattern
            $query = $db->getQuery(true)
                ->select('COUNT(*)')
                ->from($db->quoteName('#__frothiq_license'))
                ->where($db->quoteName('tenant_id') . ' = ' . $db->quote($tenantId));
            $exists = (int) $db->setQuery($query)->loadResult();

            if ($exists) {
                $db->setQuery(
                    $db->getQuery(true)
                        ->update($db->quoteName('#__frothiq_license'))
                        ->set($db->quoteName('token_json') . ' = ' . $db->quote($json))
                        ->where($db->quoteName('tenant_id') . ' = ' . $db->quote($tenantId))
                )->execute();
            } else {
                $obj = (object) ['tenant_id' => $tenantId, 'token_json' => $json, 'last_valid_ts' => 0.0];
                $db->insertObject('#__frothiq_license', $obj);
            }
        } catch (\Exception) {
            // Best-effort — existing token remains in place
        }
    }

    protected function loadLastValidTs(): float
    {
        try {
            $db  = Factory::getDbo();
            $row = $db->setQuery(
                $db->getQuery(true)
                    ->select($db->quoteName('last_valid_ts'))
                    ->from($db->quoteName('#__frothiq_license'))
                    ->where($db->quoteName('tenant_id') . ' = ' . $db->quote(
                        (string) $this->params->get('tenant_id', '')
                    ))
                    ->setLimit(1)
            )->loadAssoc();
            return (float) ($row['last_valid_ts'] ?? 0.0);
        } catch (\Exception) {
            return 0.0;
        }
    }

    protected function saveLastValidTs(float $ts): void
    {
        try {
            $db       = Factory::getDbo();
            $tenantId = (string) $this->params->get('tenant_id', '');
            if ($tenantId === '') {
                return;
            }
            $db->setQuery(
                $db->getQuery(true)
                    ->update($db->quoteName('#__frothiq_license'))
                    ->set($db->quoteName('last_valid_ts') . ' = ' . $db->quote($ts))
                    ->where($db->quoteName('tenant_id') . ' = ' . $db->quote($tenantId))
            )->execute();
        } catch (\Exception) {}
    }

    // ------------------------------------------------------------------
    // FrothIQSDKBase — optional overrides
    // ------------------------------------------------------------------

    protected function getExpectedTenantId(): ?string
    {
        $tid = (string) $this->params->get('tenant_id', '');
        return $tid !== '' ? $tid : null;
    }

    protected function getAgentId(): string
    {
        return (string) $this->params->get('agent_id', '');
    }

    protected function createAuditEmitter(): AuditEmitterBase
    {
        $logPath = JPATH_ROOT . '/logs/frothiq_license_audit.jsonl';
        return new FileAuditEmitter($logPath);
    }

    protected function createSyncClient(string $controlCenterUrl): SyncClient
    {
        return new Joomla_FrothIQ_SyncClient($controlCenterUrl);
    }

    // ------------------------------------------------------------------
    // Joomla-specific helpers
    // ------------------------------------------------------------------

    public function heartbeat(): bool
    {
        $ccUrl    = (string) $this->params->get('control_center_url', '');
        $tenantId = (string) $this->params->get('tenant_id', '');
        $agentId  = (string) $this->params->get('agent_id', '');
        $version  = (int)    $this->params->get('license_version', 0);

        if ($ccUrl === '' || $tenantId === '') {
            return false;
        }

        return $this->refresh($ccUrl, $tenantId, $agentId, $version);
    }
}


// ---------------------------------------------------------------------------
// Joomla-specific HTTP client (uses Joomla HttpFactory)
// ---------------------------------------------------------------------------

use FrothIQ\EdgeSDK\SyncResult;

class Joomla_FrothIQ_SyncClient extends SyncClient
{
    private string $controlCenterUrl;

    public function __construct(string $controlCenterUrl)
    {
        parent::__construct($controlCenterUrl);
        $this->controlCenterUrl = rtrim($controlCenterUrl, '/');
    }

    public function sync(
        string $tenantId,
        string $agentId,
        string $currentTokenJson = '',
        int    $currentVersion   = 0,
        string $requestReason    = 'joomla_heartbeat'
    ): SyncResult {
        if ($tenantId === '') {
            return SyncResult::failure('tenant_id_required');
        }

        $endpoint = $this->controlCenterUrl
            . '/api/method/orbweaver_frothiq.license_system.license_api.sync_license';
        $payload  = json_encode([
            'payload' => [
                'agent_id'                => $agentId,
                'tenant_id'               => $tenantId,
                'current_license_version' => $currentVersion,
                'token_json'              => $currentTokenJson,
                'request_reason'          => $requestReason,
            ],
        ]);

        try {
            $http     = HttpFactory::getHttp();
            $response = $http->post($endpoint, $payload, ['Content-Type' => 'application/json'], 10);

            if ($response->code !== 200) {
                return SyncResult::failure("http_{$response->code}");
            }

            $body = json_decode($response->body, true);
            if (!is_array($body)) {
                return SyncResult::failure('invalid_response_json');
            }

            $msg = $body['message'] ?? $body;
            if (empty($msg['license_token'])) {
                return SyncResult::failure('no_license_token_in_response');
            }

            $tokenJson = json_encode($msg['license_token']);
            return new SyncResult(
                success:    true,
                updated:    (bool) ($msg['updated'] ?? false),
                tokenJson:  $tokenJson ?: null,
                serverTime: (float) ($msg['server_time'] ?? 0.0),
            );
        } catch (\Exception $e) {
            return SyncResult::failure('exception: ' . $e->getMessage());
        }
    }
}
