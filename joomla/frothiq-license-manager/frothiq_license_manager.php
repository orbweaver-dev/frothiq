<?php
/**
 * FrothIQ License Manager — Joomla System Plugin
 *
 * @package   FrothIQ\Joomla
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 *
 * DESIGN CONTRACT
 * ===============
 *  FAIL CLOSED:  missing / invalid / unsigned token → quarantine mode.
 *  NO ONLINE CHECK ON EVERY REQUEST: local HMAC verify + TTL check only.
 *  CACHE FALLBACK: last valid token in #__frothiq_license for up to 4 hours.
 *
 * Heartbeat
 * ---------
 *   Fires on onAfterRoute when last sync was >6 hours ago.
 *   Does NOT require Joomla task scheduler — self-triggering on request.
 */

defined('_JEXEC') or die;

use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Factory;
use FrothIQ\EdgeSDK\LicenseResult;

// ---------------------------------------------------------------------------
// Autoload the FrothIQ Edge SDK PHP classes
// ---------------------------------------------------------------------------

$_frothiq_sdk_root = __DIR__ . '/../../../../edge_sdk/php/';
foreach ([
    'Exceptions.php',
    'LicenseResult.php',
    'TokenValidator.php',
    'FeatureGate.php',
    'OfflineGraceManager.php',
    'SyncClient.php',
    'AuditEmitter.php',
    'FrothIQSDKBase.php',
] as $_file) {
    $path = $_frothiq_sdk_root . $_file;
    if (file_exists($path)) {
        require_once $path;
    }
}
unset($_frothiq_sdk_root, $_file, $path);

require_once __DIR__ . '/includes/class-joomla-storage.php';


// ---------------------------------------------------------------------------
// Plugin class
// ---------------------------------------------------------------------------

class PlgSystemFrothiqLicense extends CMSPlugin
{
    /**
     * onAfterInitialise — earliest safe hook to validate license.
     * Called on every Joomla request. Uses cached result (no network call).
     */
    public function onAfterInitialise(): void
    {
        $manager = $this->getLicenseManager();
        if ($manager === null) {
            return; // Not configured — allow setup to proceed
        }

        $result = $manager->validate();

        // Expose result to FrothIQ protection layer via application state
        $app = Factory::getApplication();
        $app->set('frothiq.license', $result);
        $app->set('frothiq.can_block', $result->canBlock());
        $app->set('frothiq.can_log',   $result->canLog());
    }

    /**
     * onAfterRoute — perform heartbeat sync check.
     * Fires sync if last sync was > 6 hours ago.
     * Fires AFTER routing so a license update doesn't affect the current request.
     */
    public function onAfterRoute(): void
    {
        $lastSync = (int) $this->params->get('last_heartbeat_ts', 0);
        if ((time() - $lastSync) > (6 * 3600)) {
            $this->doHeartbeat();
        }
    }

    // ------------------------------------------------------------------
    // Private
    // ------------------------------------------------------------------

    private function getLicenseManager(): ?FrothIQ_Joomla_LicenseManager
    {
        $secret = (string) $this->params->get('license_secret', '');
        if (!defined('FROTHIQ_LICENSE_SECRET') && $secret === '') {
            return null; // Not configured
        }
        return new FrothIQ_Joomla_LicenseManager($this->params);
    }

    private function doHeartbeat(): void
    {
        $manager = $this->getLicenseManager();
        if ($manager === null) {
            return;
        }

        $manager->heartbeat();

        // Update heartbeat timestamp in params
        $this->params->set('last_heartbeat_ts', time());
        // Persist params
        try {
            $db    = Factory::getDbo();
            $query = $db->getQuery(true)
                ->update($db->quoteName('#__extensions'))
                ->set($db->quoteName('params') . ' = ' . $db->quote((string) $this->params))
                ->where($db->quoteName('element') . ' = ' . $db->quote('frothiqlicense'))
                ->where($db->quoteName('folder') . ' = ' . $db->quote('system'));
            $db->setQuery($query)->execute();
        } catch (\Exception) {
            // Best-effort — heartbeat timestamp update is non-critical
        }
    }
}
