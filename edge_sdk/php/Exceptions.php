<?php
/**
 * FrothIQ Edge SDK — Exception Hierarchy
 *
 * All SDK exceptions extend FrothIQSDKException.
 * The base is intentionally minimal — only exceptions that change
 * caller behavior are given distinct types.
 *
 * @package   FrothIQ\EdgeSDK
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 */

declare(strict_types=1);

namespace FrothIQ\EdgeSDK;

// ---------------------------------------------------------------------------
// Base
// ---------------------------------------------------------------------------

/**
 * Root of the FrothIQ SDK exception tree.
 *
 * Callers that do not need to distinguish sub-types can catch this.
 */
class FrothIQSDKException extends \RuntimeException {}

// ---------------------------------------------------------------------------
// Validation exceptions (all → quarantine unless otherwise noted)
// ---------------------------------------------------------------------------

/**
 * Thrown when a license token JSON cannot be parsed or is missing
 * required fields.  → offline_fallback path.
 */
class TokenParseException extends FrothIQSDKException {}

/**
 * Thrown when the HMAC-SHA256 signature does not match the token payload.
 * FAIL CLOSED: always maps to quarantine; no offline grace.
 */
class SignatureException extends FrothIQSDKException {}

/**
 * Thrown when the token's tenant_id does not match the expected value.
 * FAIL CLOSED: always maps to quarantine; no offline grace.
 */
class TenantMismatchException extends FrothIQSDKException {}

/**
 * Thrown when the token carries a schema_version the SDK does not recognise.
 * FAIL CLOSED: always maps to quarantine.
 */
class SchemaVersionException extends FrothIQSDKException {}

// ---------------------------------------------------------------------------
// Sync / network exceptions (do NOT map to quarantine — use grace period)
// ---------------------------------------------------------------------------

/**
 * Thrown when the heartbeat sync request to the control center fails.
 * Caller should allow offline grace period to continue; NOT quarantine.
 */
class SyncException extends FrothIQSDKException {}

/**
 * Thrown when a token store operation fails (disk write, DB write, etc.).
 * Last-known-good token remains in place.
 */
class StorageException extends FrothIQSDKException {}
