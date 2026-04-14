<?php
/**
 * FrothIQ Edge SDK — Token Validator
 *
 * Canonical HMAC-SHA256 verification for FrothIQ license tokens.
 * All logic is STATIC so it can be used independently of the SDK base class.
 *
 * CRITICAL: canonicalJson() MUST produce output IDENTICAL to the Python SDK:
 *   json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
 *
 * KNOWN BUG IN LEGACY STUBS: the old WordPress and Joomla plugins converted
 * nested arrays (features, limits) to their JSON string representations before
 * calling json_encode() on the parent.  This produced canonical JSON like:
 *
 *   {"features":"{\"defense_mesh\":true,...}","limits":"{\"rpm\":600,...}"}
 *
 * instead of the correct:
 *
 *   {"features":{"defense_mesh":true,...},"limits":{"rpm":600,...}}
 *
 * This bug caused HMAC verification to ALWAYS FAIL for tokens with nested
 * structures.  The fix: deep-sort keys without converting to strings.
 *
 * @package   FrothIQ\EdgeSDK
 * @version   1.0.0
 * @copyright 2026, OrbWeaver — Proprietary
 */

declare(strict_types=1);

namespace FrothIQ\EdgeSDK;

final class TokenValidator
{
    /** Required top-level fields on every license token. */
    private const REQUIRED_FIELDS = [
        'tenant_id', 'license_id', 'plan', 'status',
        'signature', 'issued_at', 'expires_at', 'features', 'limits',
    ];

    /** Only schema version 1 is currently supported. */
    public const SUPPORTED_SCHEMA_VERSION = 1;

    // No instantiation — all methods are static.
    private function __construct() {}

    // ------------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------------

    /**
     * Parse a license token JSON string into an array.
     *
     * @param  string $tokenJson  Raw JSON from control center or local cache.
     * @return array              Decoded token array.
     *
     * @throws TokenParseException  on parse failure or missing required fields.
     */
    public static function parse(string $tokenJson): array
    {
        if ($tokenJson === '') {
            throw new TokenParseException('empty token_json');
        }
        $data = json_decode($tokenJson, true);
        if (!is_array($data)) {
            throw new TokenParseException('token must be a JSON object');
        }
        foreach (self::REQUIRED_FIELDS as $field) {
            if (!array_key_exists($field, $data)) {
                throw new TokenParseException("missing required field: {$field}");
            }
        }
        return $data;
    }

    // ------------------------------------------------------------------
    // Schema version
    // ------------------------------------------------------------------

    /**
     * Verify the schema_version field.
     *
     * @throws SchemaVersionException  when version is unknown.
     */
    public static function checkSchemaVersion(array $token): void
    {
        $ver = (int) ($token['schema_version'] ?? 1);
        if ($ver !== self::SUPPORTED_SCHEMA_VERSION) {
            throw new SchemaVersionException(
                "unsupported schema_version: {$ver} (supported: " . self::SUPPORTED_SCHEMA_VERSION . ')'
            );
        }
    }

    // ------------------------------------------------------------------
    // Tenant binding
    // ------------------------------------------------------------------

    /**
     * Verify the token's tenant_id matches the expected value.
     *
     * @throws TenantMismatchException  on mismatch (fail closed).
     */
    public static function checkTenantBinding(array $token, string $expectedTenantId): void
    {
        if (($token['tenant_id'] ?? '') !== $expectedTenantId) {
            throw new TenantMismatchException(
                "tenant_id mismatch: token has '{$token['tenant_id']}', expected '{$expectedTenantId}'"
            );
        }
    }

    // ------------------------------------------------------------------
    // Signature verification
    // ------------------------------------------------------------------

    /**
     * Verify the HMAC-SHA256 signature on a decoded token array.
     *
     * Uses constant-time comparison (hash_equals) to prevent timing attacks.
     *
     * @param  array  $token       Decoded token (must include 'signature').
     * @param  string $signingKey  Raw signing key bytes (from FROTHIQ_LICENSE_SECRET).
     * @return bool                True if the signature is valid.
     *
     * @throws SignatureException  if 'signature' field is missing.
     */
    public static function verifySignature(array $token, string $signingKey): bool
    {
        $submitted = $token['signature'] ?? '';
        if ($submitted === '') {
            throw new SignatureException('missing signature field');
        }
        $payload  = $token;
        unset($payload['signature']);
        $canonical = self::canonicalJson($payload);
        $expected  = hash_hmac('sha256', $canonical, $signingKey);
        // hash_equals — constant-time, immune to timing side-channels.
        return hash_equals($expected, $submitted);
    }

    // ------------------------------------------------------------------
    // Expiry
    // ------------------------------------------------------------------

    /**
     * Return true if the token has NOT yet expired.
     */
    public static function isNotExpired(array $token): bool
    {
        try {
            return time() < (float) ($token['expires_at'] ?? 0);
        } catch (\Throwable) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Canonical JSON  (THE FIX — matches Python SDK exactly)
    // ------------------------------------------------------------------

    /**
     * Produce canonical JSON for HMAC computation.
     *
     * Equivalent to Python's:
     *   json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
     *
     * The key property: EVERY nested associative array has its keys sorted
     * recursively.  The result is JSON-encoded ONCE at the top level — NOT
     * converted to a string at each level of nesting.
     *
     * @param  array  $data  Token payload (without 'signature').
     * @return string        Canonical JSON string.
     */
    public static function canonicalJson(array $data): string
    {
        return json_encode(
            self::deepKsort($data),
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );
    }

    /**
     * Recursively sort associative-array keys without converting values to strings.
     *
     * This is the correct implementation.  The legacy stubs set
     * $data[$key] = $this->canonicalJson($val) which turned nested arrays
     * into strings, producing wrong canonical form and broken HMAC.
     */
    private static function deepKsort(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }
        ksort($value);
        foreach ($value as $k => $v) {
            $value[$k] = self::deepKsort($v);
        }
        return $value;
    }
}
