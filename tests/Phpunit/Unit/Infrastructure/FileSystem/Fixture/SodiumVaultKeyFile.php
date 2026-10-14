<?php

/*
 * This file is part of the vinceamstoutz/symfony-security-auditor package.
 *
 * (c) Vincent Amstoutz <vincent.amstoutz.dev@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\FileSystem\Fixture;

/**
 * Writes a decryption key file the way Symfony's `SodiumVault::export()` does, from a key generated
 * when the test runs, so no key material is ever committed.
 */
final class SodiumVaultKeyFile
{
    private const string HEADER = '<?php // prod.decrypt.private on Mon, 12 Oct 2026 05:59:43 +0000';

    public static function generatedKey(): string
    {
        return sodium_crypto_box_keypair();
    }

    /**
     * The bytes as `SodiumVault` spells them in the file: each one `rawurlencode()` escapes written `\xHH`.
     */
    public static function escaped(string $bytes): string
    {
        return str_replace('%', '\x', rawurlencode($bytes));
    }

    public static function contents(string $key): string
    {
        return self::returning($key, $key);
    }

    /**
     * A key file whose base64 copy is of the key and whose literal holds the bytes given.
     */
    public static function returning(string $key, string $returned): string
    {
        return \sprintf("%s\n\n// SYMFONY_DECRYPTION_SECRET=%s\nreturn \"%s\";\n", self::HEADER, base64_encode($key), self::escaped($returned));
    }

    public static function redacted(): string
    {
        return \sprintf("%s\n\n// SYMFONY_DECRYPTION_SECRET=***REDACTED:env_assignment***\nreturn \"***REDACTED:secrets_vault_key***\";\n", self::HEADER);
    }
}
