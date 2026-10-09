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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem;

/**
 * Tells a value that names a thing from a value that may be a secret, under a key that names a credential:
 * `refresh_token_class: App\Entity\RefreshToken`, `secret_key: '%kernel.project_dir%/config/jwt/private.pem'`,
 * `access_token_url: https://github.com/login/oauth/access_token` or `reset_password_code_validity: 14400`
 * are stock bundle configuration. Redacting them hides the structure from the model and tells it, through
 * the `scrubbed_secret` marker, that a secret is committed.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class NonSecretValue
{
    private const string CLASS_NAME = '/\A\\\\?[A-Za-z_]\w*(?:\\\\{1,2}[A-Za-z_]\w*)+(?:::class)?\z/';

    private const string PARAMETER_REFERENCE = '/%(?:env\([^)%\s]++\)|[a-z_][\w\-]*+(?:\.[\w\-]++)++)%/i';

    private const string PATH = '/\A(?:~|\.{1,2})?(?:\/[\w.\-]++){2,}\/?\z/';

    private const string URL = '/\Ahttps?:\/\/[^\s@\/?#]++(?:\/[^\s?#]*+)?\z/i';

    private const string NUMBER = '/\A\d++\z/';

    private const string URL_KEY = '/[_-](?:url|uri|endpoint)["\']?\]?\s*(?:=>|:(?!:)|=)/i';

    private const string DURATION_KEY = '/[_-](?:ttl|validity|lifetime|expiry|expires|expiration|timeout|length|size|bits|count|age|interval|duration)["\']?\]?\s*(?:=>|:(?!:)|=)/i';

    /**
     * @param string $prefix the key and the operator the value was written after
     */
    public function holdsNoSecret(string $prefix, string $value): bool
    {
        return \in_array(1, [preg_match(self::CLASS_NAME, $value), preg_match(self::PARAMETER_REFERENCE, $value), preg_match(self::PATH, $value)], true)
            || $this->fitsItsKey($prefix, $value);
    }

    private function fitsItsKey(string $prefix, string $value): bool
    {
        return (1 === preg_match(self::URL_KEY, $prefix) && 1 === preg_match(self::URL, $value))
            || (1 === preg_match(self::DURATION_KEY, $prefix) && 1 === preg_match(self::NUMBER, $value));
    }
}
