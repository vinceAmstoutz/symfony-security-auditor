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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone;

use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnloadableBridgeTreeException;

/**
 * The `vendor/composer/platform_check.php` of a bridge tree refuses a PHP it
 * was not resolved for by throwing since Composer 2.8.10, and before that
 * through `trigger_error(…, E_USER_ERROR)`, which ends the process. While the
 * tree's autoloader is required, this error handler turns the older form into
 * the exception the newer one throws, so both are reported the same way.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformCheckErrorConverter
{
    /**
     * PHP 8.4 deprecates the call raising that error, just ahead of it.
     */
    private const string RAISING_CALL_DEPRECATION = 'Passing E_USER_ERROR to trigger_error()';

    /**
     * True for the deprecation that only announces the error, which reports
     * the same refusal; false hands every other error to PHP.
     *
     * @throws UnloadableBridgeTreeException
     */
    public function __invoke(int $severity, string $message): bool
    {
        if (\E_USER_ERROR === $severity) {
            throw UnloadableBridgeTreeException::fromPlatformCheck($message);
        }

        return \E_DEPRECATED === $severity && str_starts_with($message, self::RAISING_CALL_DEPRECATION);
    }
}
