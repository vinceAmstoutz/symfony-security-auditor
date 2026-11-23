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
 * Turns the `E_USER_ERROR` a bridge tree's `vendor/composer/platform_check.php`
 * raises before Composer 2.8.10 into the exception later Composer releases
 * throw, so both refusals are reported the same way.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PlatformCheckErrorConverter
{
    /**
     * The deprecation PHP 8.4 raises just before that error.
     */
    private const string RAISING_CALL_DEPRECATION = 'Passing E_USER_ERROR to trigger_error()';

    /**
     * Returns true for the deprecation announcing the error and false, which
     * hands the error to PHP, for any other.
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
