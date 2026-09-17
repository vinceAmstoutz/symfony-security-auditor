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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

/**
 * A value written into the standalone config reaches the container verbatim,
 * where `ParameterBag` reads `%name%` as a parameter reference and `%%` as an
 * escaped percent. Neither is what someone typing a URL means: the first aborts
 * the run with "You have requested a non-existent parameter", the second
 * silently rewrites the value. A whole-value `%env(VAR)%` is the exception,
 * because `StandalonePlatformConfigResolver` resolves it before the container
 * is built.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ContainerParameterSyntax
{
    private const string REFERENCE_PATTERN = '/%%|%[^%\s]++%/';

    public static function accepts(string $value): bool
    {
        return EnvPlaceholder::in($value) instanceof EnvPlaceholder
            || 1 !== preg_match(self::REFERENCE_PATTERN, $value);
    }
}
