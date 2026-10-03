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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception;

use RuntimeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class ProjectConfigUserOnlyKeyException extends RuntimeException
{
    public static function forLoosenedBudget(string $projectConfigFile, string $key): self
    {
        return new self(\sprintf(
            'The project config "%s" sets "%s" to something other than a number at or below the cap in your user config — a repository you audit may tighten the budget, never loosen it.',
            $projectConfigFile,
            $key,
        ));
    }

    public static function forShortenedTimeout(string $projectConfigFile, string $key): self
    {
        return new self(\sprintf(
            'The project config "%s" sets "%s" to something other than a number of seconds at or above the timeout your user config allows — a repository you audit may give the provider more time, never less.',
            $projectConfigFile,
            $key,
        ));
    }

    public static function forErasedSection(string $projectConfigFile, string $key): self
    {
        return new self(\sprintf(
            'The project config "%s" sets "%s" to something other than a map, which would drop every setting of that section in your user config — a repository you audit may override single keys beneath it, never the section itself.',
            $projectConfigFile,
            $key,
        ));
    }

    /**
     * @param list<string> $keys
     */
    public static function forKeys(string $projectConfigFile, array $keys): self
    {
        return new self(\sprintf(
            'The project config "%s" declares %s, which decides what the run spends, trusts or writes — a repository you audit must not set it. Configure it in your user config instead.',
            $projectConfigFile,
            implode(' and ', array_map(static fn (string $key): string => \sprintf('"%s"', $key), $keys)),
        ));
    }
}
