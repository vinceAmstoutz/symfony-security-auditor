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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

/**
 * Names the first files of a list and counts the others.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class NamedFiles
{
    private const int NAMED = 5;

    /**
     * @param list<string> $paths
     */
    public static function of(array $paths): string
    {
        $named = implode(', ', \array_slice($paths, 0, self::NAMED));
        $others = \count($paths) - self::NAMED;

        return $others > 0 ? \sprintf('%s and %d more', $named, $others) : $named;
    }
}
