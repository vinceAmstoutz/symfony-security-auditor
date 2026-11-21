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

/** @internal not part of the BC promise, see docs/versioning.md */
final readonly class EnclosingProjectScope
{
    /**
     * @param list<string> $scanPaths
     */
    public static function line(string $folder, array $scanPaths): string
    {
        if ([] === $scanPaths) {
            return \sprintf('Scope: <info>whole project</info> <fg=gray>(no composer.json in "%s": auditing its enclosing project)</>', $folder);
        }

        return \sprintf('Scope: <info>%s</info> <fg=gray>(no composer.json in the folder named: auditing its enclosing project)</>', implode(', ', $scanPaths));
    }
}
