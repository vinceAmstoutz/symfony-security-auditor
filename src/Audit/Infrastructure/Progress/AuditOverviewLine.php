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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress;

/**
 * The one-line attack-surface overview printed when the audit starts. Leaves
 * out the categories counted zero.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class AuditOverviewLine
{
    /** @param array<string, mixed> $context */
    public static function from(array $context): string
    {
        $files = \sprintf('Auditing %d file(s)', ProgressContext::int($context, 'files'));

        $segments = [];
        foreach (['controller' => 'controllers', 'voter' => 'voters', 'form' => 'forms'] as $noun => $key) {
            $count = ProgressContext::int($context, $key);
            if ($count > 0) {
                $segments[] = \sprintf('%d %s(s)', $count, $noun);
            }
        }

        return [] === $segments ? $files : \sprintf('%s — %s', $files, implode(', ', $segments));
    }
}
