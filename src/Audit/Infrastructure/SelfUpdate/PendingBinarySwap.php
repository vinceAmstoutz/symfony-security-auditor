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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate;

use Closure;
use Override;

/**
 * Holds the verified download's final move until the entry point commits it,
 * once the console application has finished and no further class can be
 * autoloaded from the archive being replaced.
 *
 * Mutable by design — {@see SelfUpdater} registers the move through
 * {@see schedule()} mid-run, and the standalone entry point drains it through
 * {@see commit()} on the way out.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class PendingBinarySwap implements BinarySwapSchedulerInterface
{
    /** @var list<Closure(): void> */
    private array $swaps = [];

    /**
     * @param Closure(): void $swap
     */
    #[Override]
    public function schedule(Closure $swap): void
    {
        $this->swaps[] = $swap;
    }

    public function commit(): void
    {
        $swaps = $this->swaps;
        $this->swaps = [];

        foreach ($swaps as $swap) {
            $swap();
        }
    }
}
