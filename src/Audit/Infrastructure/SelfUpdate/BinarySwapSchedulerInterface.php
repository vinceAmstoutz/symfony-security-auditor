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

/**
 * Defers moving a verified download over the running binary until the process
 * is about to end. The standalone binary is a PHAR whose classes load lazily,
 * by path, for as long as the process lives; replacing that path mid-run makes
 * every later autoload read the new archive at the old archive's offsets, so
 * PHP aborts with "internal corruption of phar ... actual filesize mismatch"
 * even though the update itself succeeded.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface BinarySwapSchedulerInterface
{
    /**
     * @param Closure(): void $swap the move to run at the end of the process
     */
    public function schedule(Closure $swap): void;
}
