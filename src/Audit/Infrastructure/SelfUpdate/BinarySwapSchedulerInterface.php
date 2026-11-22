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
 * ends: the PHAR loads its classes lazily, so replacing it mid-run corrupts
 * every later autoload.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface BinarySwapSchedulerInterface
{
    /**
     * @param Closure(): void $swap the move to run at the end of the process
     */
    public function schedule(Closure $swap): void;
}
