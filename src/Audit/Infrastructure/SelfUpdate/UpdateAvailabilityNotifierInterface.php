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

/** @internal not part of the BC promise — see docs/versioning.md */
interface UpdateAvailabilityNotifierInterface
{
    /**
     * Returns a one-line notice when a newer release than $currentVersion is
     * available, or null when the running version is current, cannot be
     * compared, or the check could not be performed.
     */
    public function availableUpdateNotice(string $currentVersion): ?string;
}
