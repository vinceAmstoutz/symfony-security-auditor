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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\UnsupportedSelfUpdatePlatformException;

/** @internal not part of the BC promise — see docs/versioning.md */
interface SelfUpdaterInterface
{
    /**
     * @param (Closure(int): void)|null $onDownloadProgress called with the bytes of the new binary received so far
     *
     * @throws SelfUpdateFailedException
     * @throws UnsupportedSelfUpdatePlatformException
     */
    public function run(string $currentVersion, bool $checkOnly, ReleaseChannel $releaseChannel = ReleaseChannel::Stable, ?Closure $onDownloadProgress = null): SelfUpdateResult;
}
