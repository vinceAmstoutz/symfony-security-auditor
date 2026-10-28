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

/** @internal not part of the BC promise — see docs/versioning.md */
interface ReleaseClientInterface
{
    /**
     * @throws SelfUpdateFailedException
     */
    public function get(string $url): string;

    /**
     * @param (Closure(int): void)|null $onProgress called with the bytes received so far, while the download runs and once it ends
     *
     * @throws SelfUpdateFailedException
     */
    public function download(string $url, string $destination, ?Closure $onProgress = null): void;
}
