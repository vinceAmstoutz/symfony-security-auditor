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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;

/** @internal not part of the BC promise — see docs/versioning.md */
interface ReleaseClientInterface
{
    /**
     * @throws SelfUpdateFailedException
     */
    public function get(string $url): string;

    /**
     * @throws SelfUpdateFailedException
     */
    public function download(string $url, string $destination): void;
}
