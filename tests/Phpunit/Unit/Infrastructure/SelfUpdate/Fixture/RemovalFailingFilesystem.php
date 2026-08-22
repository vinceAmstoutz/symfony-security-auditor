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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\SelfUpdate\Fixture;

use Override;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;

final class RemovalFailingFilesystem extends Filesystem
{
    /**
     * @param string|iterable<mixed> $files
     */
    #[Override]
    public function remove(string|iterable $files): void
    {
        throw new IOException('Simulated failure removing the leftover download.');
    }
}
