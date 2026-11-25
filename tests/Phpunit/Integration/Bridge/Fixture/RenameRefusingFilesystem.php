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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bridge\Fixture;

use Override;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;

/**
 * Refuses every rename, as a locked folder does.
 */
final class RenameRefusingFilesystem extends Filesystem
{
    #[Override]
    public function rename(string $origin, string $target, bool $overwrite = false): void
    {
        throw new IOException(\sprintf('Cannot rename "%s".', $origin));
    }
}
