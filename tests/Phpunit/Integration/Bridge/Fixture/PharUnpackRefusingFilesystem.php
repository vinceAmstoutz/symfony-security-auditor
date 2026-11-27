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

use function Symfony\Component\String\u;

/**
 * Refuses to copy a file out of a phar, as a full disk does.
 */
final class PharUnpackRefusingFilesystem extends Filesystem
{
    #[Override]
    public function copy(string $originFile, string $targetFile, bool $overwriteNewerFiles = false): void
    {
        if (u($originFile)->startsWith('phar://')) {
            throw new IOException(\sprintf('Cannot copy "%s".', $originFile));
        }

        parent::copy($originFile, $targetFile, $overwriteNewerFiles);
    }
}
