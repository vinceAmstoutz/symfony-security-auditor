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
use Symfony\Component\Filesystem\Filesystem;

/**
 * Counts the files copied through it.
 */
final class CopyCountingFilesystem extends Filesystem
{
    public int $copies = 0;

    #[Override]
    public function copy(string $originFile, string $targetFile, bool $overwriteNewerFiles = false): void
    {
        ++$this->copies;

        parent::copy($originFile, $targetFile, $overwriteNewerFiles);
    }
}
