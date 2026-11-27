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
 * Refuses to delete a phar, as Windows does while the process that unpacked it still holds it.
 */
final class PharRemovalRefusingFilesystem extends Filesystem
{
    /**
     * @param string|iterable<mixed, mixed> $files
     */
    #[Override]
    public function remove(string|iterable $files): void
    {
        if (\is_string($files) && u($files)->endsWith('.phar')) {
            throw new IOException(\sprintf('Failed to remove file "%s": Permission denied.', $files));
        }

        parent::remove($files);
    }
}
