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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture;

use Override;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;

/**
 * Test fake — a filesystem whose disk fills up as the report is saved, after
 * every check made before the run passed.
 *
 * @internal scoped to AuditCommand save-failure integration tests
 */
final class FailingDumpFilesystem extends Filesystem
{
    public const string FAILURE = 'No space left on device';

    #[Override]
    public function dumpFile(string $filename, $content): void
    {
        throw new IOException(self::FAILURE, path: $filename);
    }
}
