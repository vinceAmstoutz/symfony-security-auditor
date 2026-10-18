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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Scan\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReadSharingProjectFileScannerInterface;

/**
 * Test fake: a scanner that finds nothing itself and hands out the scanner it was given as the one
 * sharing its reads.
 */
final readonly class ReadSharingScanner implements ReadSharingProjectFileScannerInterface
{
    public function __construct(private ProjectFileScannerInterface $projectFileScanner) {}

    #[Override]
    public function scan(string $projectPath): array
    {
        return [];
    }

    #[Override]
    public function sharingReads(): ProjectFileScannerInterface
    {
        return $this->projectFileScanner;
    }
}
