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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileScan;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SkippedFileReportingProjectFileScannerInterface;

/**
 * Test fake: a scanner that reports the files it left out and keeps the paths
 * each scan was asked for.
 */
final class RecordingReportingScanner implements SkippedFileReportingProjectFileScannerInterface
{
    /** @var list<list<string>> */
    public array $requestedPaths = [];

    public function __construct(
        private readonly ProjectFileScan $configuredScan,
        private readonly ProjectFileScan $scopedScan,
    ) {}

    #[Override]
    public function scan(string $projectPath): array
    {
        return $this->scanReportingSkippedFiles($projectPath)->files;
    }

    #[Override]
    public function scanReportingSkippedFiles(string $projectPath, array $scanPaths = []): ProjectFileScan
    {
        $this->requestedPaths[] = $scanPaths;

        return [] === $scanPaths ? $this->configuredScan : $this->scopedScan;
    }
}
