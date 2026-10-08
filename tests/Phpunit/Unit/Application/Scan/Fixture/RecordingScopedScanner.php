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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ScopedProjectFileScannerInterface;

/**
 * Test fake: a scanner that can be told where to look and keeps which of its
 * two methods were called, with which paths.
 */
final class RecordingScopedScanner implements ScopedProjectFileScannerInterface
{
    /** @var list<array{string, list<string>|null}> */
    public array $calls = [];

    /**
     * @param list<ProjectFile> $configuredFiles what `scan()` returns
     * @param list<ProjectFile> $scopedFiles     what `scanWithin()` returns
     */
    public function __construct(
        private readonly array $configuredFiles,
        private readonly array $scopedFiles,
    ) {}

    #[Override]
    public function scan(string $projectPath): array
    {
        $this->calls[] = ['scan', null];

        return $this->configuredFiles;
    }

    #[Override]
    public function scanWithin(string $projectPath, array $scanPaths): array
    {
        $this->calls[] = ['scanWithin', $scanPaths];

        return $this->scopedFiles;
    }
}
