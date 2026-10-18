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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProbingProjectFileScannerInterface;

/**
 * Test fake: a scanner that answers a probe as told and keeps which projects it was probed and
 * scanned for.
 */
final class ProbingScanner implements ProbingProjectFileScannerInterface
{
    /** @var list<string> */
    public array $probedProjectPaths = [];

    /** @var list<string> */
    public array $scannedProjectPaths = [];

    public function __construct(private readonly bool $reachesAFile) {}

    #[Override]
    public function scan(string $projectPath): array
    {
        $this->scannedProjectPaths[] = $projectPath;

        return [];
    }

    #[Override]
    public function reachesAFile(string $projectPath): bool
    {
        $this->probedProjectPaths[] = $projectPath;

        return $this->reachesAFile;
    }
}
