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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;

/**
 * Test fake: a scanner that cannot be told where to look, like any custom
 * scanner written before the opt-in port existed.
 */
final readonly class FixedScanner implements ProjectFileScannerInterface
{
    /**
     * @param list<ProjectFile> $files
     */
    public function __construct(private array $files) {}

    #[Override]
    public function scan(string $projectPath): array
    {
        return $this->files;
    }
}
