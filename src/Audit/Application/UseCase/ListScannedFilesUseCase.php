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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScanPathFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;

/**
 * Resolves the exact set of files an audit would ingest — the project scan
 * narrowed by the same scan-path filter the real run applies — without
 * invoking the LLM. Backs the `--show-scanned` console option so a user can
 * confirm their `included_paths` / `--path` configuration matches the files
 * they expect before paying for a run.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ListScannedFilesUseCase
{
    public function __construct(private ProjectFileScannerInterface $projectFileScanner) {}

    /**
     * @param list<string> $scanPaths optional project-relative subdirectories
     *                                to restrict the listing to; empty list
     *                                (the default) lists every scanned file
     *
     * @return list<ProjectFile>
     */
    public function execute(string $projectPath, array $scanPaths = []): array
    {
        return ScanPathFilter::apply($this->projectFileScanner->scan($projectPath), $scanPaths);
    }
}
