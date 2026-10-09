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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileScan;

/**
 * What {@see ScopedScan} found for a run: the scan of the files it audits, and
 * the wider set of files the Symfony mapping is read from.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ScopedScanResult
{
    /**
     * @param list<ProjectFile> $mappingFiles
     */
    public function __construct(
        public ProjectFileScan $audited,
        public array $mappingFiles,
    ) {}
}
