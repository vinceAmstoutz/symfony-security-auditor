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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InsufficientTrendReportsException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;

/**
 * Tracks how finding counts evolve across a chronological series of JSON
 * audit reports.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface ReportTrendAnalyzerInterface
{
    /**
     * @param list<string> $reportPaths paths to two or more JSON reports, ordered oldest to newest
     *
     * @throws InsufficientTrendReportsException
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function analyze(array $reportPaths): ReportTrend;
}
