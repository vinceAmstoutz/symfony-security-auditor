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

use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedBaselineFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;

/** @internal not part of the BC promise, see docs/versioning.md */
interface BaselineMergerInterface
{
    /**
     * Plans a merge of a JSON report's findings into a baseline file. Each
     * entry accepts one occurrence, so a finding duplicated beyond its
     * accepted count is new again.
     *
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     * @throws MalformedBaselineFileException
     */
    public function plan(string $reportPath, string $baselinePath, bool $prune): BaselineMergePlan;

    /**
     * Writes the kept entries verbatim, then one dated entry per new finding.
     *
     * @param array<int, string> $reasons acceptance reason per `newFindings` index
     *
     * @throws MalformedBaselineFileException
     * @throws UnsafeBaselineWriteException
     */
    public function commit(string $baselinePath, BaselineMergePlan $baselineMergePlan, array $reasons): void;
}
