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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\BaselineWriteFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;

/** @internal not part of the BC promise, see docs/versioning.md */
interface BaselineProcessorInterface
{
    /**
     * The entries of the `--baseline` file, else of the configured one, that
     * carry a `reason`. None when neither is set.
     */
    public function feedback(?string $cliBaseline): ReviewerFeedback;

    /**
     * Refuses a path a baseline could never be generated to.
     *
     * @param string $projectPath the audited project, whose directories are walked for a symlink like the working directory's
     *
     * @throws UnsafeBaselineWriteException
     * @throws BaselineWriteFailedException
     */
    public function assertWritable(string $path, string $projectPath): void;

    /**
     * Writes the report's findings to a baseline file and returns how many.
     */
    public function generate(AuditReport $auditReport, string $path): int;

    /**
     * The accepted fingerprints of the `--baseline` file, else of the
     * configured one. None when neither is set.
     *
     * @return list<string>
     */
    public function acceptedFingerprints(?string $cliBaseline): array;

    /**
     * The files the entries of the `--baseline` file, else of the configured
     * one, name, in its order. None when neither is set.
     *
     * @return list<string>
     */
    public function filePaths(?string $cliBaseline): array;

    /**
     * Leaves the findings the `--baseline` file, else the configured one,
     * accepts out of the report, which stays unchanged when neither is set.
     * The result carries the matched fingerprints, so a format can render
     * those findings as suppressed.
     */
    public function apply(AuditReport $auditReport, ?string $cliBaseline): BaselineResult;
}
