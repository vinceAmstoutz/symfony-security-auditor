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

use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/** @internal not part of the BC promise, see docs/versioning.md */
interface AuditPresenterInterface
{
    public function header(SymfonyStyle $symfonyStyle, string $projectPath): void;

    /**
     * Says that the run audits the project enclosing `$folder`, which is not a
     * project, narrowed to `$scanPaths`.
     *
     * @param list<string> $scanPaths project-relative, none when the project itself was named
     */
    public function enclosingProject(SymfonyStyle $symfonyStyle, string $folder, array $scanPaths): void;

    /**
     * @param list<string> $configNotices
     */
    public function preflightWarnings(SymfonyStyle $symfonyStyle, bool $secretScrubbingEnabled, array $configNotices = []): void;

    /**
     * Says that a `--min-score` below 0 is honored and gates no run.
     */
    public function minScoreBelowRange(SymfonyStyle $symfonyStyle, int $minScore): void;

    /**
     * Says that a `--min-score` above 100 is honored and fails every run.
     */
    public function minScoreAboveRange(SymfonyStyle $symfonyStyle, int $minScore): void;

    public function unsupportedModelWarnings(SymfonyStyle $symfonyStyle, AuditReport $auditReport): void;

    public function synthesisCostWarnings(SymfonyStyle $symfonyStyle, bool $pocSynthesisEnabled, bool $fixSynthesisEnabled): void;

    public function runningSection(SymfonyStyle $symfonyStyle): void;

    public function longRunNotice(SymfonyStyle $symfonyStyle): void;

    public function estimatingSection(SymfonyStyle $symfonyStyle): void;

    public function dryRunResult(SymfonyStyle $symfonyStyle, AuditReport $auditReport): void;

    /**
     * @param list<ProjectFile> $projectFiles
     */
    public function scannedFiles(SymfonyStyle $symfonyStyle, array $projectFiles): void;

    /**
     * Says that the scan listed no file, naming the project and the `--path`
     * values it looked under.
     *
     * @param list<string> $scanPaths
     */
    public function noFilesMatched(SymfonyStyle $symfonyStyle, string $projectPath, array $scanPaths): void;

    public function scannedFilesHint(SymfonyStyle $symfonyStyle, int $fileCount): void;

    public function error(SymfonyStyle $symfonyStyle, Throwable $throwable): void;

    /**
     * @param string $failOnIncompleteSetting the flag or configuration key that failed an incomplete run, named when it did
     */
    public function result(SymfonyStyle $symfonyStyle, AuditReport $auditReport, int $exitCode, string $failOnIncompleteSetting): void;

    /**
     * Says so when the report is incomplete or has no verdict, nothing
     * otherwise. `result()` prints it too.
     *
     * @param string $failOnIncompleteSetting the flag or configuration key that failed an incomplete run, named when it did
     */
    public function incompleteRunNotice(SymfonyStyle $symfonyStyle, AuditReport $auditReport, int $exitCode, string $failOnIncompleteSetting): void;

    public function baselineGenerated(SymfonyStyle $symfonyStyle, string $path, int $fingerprintCount): void;

    /**
     * Says why a run with no verdict left the baseline at `$path` untouched.
     */
    public function baselineKept(SymfonyStyle $symfonyStyle, string $path, AuditReport $auditReport): void;
}
