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

/** @internal not part of the BC promise — see docs/versioning.md */
interface AuditPresenterInterface
{
    public function header(SymfonyStyle $symfonyStyle, string $projectPath): void;

    /**
     * @param list<string> $configNotices
     */
    public function preflightWarnings(SymfonyStyle $symfonyStyle, bool $secretScrubbingEnabled, array $configNotices = []): void;

    public function unsupportedModelWarnings(SymfonyStyle $symfonyStyle, AuditReport $auditReport): void;

    public function runningSection(SymfonyStyle $symfonyStyle): void;

    public function longRunNotice(SymfonyStyle $symfonyStyle): void;

    public function estimatingSection(SymfonyStyle $symfonyStyle): void;

    public function dryRunResult(SymfonyStyle $symfonyStyle, AuditReport $auditReport): void;

    public function error(SymfonyStyle $symfonyStyle, Throwable $throwable): void;

    public function result(SymfonyStyle $symfonyStyle, AuditReport $auditReport, int $exitCode): void;
}
