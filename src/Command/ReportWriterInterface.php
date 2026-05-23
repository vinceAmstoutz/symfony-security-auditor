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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

/** @internal not part of the BC promise — see docs/versioning.md */
interface ReportWriterInterface
{
    public function write(AuditReport $auditReport, OutputFormat $outputFormat, ?string $outputFile, SymfonyStyle $symfonyStyle): void;
}
