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

namespace VinceAmstoutz\SecurityAuditor\Command;

use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SecurityAuditor\Command\Exception\ReportWriteFailedException;
use VinceAmstoutz\SecurityAuditor\Command\Exception\UnsafeReportWriteException;
use VinceAmstoutz\SecurityAuditor\Command\Exception\UnsupportedOutputFormatException;

/** @internal not part of the BC promise — see docs/versioning.md */
interface ReportWriterInterface
{
    /**
     * @param list<string> $baselinedFingerprints fingerprints rendered as suppressed instead of dropped, by formats that support it (currently SARIF)
     *
     * @throws UnsupportedOutputFormatException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function write(AuditReport $auditReport, OutputFormat $outputFormat, ?string $outputFile, SymfonyStyle $symfonyStyle, array $baselinedFingerprints = []): void;
}
