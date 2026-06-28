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

use Override;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRenderer;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ReportWriter implements ReportWriterInterface
{
    public function __construct(
        private ReportRenderer $reportRenderer,
        private Filesystem $filesystem,
    ) {}

    #[Override]
    public function write(AuditReport $auditReport, OutputFormat $outputFormat, ?string $outputFile, SymfonyStyle $symfonyStyle): void
    {
        $content = match ($outputFormat) {
            OutputFormat::Json => $this->reportRenderer->renderJson($auditReport),
            OutputFormat::Sarif => $this->reportRenderer->renderSarif($auditReport),
            OutputFormat::Html => $this->reportRenderer->renderHtml($auditReport),
            OutputFormat::Markdown => $this->reportRenderer->renderMarkdown($auditReport),
            OutputFormat::Console => $this->reportRenderer->renderConsole($auditReport),
        };

        if (null === $outputFile) {
            $symfonyStyle->writeln($content);

            return;
        }

        $this->filesystem->dumpFile($outputFile, $content);
        $symfonyStyle->success(\sprintf('Report saved to %s', $outputFile));
    }
}
