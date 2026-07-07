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
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\BaselineSuppressingReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsupportedOutputFormatException;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ReportWriter implements ReportWriterInterface
{
    /** @var array<string, ReportRendererInterface> */
    private array $renderers;

    /** @param iterable<ReportRendererInterface> $renderers */
    public function __construct(
        iterable $renderers,
        private Filesystem $filesystem,
    ) {
        $indexed = [];
        foreach ($renderers as $renderer) {
            $indexed[$renderer->format()] = $renderer;
        }

        $this->renderers = $indexed;
    }

    /**
     * @param list<string> $baselinedFingerprints
     *
     * @throws UnsupportedOutputFormatException
     */
    #[Override]
    public function write(AuditReport $auditReport, OutputFormat $outputFormat, ?string $outputFile, SymfonyStyle $symfonyStyle, array $baselinedFingerprints = []): void
    {
        $content = $this->renderContent($outputFormat, $auditReport, $baselinedFingerprints);

        if (null === $outputFile) {
            // OUTPUT_RAW keeps markup-lookalike text in finding titles/proofs out of the console
            // formatter for every format, including console: no renderer emits real Symfony tags,
            // so any `<...>` in that content is untrusted data from the audited codebase, not markup.
            $symfonyStyle->writeln($content, OutputInterface::OUTPUT_RAW);

            return;
        }

        $this->filesystem->dumpFile($outputFile, $content);
        $symfonyStyle->success(\sprintf('Report saved to %s', $outputFile));
    }

    /**
     * @param list<string> $baselinedFingerprints
     *
     * @throws UnsupportedOutputFormatException
     */
    private function renderContent(OutputFormat $outputFormat, AuditReport $auditReport, array $baselinedFingerprints): string
    {
        $reportRenderer = $this->rendererFor($outputFormat);

        return $reportRenderer instanceof BaselineSuppressingReportRendererInterface
            ? $reportRenderer->renderWithSuppressions($auditReport, $baselinedFingerprints)
            : $reportRenderer->render($auditReport);
    }

    /**
     * @throws UnsupportedOutputFormatException
     */
    private function rendererFor(OutputFormat $outputFormat): ReportRendererInterface
    {
        return $this->renderers[$outputFormat->value]
            ?? throw UnsupportedOutputFormatException::forFormat($outputFormat->value);
    }
}
