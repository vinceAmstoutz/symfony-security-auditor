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
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\SymlinkGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\BaselineSuppressingReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportWriteFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeReportWriteException;
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
        private WorkflowCommandNeutralizerInterface $workflowCommandNeutralizer = new WorkflowCommandNeutralizer(false),
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
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    #[Override]
    public function write(AuditReport $auditReport, OutputFormat $outputFormat, ?string $outputFile, SymfonyStyle $symfonyStyle, array $baselinedFingerprints = []): void
    {
        $content = $this->renderContent($outputFormat, $auditReport, $baselinedFingerprints);

        if (null === $outputFile) {
            $this->keepOnConsole($symfonyStyle, $outputFormat, $content);

            return;
        }

        try {
            $this->assertSafeToWrite($outputFile, $auditReport->projectPath());
            WritableFilePath::dump($this->filesystem, $outputFile, $content);
        } catch (UnsafeReportWriteException $unsafeReportWriteException) {
            $this->keepOnConsole($symfonyStyle, $outputFormat, $content);

            throw $unsafeReportWriteException;
        } catch (IOException $ioException) {
            $this->keepOnConsole($symfonyStyle, $outputFormat, $content);

            throw ReportWriteFailedException::fromIOException($outputFile, $ioException);
        }

        $symfonyStyle->success(\sprintf('Report saved to %s', $outputFile));
    }

    /**
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    #[Override]
    public function assertWritable(?string $outputFile, string $projectPath): void
    {
        if (null === $outputFile) {
            return;
        }

        $this->assertSafeToWrite($outputFile, $projectPath);

        if (WritableFilePath::namesADirectory($outputFile)) {
            throw ReportWriteFailedException::forDirectoryPath($outputFile);
        }

        try {
            $this->filesystem->mkdir(\dirname($outputFile));
        } catch (IOException $ioException) {
            throw ReportWriteFailedException::forUncreatableDirectory($outputFile, $ioException);
        }

        if (!WritableFilePath::canBeWritten($outputFile)) {
            throw ReportWriteFailedException::forUnwritablePath($outputFile);
        }
    }

    /**
     * A report reaches the console when no `--output` was given, and also
     * when its file cannot be written: the audit already ran and paid for
     * it, so it goes to the console instead of vanishing with the exception.
     */
    private function keepOnConsole(SymfonyStyle $symfonyStyle, OutputFormat $outputFormat, string $content): void
    {
        // OUTPUT_RAW: no renderer emits real Symfony tags, so a finding's own `<...>` text must never reach the console formatter.
        $symfonyStyle->writeln($this->workflowCommandNeutralizer->report($outputFormat, $content), OutputInterface::OUTPUT_RAW);
    }

    /**
     * `Filesystem::dumpFile()` transparently writes through a pre-existing
     * symlink at its destination — a predictable, documented `--output` path
     * (e.g. `report.sarif`, `gl-sast-report.sarif`) committed as a symlink by
     * a malicious PR would let the audit overwrite an arbitrary file the CI
     * runner can reach. Mirrors the guard already applied to the filesystem
     * attacker/reviewer/advisory caches and the standalone config writer, and
     * walks the audited project below its root as well.
     *
     * @throws UnsafeReportWriteException
     */
    private function assertSafeToWrite(string $path, string $projectPath): void
    {
        if (SymlinkGuard::isThroughSymlinkIntoProject($path, $projectPath)) {
            throw UnsafeReportWriteException::forSymlinkedPath($path);
        }
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
