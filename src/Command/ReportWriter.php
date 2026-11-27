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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\PrivateFileWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\SymlinkGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\BaselineSuppressingReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportWriteFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeReportWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsupportedOutputFormatException;

/** @internal not part of the BC promise, see docs/versioning.md */
final readonly class ReportWriter implements ReportWriterInterface
{
    private const string TEMPORARY_REPORT_PREFIX = 'symfony-security-auditor-report-';

    /** @var array<string, ReportRendererInterface> */
    private array $renderers;

    /** @param iterable<ReportRendererInterface> $renderers */
    public function __construct(
        iterable $renderers,
        private Filesystem $filesystem,
        private WorkflowCommandNeutralizerInterface $workflowCommandNeutralizer = new WorkflowCommandNeutralizer(false),
        private ?string $temporaryDirectory = null,
        private StandardOutputInterface $standardOutput = new StandardOutput(),
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

        if (null === $outputFile && OutputFormat::Html === $outputFormat && $this->standardOutput->isTerminal()) {
            $this->linkFromATemporaryFile($symfonyStyle, $content);

            return;
        }

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

    private function linkFromATemporaryFile(SymfonyStyle $symfonyStyle, string $content): void
    {
        try {
            $path = $this->filesystem->tempnam($this->temporaryDirectory ?? sys_get_temp_dir(), self::TEMPORARY_REPORT_PREFIX, '.html');
            PrivateFileWriter::write($this->filesystem, $path, $content);
        } catch (IOException) {
            $this->keepOnConsole($symfonyStyle, OutputFormat::Html, $content);

            return;
        }

        $url = FileUrl::of($path);

        $symfonyStyle->success(\sprintf('Report saved to %s', $path));
        $symfonyStyle->writeln(\sprintf(' Open it in your browser: <href=%1$s>%1$s</>', $url));
    }

    /**
     * Prints the report without `--output` or when its file cannot be written.
     */
    private function keepOnConsole(SymfonyStyle $symfonyStyle, OutputFormat $outputFormat, string $content): void
    {
        // OUTPUT_RAW keeps a finding's own `<...>` text out of the console formatter.
        $symfonyStyle->writeln($this->workflowCommandNeutralizer->report($outputFormat, $content), OutputInterface::OUTPUT_RAW);
    }

    /**
     * Refuses a path through a symlink below the working directory or the
     * project root, which `dumpFile()` would follow to any file the runner can
     * reach.
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
