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
     * @throws UnsupportedOutputFormatException
     */
    #[Override]
    public function write(AuditReport $auditReport, OutputFormat $outputFormat, ?string $outputFile, SymfonyStyle $symfonyStyle): void
    {
        $content = $this->rendererFor($outputFormat)->render($auditReport);

        if (null === $outputFile) {
            $symfonyStyle->writeln($content);

            return;
        }

        $this->filesystem->dumpFile($outputFile, $content);
        $symfonyStyle->success(\sprintf('Report saved to %s', $outputFile));
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
