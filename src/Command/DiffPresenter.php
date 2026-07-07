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

use JsonException;
use Override;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Renders a {@see ReportDiff} as human-readable console sections or as a raw
 * JSON document.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class DiffPresenter implements DiffPresenterInterface
{
    /**
     * @throws JsonException
     */
    #[Override]
    public function present(SymfonyStyle $symfonyStyle, ReportDiff $reportDiff, DiffOutputFormat $diffOutputFormat): void
    {
        if (DiffOutputFormat::Json === $diffOutputFormat) {
            // OUTPUT_RAW keeps markup-lookalike text in finding titles out of the console formatter.
            $symfonyStyle->writeln(json_encode($reportDiff->toArray(), \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR), OutputInterface::OUTPUT_RAW);

            return;
        }

        $this->section($symfonyStyle, 'New', $reportDiff->newFindings);
        $this->section($symfonyStyle, 'Fixed', $reportDiff->fixedFindings);
        $this->section($symfonyStyle, 'Persisting', $reportDiff->persistingFindings);

        $symfonyStyle->writeln(\sprintf(
            'Summary: %d new, %d fixed, %d persisting.',
            \count($reportDiff->newFindings),
            \count($reportDiff->fixedFindings),
            \count($reportDiff->persistingFindings),
        ));
    }

    /**
     * @param list<DiffFinding> $findings
     */
    private function section(SymfonyStyle $symfonyStyle, string $title, array $findings): void
    {
        $symfonyStyle->section(\sprintf('%s (%d)', $title, \count($findings)));

        if ([] !== $findings) {
            foreach ($findings as $finding) {
                $symfonyStyle->writeln(\sprintf(
                    '  [%s] %s — %s (%s)',
                    strtoupper($finding->severity),
                    $finding->type,
                    $finding->title,
                    $finding->file,
                ), OutputInterface::OUTPUT_RAW);
            }

            return;
        }

        $symfonyStyle->writeln('  (none)');
    }
}
