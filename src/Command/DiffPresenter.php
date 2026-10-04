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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\WorkflowCommandText;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\TerminalTextSanitizer;

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
            $symfonyStyle->writeln(WorkflowCommandText::inJson(json_encode($reportDiff->toArray(), \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR)), OutputInterface::OUTPUT_RAW);

            return;
        }

        $this->section($symfonyStyle, 'New', $reportDiff->newFindings);
        $this->section($symfonyStyle, 'Fixed', $reportDiff->fixedFindings);
        $this->unverifiedSection($symfonyStyle, $reportDiff->unverifiedFindings);
        $this->section($symfonyStyle, 'Persisting', $reportDiff->persistingFindings);

        $symfonyStyle->writeln(\sprintf(
            'Summary: %d new, %d fixed, %s%d persisting.',
            \count($reportDiff->newFindings),
            \count($reportDiff->fixedFindings),
            [] === $reportDiff->unverifiedFindings ? '' : \sprintf('%d unverified, ', \count($reportDiff->unverifiedFindings)),
            \count($reportDiff->persistingFindings),
        ));
    }

    /**
     * Shown only when the current report could not vouch for a file, so a
     * comparison of two complete reports reads exactly as it always did.
     *
     * @param list<DiffFinding> $findings
     */
    private function unverifiedSection(SymfonyStyle $symfonyStyle, array $findings): void
    {
        if ([] === $findings) {
            return;
        }

        $this->section($symfonyStyle, 'Unverified', $findings);
        $symfonyStyle->writeln('  (absent from the current report, whose run did not fully analyze their files, or never looked at them — not shown as fixed)');
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
                    strtoupper($this->sanitize($finding->severity)),
                    $this->sanitize($finding->type),
                    $this->sanitize($finding->title),
                    $this->sanitize($finding->file),
                ), OutputInterface::OUTPUT_RAW);
            }

            return;
        }

        $symfonyStyle->writeln('  (none)');
    }

    /**
     * The diff reads its `DiffFinding` fields from two untrusted JSON report
     * files whose titles/paths ultimately come from LLM-produced or
     * project-derived text. `OUTPUT_RAW` bypasses Symfony's formatter but not
     * the terminal itself, so — exactly as the console audit-report renderer
     * does — each single-line field is collapsed and stripped of
     * control/ANSI/bidi characters so a crafted value cannot forge a fake
     * `[SEVERITY]` finding line or spoof the terminal, and a legacy
     * `##[command]` in it is defused for a CI runner's log.
     */
    private function sanitize(string $value): string
    {
        return WorkflowCommandText::inLine(TerminalTextSanitizer::collapseToSingleLine(mb_scrub($value, 'UTF-8')));
    }
}
