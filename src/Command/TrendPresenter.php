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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\TerminalTextSanitizer;

/**
 * Renders a {@see ReportTrend} as a human-readable console timeline or as a
 * raw JSON document.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class TrendPresenter implements TrendPresenterInterface
{
    /**
     * @throws JsonException
     */
    #[Override]
    public function present(SymfonyStyle $symfonyStyle, ReportTrend $reportTrend, TrendOutputFormat $trendOutputFormat): void
    {
        if (TrendOutputFormat::Json === $trendOutputFormat) {
            // OUTPUT_RAW keeps markup-lookalike text in report paths out of the console formatter.
            $symfonyStyle->writeln(json_encode($reportTrend->toArray(), \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR), OutputInterface::OUTPUT_RAW);

            return;
        }

        $points = $reportTrend->points;
        $symfonyStyle->section(\sprintf('Trend (%d reports)', \count($points)));

        foreach ($points as $index => $trendPoint) {
            $symfonyStyle->writeln($this->pointLine($index + 1, $trendPoint), OutputInterface::OUTPUT_RAW);
        }

        $first = $points[0];
        $last = $points[\count($points) - 1];
        $symfonyStyle->writeln(\sprintf(
            'Summary: %d → %d findings (%+d) across %d reports.',
            $first->totalCount,
            $last->totalCount,
            $last->totalCount - $first->totalCount,
            \count($points),
        ));
    }

    private function pointLine(int $position, TrendPoint $trendPoint): string
    {
        $line = \sprintf('  %d. %s — %d findings', $position, $this->sanitize($trendPoint->report), $trendPoint->totalCount);

        if (null === $trendPoint->newCount || null === $trendPoint->fixedCount) {
            return $line;
        }

        return \sprintf('%s (%d new, %d fixed)', $line, $trendPoint->newCount, $trendPoint->fixedCount);
    }

    /**
     * Report paths are echoed back to the terminal verbatim, so — exactly as
     * the diff presenter does — each one is collapsed to a single line and
     * stripped of control/ANSI/bidi characters so a crafted value cannot
     * forge a fake trend line or spoof the terminal.
     */
    private function sanitize(string $value): string
    {
        return TerminalTextSanitizer::collapseToSingleLine(mb_scrub($value, 'UTF-8'));
    }
}
