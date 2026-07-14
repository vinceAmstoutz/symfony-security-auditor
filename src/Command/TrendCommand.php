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

use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InsufficientTrendReportsException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;

#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
/** @internal not part of the BC promise — the command *name* (`audit:trend`) is public, but the PHP class itself is for internal use only. */
final readonly class TrendCommand
{
    public const string NAME = 'audit:trend';

    public const string DESCRIPTION = 'Track how finding counts evolve across two or more JSON audit reports ordered oldest to newest';

    public function __construct(
        private ReportTrendAnalyzerInterface $reportTrendAnalyzer,
        private TrendPresenterInterface $trendPresenter,
    ) {}

    /**
     * @param list<string> $reports
     */
    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[Argument(description: 'Paths to two or more JSON reports, ordered oldest to newest.', name: 'reports')] array $reports,
        #[Option(description: 'Output format: console, json or html', name: 'format', shortcut: 'f')] TrendOutputFormat $trendOutputFormat = TrendOutputFormat::Console,
    ): int {
        try {
            $reportTrend = $this->reportTrendAnalyzer->analyze($reports);
        } catch (InsufficientTrendReportsException|ReportFileNotReadableException|MalformedReportFileException $exception) {
            $this->errorStyle($symfonyStyle, $trendOutputFormat)->error($exception->getMessage());

            return ExitCode::Failure->value;
        }

        $this->trendPresenter->present($symfonyStyle, $reportTrend, $trendOutputFormat);

        return ExitCode::Success->value;
    }

    /**
     * Human-facing error messages move to stderr when stdout carries a
     * machine-readable document, so `--format=json > trend.json` and
     * `--format=html > trend.html` receive the document alone — mirrors
     * `DiffCommand::errorStyle()`.
     */
    private function errorStyle(SymfonyStyle $symfonyStyle, TrendOutputFormat $trendOutputFormat): SymfonyStyle
    {
        return TrendOutputFormat::Console !== $trendOutputFormat ? $symfonyStyle->getErrorStyle() : $symfonyStyle;
    }
}
