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
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InsufficientTrendReportsException;

/**
 * Builds a trend by diffing each consecutive report pair. Every count comes
 * from the fingerprint-paired buckets of {@see ReportDifferInterface}, so a
 * report total is `new + persisting` of the diff that ends on it — and the
 * very first report, which no diff ends on, gets `fixed + persisting` of the
 * first pair instead.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReportTrendAnalyzer implements ReportTrendAnalyzerInterface
{
    public function __construct(
        private ReportDifferInterface $reportDiffer,
    ) {}

    #[Override]
    public function analyze(array $reportPaths): ReportTrend
    {
        if (\count($reportPaths) < 2) {
            throw InsufficientTrendReportsException::forCount(\count($reportPaths));
        }

        $points = [];
        foreach (\array_slice($reportPaths, 1) as $index => $reportPath) {
            $reportDiff = $this->reportDiffer->diff($reportPaths[$index], $reportPath);

            if (0 === $index) {
                $points[] = new TrendPoint(
                    $reportPaths[0],
                    \count($reportDiff->fixedFindings) + \count($reportDiff->persistingFindings),
                    null,
                    null,
                );
            }

            $points[] = new TrendPoint(
                $reportPath,
                \count($reportDiff->newFindings) + \count($reportDiff->persistingFindings),
                \count($reportDiff->newFindings),
                \count($reportDiff->fixedFindings),
            );
        }

        return new ReportTrend($points);
    }
}
