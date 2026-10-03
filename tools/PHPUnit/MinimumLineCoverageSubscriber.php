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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tooling\PHPUnit;

use Override;
use PHPUnit\Event\Application\Finished;
use PHPUnit\Event\Application\FinishedSubscriber;

final readonly class MinimumLineCoverageSubscriber implements FinishedSubscriber
{
    private const int MAXIMUM_REPORTED_LINES = 40;

    public function __construct(
        private ?string $cloverPath,
        private float $minimumCoverage,
    ) {}

    #[Override]
    public function notify(Finished $finished): void
    {
        if (null === $this->cloverPath || !is_file($this->cloverPath)) {
            fwrite(\STDOUT, \sprintf('%s[coverage] gate inactive — run with --coverage-clover to enforce the %.2f%% minimum.%s', \PHP_EOL, $this->minimumCoverage, \PHP_EOL));

            return;
        }

        $report = (string) file_get_contents($this->cloverPath);

        if (1 !== preg_match('/.*(<metrics\b[^>]*>)/s', $report, $matches)) {
            return;
        }

        $projectMetrics = $matches[1];
        $statements = $this->readMetric($projectMetrics, 'statements');
        $covered = $this->readMetric($projectMetrics, 'coveredstatements');
        $percentage = $statements > 0 ? $covered / $statements * 100 : 100.0;

        if ($percentage + 1.0e-9 < $this->minimumCoverage) {
            fwrite(\STDERR, \sprintf('%s[coverage] %.2f%% (%d/%d) is below the required %.2f%%.%s', \PHP_EOL, $percentage, $covered, $statements, $this->minimumCoverage, \PHP_EOL));
            fwrite(\STDERR, $this->uncoveredDetail($report));

            exit(1);
        }

        fwrite(\STDOUT, \sprintf('%s[coverage] %.2f%% (%d/%d) meets the %.2f%% threshold.%s', \PHP_EOL, $percentage, $covered, $statements, $this->minimumCoverage, \PHP_EOL));
    }

    /**
     * A percentage says a gate failed; the lines say why. Long lists are
     * truncated so one badly-covered file cannot bury the rest of the log.
     */
    private function uncoveredDetail(string $report): string
    {
        $uncovered = UncoveredLines::in($report);
        if ([] === $uncovered) {
            return \sprintf('[coverage] the Clover report lists no uncovered statement — the shortfall is outside line coverage.%s', \PHP_EOL);
        }

        $shown = \array_slice($uncovered, 0, self::MAXIMUM_REPORTED_LINES);
        $detail = \sprintf('[coverage] never executed:%s', \PHP_EOL);
        foreach ($shown as $line) {
            $detail .= \sprintf('  %s%s', $line, \PHP_EOL);
        }

        return $detail.$this->truncationNotice(\count($uncovered));
    }

    private function truncationNotice(int $total): string
    {
        return $total > self::MAXIMUM_REPORTED_LINES
            ? \sprintf('  … and %d more%s', $total - self::MAXIMUM_REPORTED_LINES, \PHP_EOL)
            : '';
    }

    private function readMetric(string $metricsTag, string $attribute): int
    {
        if (1 !== preg_match('/\b'.preg_quote($attribute, '/').'="(\d+)"/', $metricsTag, $match)) {
            return 0;
        }

        return (int) $match[1];
    }
}
