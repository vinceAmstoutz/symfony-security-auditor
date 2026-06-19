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

use PHPUnit\Event\Application\Finished;
use PHPUnit\Event\Application\FinishedSubscriber;

final readonly class MinimumLineCoverageSubscriber implements FinishedSubscriber
{
    public function __construct(
        private ?string $cloverPath,
        private float $minimumCoverage,
    ) {}

    public function notify(Finished $finished): void
    {
        if (null === $this->cloverPath || !is_file($this->cloverPath)) {
            fwrite(\STDOUT, \sprintf('%s[coverage] gate inactive — run with --coverage-clover to enforce the %.2f%% minimum.%s', \PHP_EOL, $this->minimumCoverage, \PHP_EOL));

            return;
        }

        $report = (string) file_get_contents($this->cloverPath);

        $metricsCount = preg_match_all('/<metrics\b[^>]*>/', $report, $matches);
        if (false === $metricsCount || 0 === $metricsCount || [] === $matches[0]) {
            return;
        }

        $projectMetrics = end($matches[0]);
        $statements = $this->readMetric($projectMetrics, 'statements');
        $covered = $this->readMetric($projectMetrics, 'coveredstatements');
        $percentage = $statements > 0 ? $covered / $statements * 100 : 100.0;

        if ($percentage + 1.0e-9 < $this->minimumCoverage) {
            fwrite(\STDERR, \sprintf('%s[coverage] %.2f%% (%d/%d) is below the required %.2f%%.%s', \PHP_EOL, $percentage, $covered, $statements, $this->minimumCoverage, \PHP_EOL));

            exit(1);
        }

        fwrite(\STDOUT, \sprintf('%s[coverage] %.2f%% (%d/%d) meets the %.2f%% threshold.%s', \PHP_EOL, $percentage, $covered, $statements, $this->minimumCoverage, \PHP_EOL));
    }

    private function readMetric(string $metricsTag, string $attribute): int
    {
        if (1 !== preg_match('/\b'.preg_quote($attribute, '/').'="(\d+)"/', $metricsTag, $match)) {
            return 0;
        }

        return (int) $match[1];
    }
}
