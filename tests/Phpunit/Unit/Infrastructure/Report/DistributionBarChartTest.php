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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Report;

use Override;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ChartBar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\DistributionBarChart;

final class DistributionBarChartTest extends TestCase
{
    private DistributionBarChart $distributionBarChart;

    #[Override]
    protected function setUp(): void
    {
        $this->distributionBarChart = new DistributionBarChart();
    }

    public function test_it_renders_nothing_without_bars(): void
    {
        self::assertSame('', $this->distributionBarChart->render('Findings by severity', []));
    }

    public function test_it_labels_the_chart_for_assistive_technology(): void
    {
        $output = $this->distributionBarChart->render('Findings by severity', [new ChartBar('High', 1, 'high')]);

        self::assertStringContainsString('role="img" aria-label="Findings by severity"', $output);
    }

    public function test_it_renders_one_labelled_bar_per_entry(): void
    {
        $output = $this->distributionBarChart->render('Findings by severity', [
            new ChartBar('High', 3, 'high'),
            new ChartBar('Low', 1, 'low'),
        ]);

        self::assertSame(2, preg_match_all('/<rect class="bar bar-/', $output));
        self::assertStringContainsString('>High</text>', $output);
        self::assertStringContainsString('>Low</text>', $output);
    }

    public function test_the_longest_bar_spans_the_full_plot_width(): void
    {
        $output = $this->distributionBarChart->render('Findings by severity', [new ChartBar('High', 3, 'high')]);

        self::assertStringContainsString('width="290.0"', $output);
    }

    public function test_bar_width_is_proportional_to_the_largest_count(): void
    {
        $output = $this->distributionBarChart->render('Findings by severity', [
            new ChartBar('High', 4, 'high'),
            new ChartBar('Low', 1, 'low'),
        ]);

        self::assertStringContainsString('width="72.5"', $output);
    }

    public function test_each_bar_carries_its_severity_modifier_class(): void
    {
        $output = $this->distributionBarChart->render('Findings by severity', [new ChartBar('Critical', 1, 'critical')]);

        self::assertStringContainsString('class="bar bar-critical"', $output);
    }

    public function test_it_prints_the_count_next_to_each_bar(): void
    {
        $output = $this->distributionBarChart->render('Findings by severity', [new ChartBar('High', 7, 'high')]);

        self::assertStringContainsString('<text class="bar-count" x="548.0" y="16">7</text>', $output);
    }

    public function test_chart_height_grows_with_the_number_of_bars(): void
    {
        $output = $this->distributionBarChart->render('Findings by type', [
            new ChartBar('sql_injection', 1, 'type'),
            new ChartBar('twig_injection', 1, 'type'),
        ]);

        self::assertStringContainsString('viewBox="0 0 600 48"', $output);
    }

    public function test_each_bar_sits_centred_inside_its_row(): void
    {
        $output = $this->distributionBarChart->render('Findings by type', [
            new ChartBar('first', 1, 'type'),
            new ChartBar('second', 1, 'type'),
        ]);

        self::assertStringContainsString('x="250" y="5" width="290.0" height="14"', $output);
        self::assertStringContainsString('x="250" y="29" width="290.0" height="14"', $output);
    }

    public function test_rows_are_stacked_one_below_the_other(): void
    {
        $output = $this->distributionBarChart->render('Findings by type', [
            new ChartBar('first', 1, 'type'),
            new ChartBar('second', 1, 'type'),
        ]);

        self::assertStringContainsString('y="16">first</text>', $output);
        self::assertStringContainsString('y="40">second</text>', $output);
    }

    public function test_it_escapes_markup_in_a_bar_label(): void
    {
        $output = $this->distributionBarChart->render('Findings by type', [new ChartBar('<script>alert(1)</script>', 1, 'type')]);

        self::assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $output);
        self::assertStringNotContainsString('<script>', $output);
    }

    public function test_it_escapes_markup_in_the_aria_label(): void
    {
        $output = $this->distributionBarChart->render('"><script>alert(1)</script>', [new ChartBar('High', 1, 'high')]);

        self::assertStringNotContainsString('<script>', $output);
        self::assertStringContainsString('&quot;&gt;', $output);
    }

    public function test_it_escapes_markup_in_a_css_modifier(): void
    {
        $output = $this->distributionBarChart->render('Findings by type', [new ChartBar('High', 1, '"><script>')]);

        self::assertStringNotContainsString('<script>', $output);
    }
}
