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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\StringInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportTrend;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendOutputFormat;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendPoint;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendPresenter;

final class TrendPresenterTest extends TestCase
{
    private TrendPresenter $trendPresenter;

    #[Override]
    protected function setUp(): void
    {
        $this->trendPresenter = new TrendPresenter();
    }

    public function test_it_prints_the_section_header_with_the_report_count(): void
    {
        self::assertStringContainsString('Trend (2 reports)', $this->presentToConsole($this->twoPointTrend()));
    }

    public function test_the_first_report_line_shows_the_total_without_new_or_fixed_counts(): void
    {
        self::assertStringContainsString('1. previous.json — 2 findings'."\n", $this->presentToConsole($this->twoPointTrend()));
    }

    public function test_a_later_report_line_shows_new_and_fixed_counts(): void
    {
        self::assertStringContainsString('2. current.json — 3 findings (2 new, 1 fixed)', $this->presentToConsole($this->twoPointTrend()));
    }

    public function test_the_summary_line_shows_first_and_last_totals_with_the_signed_delta(): void
    {
        self::assertStringContainsString('Summary: 2 → 3 findings (+1) across 2 reports.', $this->presentToConsole($this->twoPointTrend()));
    }

    public function test_the_summary_delta_is_signed_negative_when_findings_decrease(): void
    {
        $reportTrend = new ReportTrend([
            new TrendPoint('previous.json', 3, null, null),
            new TrendPoint('current.json', 1, 0, 2),
        ]);

        self::assertStringContainsString('Summary: 3 → 1 findings (-2) across 2 reports.', $this->presentToConsole($reportTrend));
    }

    public function test_control_characters_in_a_report_path_are_stripped_from_console_output(): void
    {
        $reportTrend = new ReportTrend([
            new TrendPoint("previous\e[31m.json", 1, null, null),
            new TrendPoint("current\n.json", 1, 0, 0),
        ]);

        $display = $this->presentToConsole($reportTrend);

        self::assertStringNotContainsString("\e[31m", $display);
        self::assertStringContainsString('current .json', $display);
    }

    public function test_json_format_outputs_the_trend_points_as_structured_json(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->trendPresenter->present($symfonyStyle, $this->twoPointTrend(), TrendOutputFormat::Json);

        self::assertSame(
            [
                'points' => [
                    ['report' => 'previous.json', 'total' => 2, 'new' => null, 'fixed' => null],
                    ['report' => 'current.json', 'total' => 3, 'new' => 2, 'fixed' => 1],
                ],
            ],
            json_decode($bufferedOutput->fetch(), true),
        );
    }

    public function test_html_format_outputs_a_self_contained_html_document_listing_every_report(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->trendPresenter->present($symfonyStyle, $this->twoPointTrend(), TrendOutputFormat::Html);

        $display = $bufferedOutput->fetch();
        self::assertStringStartsWith('<!doctype html>', $display);
        self::assertStringEndsWith('</html>'."\n", $display);
        self::assertStringContainsString('previous.json', $display);
        self::assertStringContainsString('current.json', $display);
    }

    private function twoPointTrend(): ReportTrend
    {
        return new ReportTrend([
            new TrendPoint('previous.json', 2, null, null),
            new TrendPoint('current.json', 3, 2, 1),
        ]);
    }

    private function presentToConsole(ReportTrend $reportTrend): string
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->trendPresenter->present($symfonyStyle, $reportTrend, TrendOutputFormat::Console);

        return $bufferedOutput->fetch();
    }
}
