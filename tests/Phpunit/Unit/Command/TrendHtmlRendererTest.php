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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportTrend;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendHtmlRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendPoint;

final class TrendHtmlRendererTest extends TestCase
{
    private TrendHtmlRenderer $trendHtmlRenderer;

    #[Override]
    protected function setUp(): void
    {
        $this->trendHtmlRenderer = new TrendHtmlRenderer();
    }

    public function test_it_renders_a_complete_html_document(): void
    {
        $html = $this->trendHtmlRenderer->render($this->twoPointTrend());

        self::assertStringStartsWith('<!doctype html>', $html);
        self::assertStringEndsWith('</html>', $html);
    }

    public function test_the_page_declares_the_package_as_its_generator(): void
    {
        self::assertStringContainsString(
            \sprintf('<meta name="generator" content="%s" />', ReportPackage::NAME),
            $this->trendHtmlRenderer->render($this->twoPointTrend()),
        );
    }

    public function test_the_footer_links_to_the_project_homepage(): void
    {
        self::assertStringContainsString(
            \sprintf('<a href="%s">%s</a>', ReportPackage::HOMEPAGE_URL, ReportPackage::NAME),
            $this->trendHtmlRenderer->render($this->twoPointTrend()),
        );
    }

    public function test_a_gridline_marks_the_highest_total_at_the_top_of_the_plot(): void
    {
        self::assertStringContainsString(
            '<line class="grid" x1="40" y1="16" x2="584" y2="16" />',
            $this->trendHtmlRenderer->render($this->twoPointTrend()),
        );
    }

    public function test_the_title_carries_the_report_count(): void
    {
        self::assertStringContainsString(
            '<title>Security Findings Trend — 2 reports</title>',
            $this->trendHtmlRenderer->render($this->twoPointTrend()),
        );
    }

    public function test_the_summary_states_first_and_last_totals_with_the_signed_delta(): void
    {
        self::assertStringContainsString(
            '2 → 3 findings (+1) across 2 reports.',
            $this->trendHtmlRenderer->render($this->twoPointTrend()),
        );
    }

    public function test_the_first_report_row_shows_dashes_instead_of_new_and_fixed_counts(): void
    {
        self::assertStringContainsString(
            '<tr><td>1</td><td>previous.json</td><td>2</td><td>—</td><td>—</td></tr>',
            $this->trendHtmlRenderer->render($this->twoPointTrend()),
        );
    }

    public function test_a_later_report_row_shows_its_new_and_fixed_counts(): void
    {
        self::assertStringContainsString(
            '<tr><td>2</td><td>current.json</td><td>3</td><td>2</td><td>1</td></tr>',
            $this->trendHtmlRenderer->render($this->twoPointTrend()),
        );
    }

    public function test_the_chart_polyline_spans_the_plot_area_scaled_to_the_highest_total(): void
    {
        self::assertStringContainsString(
            '<polyline class="line" points="40.0,66.7 584.0,16.0" />',
            $this->trendHtmlRenderer->render($this->twoPointTrend()),
        );
    }

    public function test_the_chart_area_path_closes_onto_the_baseline(): void
    {
        self::assertStringContainsString(
            '<path class="area" d="M 40.0,168 L 40.0,66.7 L 584.0,16.0 L 584.0,168 Z" />',
            $this->trendHtmlRenderer->render($this->twoPointTrend()),
        );
    }

    public function test_every_point_gets_a_marker_with_a_native_tooltip(): void
    {
        self::assertStringContainsString(
            '<circle class="marker" cx="584.0" cy="16.0" r="4"><title>current.json — 3 findings</title></circle>',
            $this->trendHtmlRenderer->render($this->twoPointTrend()),
        );
    }

    public function test_the_y_axis_is_labelled_from_zero_to_the_highest_total(): void
    {
        $html = $this->trendHtmlRenderer->render($this->twoPointTrend());

        self::assertStringContainsString('<text class="tick" x="32" y="20" text-anchor="end">3</text>', $html);
        self::assertStringContainsString('<text class="tick" x="32" y="172" text-anchor="end">0</text>', $html);
    }

    public function test_each_point_is_numbered_below_the_baseline(): void
    {
        $html = $this->trendHtmlRenderer->render($this->twoPointTrend());

        self::assertStringContainsString('<text class="tick" x="40.0" y="186" text-anchor="middle">1</text>', $html);
        self::assertStringContainsString('<text class="tick" x="584.0" y="186" text-anchor="middle">2</text>', $html);
    }

    public function test_only_the_first_and_last_points_carry_a_direct_value_label(): void
    {
        $reportTrend = new ReportTrend([
            new TrendPoint('a.json', 2, null, null),
            new TrendPoint('b.json', 4, 2, 0),
            new TrendPoint('c.json', 3, 0, 1),
        ]);

        $html = $this->trendHtmlRenderer->render($reportTrend);

        self::assertSame(2, substr_count($html, 'class="value"'));
        self::assertStringContainsString('<text class="value" x="40.0" y="82.0" text-anchor="middle">2</text>', $html);
        self::assertStringContainsString('<text class="value" x="584.0" y="44.0" text-anchor="middle">3</text>', $html);
    }

    public function test_an_all_zero_trend_draws_every_marker_on_the_baseline(): void
    {
        $reportTrend = new ReportTrend([
            new TrendPoint('a.json', 0, null, null),
            new TrendPoint('b.json', 0, 0, 0),
        ]);

        $html = $this->trendHtmlRenderer->render($reportTrend);

        self::assertSame(2, substr_count($html, 'cy="168.0"'));
        self::assertStringContainsString('<text class="tick" x="32" y="20" text-anchor="end">1</text>', $html);
    }

    public function test_a_single_point_trend_centers_its_marker_and_draws_no_line(): void
    {
        $reportTrend = new ReportTrend([new TrendPoint('only.json', 5, null, null)]);

        $html = $this->trendHtmlRenderer->render($reportTrend);

        self::assertStringContainsString('cx="312.0"', $html);
        self::assertStringNotContainsString('<polyline', $html);
        self::assertStringNotContainsString('<path class="area"', $html);
        self::assertSame(1, substr_count($html, 'class="value"'));
    }

    public function test_markup_in_a_report_path_is_escaped(): void
    {
        $reportTrend = new ReportTrend([
            new TrendPoint('<script>alert(1)</script>.json', 1, null, null),
            new TrendPoint('current.json', 1, 0, 0),
        ]);

        $html = $this->trendHtmlRenderer->render($reportTrend);

        self::assertStringNotContainsString('<script>', $html);
        self::assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;.json', $html);
    }

    public function test_quotes_in_a_report_path_are_escaped_for_attribute_contexts(): void
    {
        $reportTrend = new ReportTrend([
            new TrendPoint('a"b\'.json', 1, null, null),
            new TrendPoint('current.json', 1, 0, 0),
        ]);

        $html = $this->trendHtmlRenderer->render($reportTrend);

        self::assertStringContainsString('a&quot;b&#039;.json', $html);
        self::assertStringNotContainsString('a"b\'.json', $html);
    }

    public function test_bidi_override_characters_in_a_report_path_are_stripped(): void
    {
        $reportTrend = new ReportTrend([
            new TrendPoint("repo\u{202E}rt.json", 1, null, null),
            new TrendPoint('current.json', 1, 0, 0),
        ]);

        $html = $this->trendHtmlRenderer->render($reportTrend);

        self::assertStringNotContainsString("\u{202E}", $html);
        self::assertStringContainsString('report.json', $html);
    }

    public function test_invalid_utf8_in_a_report_path_is_scrubbed_instead_of_defeating_the_escaping(): void
    {
        $reportTrend = new ReportTrend([
            new TrendPoint("bad\xC3\x28\u{202E}.json", 1, null, null),
            new TrendPoint('current.json', 1, 0, 0),
        ]);

        $html = $this->trendHtmlRenderer->render($reportTrend);

        self::assertStringNotContainsString("\u{202E}", $html);
    }

    private function twoPointTrend(): ReportTrend
    {
        return new ReportTrend([
            new TrendPoint('previous.json', 2, null, null),
            new TrendPoint('current.json', 3, 2, 1),
        ]);
    }
}
