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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\TemplateLoader;

/**
 * Renders a {@see ReportTrend} as a self-contained HTML page: an SVG line
 * chart of finding totals over the report series plus a table of per-report
 * new/fixed deltas.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class TrendHtmlRenderer implements TrendHtmlRendererInterface
{
    private const int PLOT_LEFT_X = 40;

    private const int PLOT_RIGHT_X = 584;

    private const int PLOT_TOP_Y = 16;

    private const int BASELINE_Y = 168;

    private const int MARKER_RADIUS = 4;

    private const int VALUE_LABEL_OFFSET_Y = 10;

    private const int TICK_LABEL_Y = 186;

    public function __construct(
        private TemplateLoader $templateLoader = new TemplateLoader(),
    ) {}

    #[Override]
    public function render(ReportTrend $reportTrend): string
    {
        $points = $reportTrend->points;
        $first = $points[0];
        $last = $points[\count($points) - 1];

        return strtr($this->templateLoader->load('trend.html'), [
            '{{packageName}}' => $this->escape(ReportPackage::NAME),
            '{{packageUrl}}' => $this->escape(ReportPackage::HOMEPAGE_URL),
            '{{reportCount}}' => \count($points),
            '{{summary}}' => $this->escape(\sprintf(
                '%d → %d findings (%+d) across %d reports.',
                $first->totalCount,
                $last->totalCount,
                $last->totalCount - $first->totalCount,
                \count($points),
            )),
            '{{chart}}' => $this->chart($points),
            '{{rows}}' => $this->rows($points),
        ]);
    }

    /**
     * @param list<TrendPoint> $points
     */
    private function rows(array $points): string
    {
        $rows = [];
        foreach ($points as $index => $trendPoint) {
            $rows[] = \sprintf(
                '<tr><td>%d</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>',
                $index + 1,
                $this->escape($trendPoint->report),
                $trendPoint->totalCount,
                $trendPoint->newCount ?? '—',
                $trendPoint->fixedCount ?? '—',
            );
        }

        return implode("\n", $rows);
    }

    /**
     * @param list<TrendPoint> $points
     */
    private function chart(array $points): string
    {
        $maxTotal = max(1, ...array_map(static fn (TrendPoint $trendPoint): int => $trendPoint->totalCount, $points));

        $elements = [
            \sprintf('<line class="grid" x1="%d" y1="%d" x2="%d" y2="%d" />', self::PLOT_LEFT_X, self::PLOT_TOP_Y, self::PLOT_RIGHT_X, self::PLOT_TOP_Y),
            \sprintf('<line class="axis" x1="%d" y1="%d" x2="%d" y2="%d" />', self::PLOT_LEFT_X, self::BASELINE_Y, self::PLOT_RIGHT_X, self::BASELINE_Y),
            \sprintf('<text class="tick" x="%d" y="%d" text-anchor="end">%d</text>', self::PLOT_LEFT_X - 8, self::PLOT_TOP_Y + 4, $maxTotal),
            \sprintf('<text class="tick" x="%d" y="%d" text-anchor="end">0</text>', self::PLOT_LEFT_X - 8, self::BASELINE_Y + 4),
        ];

        $coordinates = $this->coordinates($points, $maxTotal);

        if (\count($coordinates) > 1) {
            $elements[] = $this->areaPath($coordinates);
            $elements[] = $this->polyline($coordinates);
        }

        foreach ($points as $index => $trendPoint) {
            [$x, $y] = $coordinates[$index];
            $elements[] = \sprintf(
                '<circle class="marker" cx="%s" cy="%s" r="%d"><title>%s — %d findings</title></circle>',
                $this->formatCoordinate($x),
                $this->formatCoordinate($y),
                self::MARKER_RADIUS,
                $this->escape($trendPoint->report),
                $trendPoint->totalCount,
            );
            $elements[] = \sprintf('<text class="tick" x="%s" y="%d" text-anchor="middle">%d</text>', $this->formatCoordinate($x), self::TICK_LABEL_Y, $index + 1);
        }

        foreach (array_unique([0, \count($points) - 1]) as $labelledIndex) {
            [$x, $y] = $coordinates[$labelledIndex];
            $elements[] = \sprintf(
                '<text class="value" x="%s" y="%s" text-anchor="middle">%d</text>',
                $this->formatCoordinate($x),
                $this->formatCoordinate($y - self::VALUE_LABEL_OFFSET_Y),
                $points[$labelledIndex]->totalCount,
            );
        }

        return \sprintf(
            '<svg viewBox="0 0 600 200" role="img" aria-label="Finding totals across %d reports">%s</svg>',
            \count($points),
            implode('', $elements),
        );
    }

    /**
     * @param list<TrendPoint> $points
     *
     * @return list<array{float, float}>
     */
    private function coordinates(array $points, int $maxTotal): array
    {
        $coordinates = [];
        foreach ($points as $index => $trendPoint) {
            $coordinates[] = [
                $this->x($index, \count($points)),
                $this->y($trendPoint->totalCount, $maxTotal),
            ];
        }

        return $coordinates;
    }

    /**
     * @param list<array{float, float}> $coordinates
     */
    private function areaPath(array $coordinates): string
    {
        $segments = array_map(
            fn (array $coordinate): string => \sprintf('L %s,%s', $this->formatCoordinate($coordinate[0]), $this->formatCoordinate($coordinate[1])),
            $coordinates,
        );

        return \sprintf(
            '<path class="area" d="M %s,%d %s L %s,%d Z" />',
            $this->formatCoordinate($coordinates[0][0]),
            self::BASELINE_Y,
            implode(' ', $segments),
            $this->formatCoordinate($coordinates[\count($coordinates) - 1][0]),
            self::BASELINE_Y,
        );
    }

    /**
     * @param list<array{float, float}> $coordinates
     */
    private function polyline(array $coordinates): string
    {
        $pairs = array_map(
            fn (array $coordinate): string => \sprintf('%s,%s', $this->formatCoordinate($coordinate[0]), $this->formatCoordinate($coordinate[1])),
            $coordinates,
        );

        return \sprintf('<polyline class="line" points="%s" />', implode(' ', $pairs));
    }

    private function x(int $index, int $pointCount): float
    {
        if (1 === $pointCount) {
            return (self::PLOT_LEFT_X + self::PLOT_RIGHT_X) / 2;
        }

        return self::PLOT_LEFT_X + $index * ((self::PLOT_RIGHT_X - self::PLOT_LEFT_X) / ($pointCount - 1));
    }

    private function y(int $totalCount, int $maxTotal): float
    {
        return self::BASELINE_Y - $totalCount / $maxTotal * (self::BASELINE_Y - self::PLOT_TOP_Y);
    }

    private function formatCoordinate(float $value): string
    {
        return \sprintf('%.1F', $value);
    }

    /**
     * Report paths are echoed into markup, so — exactly as the HTML report
     * renderer does — invalid UTF-8 is repaired, bidi overrides are stripped,
     * and the result is HTML-escaped so a crafted path cannot inject markup
     * or visually reorder the rendered text.
     */
    private function escape(string $value): string
    {
        $scrubbed = mb_scrub($value, 'UTF-8');
        $withoutBidiOverrides = preg_replace('/[\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '', $scrubbed) ?? $scrubbed;

        return htmlspecialchars($withoutBidiOverrides, \ENT_QUOTES | \ENT_SUBSTITUTE, 'UTF-8');
    }
}
