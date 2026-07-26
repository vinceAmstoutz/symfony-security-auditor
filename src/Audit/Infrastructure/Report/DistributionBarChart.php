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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

/**
 * Renders labelled counts as an inline SVG horizontal bar chart — no external
 * asset, no script, colors driven by the embedding page's stylesheet so the
 * chart follows the reader's light/dark preference.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class DistributionBarChart
{
    private const int CHART_WIDTH = 600;

    private const int ROW_HEIGHT = 24;

    private const int BAR_HEIGHT = 14;

    private const int BAR_LEFT_X = 250;

    private const int BAR_MAX_WIDTH = 290;

    private const int BAR_TOP_OFFSET = 5;

    private const int LABEL_BASELINE_OFFSET = 16;

    private const int COUNT_LABEL_GAP = 8;

    /**
     * @param list<ChartBar> $bars
     */
    public function render(string $ariaLabel, array $bars): string
    {
        if ([] === $bars) {
            return '';
        }

        $maxCount = max(array_map(static fn (ChartBar $chartBar): int => $chartBar->count, $bars));

        $rows = [];
        foreach ($bars as $index => $chartBar) {
            $rows[] = $this->row($chartBar, $index, $maxCount);
        }

        return \sprintf(
            '<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="%s">%s</svg>',
            self::CHART_WIDTH,
            \count($bars) * self::ROW_HEIGHT,
            $this->escape($ariaLabel),
            implode('', $rows),
        );
    }

    private function row(ChartBar $chartBar, int $index, int $maxCount): string
    {
        $rowY = $index * self::ROW_HEIGHT;
        $barWidth = $this->barWidth($chartBar->count, $maxCount);
        $baselineY = $rowY + self::LABEL_BASELINE_OFFSET;

        return \sprintf(
            '<text class="bar-label" x="0" y="%d">%s</text>'
            .'<rect class="bar bar-%s" x="%d" y="%d" width="%s" height="%d" rx="2" />'
            .'<text class="bar-count" x="%s" y="%d">%d</text>',
            $baselineY,
            $this->escape($chartBar->label),
            $this->escape($chartBar->cssModifier),
            self::BAR_LEFT_X,
            $rowY + self::BAR_TOP_OFFSET,
            $this->formatCoordinate($barWidth),
            self::BAR_HEIGHT,
            $this->formatCoordinate(self::BAR_LEFT_X + $barWidth + self::COUNT_LABEL_GAP),
            $baselineY,
            $chartBar->count,
        );
    }

    private function barWidth(int $count, int $maxCount): float
    {
        return $count / $maxCount * self::BAR_MAX_WIDTH;
    }

    private function formatCoordinate(float $value): string
    {
        return \sprintf('%.1F', $value);
    }

    private function escape(string $value): string
    {
        return htmlspecialchars($value, \ENT_QUOTES | \ENT_SUBSTITUTE, 'UTF-8');
    }
}
