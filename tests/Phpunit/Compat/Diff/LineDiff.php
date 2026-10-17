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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Diff;

/**
 * The lines one text lost and gained against another, by longest common
 * subsequence: a line the replay lost is `-line`, one it gained `+line`.
 */
final readonly class LineDiff
{
    /**
     * @param list<string> $recorded
     * @param list<string> $replayed
     *
     * @return list<Difference>
     */
    public static function between(string $path, array $recorded, array $replayed): array
    {
        $differences = [];
        foreach (self::alignment($recorded, $replayed) as [$recordedIndex, $replayedIndex]) {
            if (null === $replayedIndex) {
                $differences[] = Difference::ofLine($path, \sprintf('-%s', $recorded[$recordedIndex ?? 0]));
            }

            if (null === $recordedIndex) {
                $differences[] = Difference::ofLine($path, \sprintf('+%s', $replayed[$replayedIndex ?? 0]));
            }
        }

        return $differences;
    }

    /**
     * Walks both sequences along their longest common subsequence: a pair of
     * indexes for an item both hold, the recorded index alone for an item the
     * replay lost, the replayed index alone for one it gained.
     *
     * @param list<string> $recorded
     * @param list<string> $replayed
     *
     * @return list<array{int|null, int|null}>
     */
    public static function alignment(array $recorded, array $replayed): array
    {
        $common = self::commonLengths($recorded, $replayed);
        $alignment = [];
        $left = 0;
        $right = 0;

        while ($left < \count($recorded) || $right < \count($replayed)) {
            $step = self::step($recorded, $replayed, $common, [$left, $right]);
            $alignment[] = $step;
            $left += null === $step[0] ? 0 : 1;
            $right += null === $step[1] ? 0 : 1;
        }

        return $alignment;
    }

    /**
     * @param list<string>                $recorded
     * @param list<string>                $replayed
     * @param array<int, array<int, int>> $common
     * @param array{int, int}             $position
     *
     * @return array{int|null, int|null}
     */
    private static function step(array $recorded, array $replayed, array $common, array $position): array
    {
        [$left, $right] = $position;

        if ($left < \count($recorded) && $right < \count($replayed) && $recorded[$left] === $replayed[$right]) {
            return [$left, $right];
        }

        if ($right < \count($replayed) && ($left >= \count($recorded) || $common[$left][$right + 1] >= $common[$left + 1][$right])) {
            return [null, $right];
        }

        return [$left, null];
    }

    /**
     * @param list<string> $recorded
     * @param list<string> $replayed
     *
     * @return array<int, array<int, int>> the common subsequence length of each pair of suffixes
     */
    private static function commonLengths(array $recorded, array $replayed): array
    {
        $rows = \count($recorded);
        $columns = \count($replayed);
        $common = array_fill(0, $rows + 1, array_fill(0, $columns + 1, 0));

        for ($row = $rows - 1; $row >= 0; --$row) {
            for ($column = $columns - 1; $column >= 0; --$column) {
                $common[$row][$column] = $recorded[$row] === $replayed[$column]
                    ? $common[$row + 1][$column + 1] + 1
                    : max($common[$row + 1][$column], $common[$row][$column + 1]);
            }
        }

        return $common;
    }
}
