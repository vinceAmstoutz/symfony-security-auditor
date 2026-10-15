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
 * Compares two lists item by item after aligning the items they share, so an
 * item inserted at the front is one difference instead of a shifted rest of
 * the list: between two shared items, the items lost and gained are compared
 * in pairs, and the ones left over are reported as gone or new. A path names
 * an item by its index in the recording, or in the replay for a new one.
 */
final readonly class ListDiff
{
    /**
     * @param list<mixed> $recorded
     * @param list<mixed> $replayed
     *
     * @return list<Difference>
     */
    public static function between(string $path, array $recorded, array $replayed, ObservationDiffer $observationDiffer): array
    {
        $differences = [];
        foreach (self::gaps(LineDiff::alignment(array_map(self::canonical(...), $recorded), array_map(self::canonical(...), $replayed))) as $gap) {
            $differences = [...$differences, ...self::paired($path, [$recorded, $replayed], $gap, $observationDiffer)];
        }

        return $differences;
    }

    /**
     * @param list<array{int|null, int|null}> $alignment
     *
     * @return list<array{list<int>, list<int>}> the items lost and gained between two shared items
     */
    private static function gaps(array $alignment): array
    {
        $gaps = [[[], []]];
        foreach ($alignment as [$recordedIndex, $replayedIndex]) {
            $current = array_key_last($gaps);
            match (true) {
                null !== $recordedIndex && null !== $replayedIndex => $gaps[] = [[], []],
                null !== $recordedIndex => $gaps[$current][0][] = $recordedIndex,
                default => $gaps[$current][1][] = $replayedIndex ?? 0,
            };
        }

        return $gaps;
    }

    /**
     * @param array{list<mixed>, list<mixed>} $lists the recorded list, then the replayed one
     * @param array{list<int>, list<int>}     $gap
     *
     * @return list<Difference>
     */
    private static function paired(string $path, array $lists, array $gap, ObservationDiffer $observationDiffer): array
    {
        [$recorded, $replayed] = $lists;
        [$lost, $gained] = $gap;
        $differences = [];

        foreach ($lost as $position => $recordedIndex) {
            $itemPath = \sprintf('%s.%d', $path, $recordedIndex);
            $differences = [...$differences, ...(\array_key_exists($position, $gained)
                ? $observationDiffer->diff($recorded[$recordedIndex], $replayed[$gained[$position]], $itemPath)
                : [Difference::ofValue($itemPath, $recorded[$recordedIndex], Difference::ABSENT)])];
        }

        foreach (\array_slice($gained, \count($lost)) as $replayedIndex) {
            $differences[] = Difference::ofValue(\sprintf('%s.%d', $path, $replayedIndex), Difference::ABSENT, $replayed[$replayedIndex]);
        }

        return $differences;
    }

    private static function canonical(mixed $item): string
    {
        return (string) json_encode($item, \JSON_PRESERVE_ZERO_FRACTION | \JSON_UNESCAPED_SLASHES);
    }
}
