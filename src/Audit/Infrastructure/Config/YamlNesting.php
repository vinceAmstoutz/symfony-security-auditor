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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

/**
 * How a YAML file nests, read from its lines alone, before a parser that
 * copies the rest of a block at every level it opens is handed the file: how
 * many levels are open at once, and the bytes it would copy, each line counted
 * once for every level open around it, blank and comment lines included,
 * since a block carries them along. A carriage return ends a line, alone or
 * before a line feed, as it does for the parser.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class YamlNesting
{
    private function __construct(
        public int $depth,
        public int $nestedBytes,
    ) {}

    /**
     * @param int $depthLimit the depth past which the file is not read any further, its nested bytes then left uncounted
     */
    public static function of(string $yaml, int $depthLimit): self
    {
        $openColumns = [];
        $depth = 0;
        $nestedBytes = 0;
        foreach (explode("\n", str_replace(["\r\n", "\r"], "\n", $yaml)) as $line) {
            $openColumns = self::openAfter($openColumns, YamlLineNodes::columnsOf($line, $depthLimit));
            $depth = max($depth, \count($openColumns));
            if ($depth > $depthLimit) {
                return new self($depth, $nestedBytes);
            }

            $nestedBytes += (\strlen($line) + 1) * \count($openColumns);
        }

        return new self($depth, $nestedBytes);
    }

    /**
     * @param list<int> $openColumns
     * @param list<int> $lineColumns
     *
     * @return list<int>
     */
    private static function openAfter(array $openColumns, array $lineColumns): array
    {
        if ([] === $lineColumns) {
            return $openColumns;
        }

        return [...array_filter($openColumns, static fn (int $openColumn): bool => $openColumn < $lineColumns[0]), ...$lineColumns];
    }
}
