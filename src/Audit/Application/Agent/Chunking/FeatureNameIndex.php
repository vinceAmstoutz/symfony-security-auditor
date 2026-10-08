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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking;

use function Symfony\Component\String\u;

/**
 * Finds the features a file may belong to without testing it against every
 * feature, so grouping a project costs time proportional to its files rather
 * than to its files times its controllers.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FeatureNameIndex
{
    /**
     * @param array<string, int>          $positionByName    where each feature was declared
     * @param array<string, list<string>> $namesByFoldedName
     */
    private function __construct(
        private array $positionByName,
        private array $namesByFoldedName,
    ) {}

    /**
     * @param list<string> $featureNames
     */
    public static function of(array $featureNames): self
    {
        $namesByFoldedName = [];
        foreach ($featureNames as $featureName) {
            $namesByFoldedName[self::folded($featureName)][] = $featureName;
        }

        return new self(array_flip($featureNames), $namesByFoldedName);
    }

    /**
     * The features whose name is the start of `$baseName`, however the rest
     * of it reads.
     *
     * @return list<string>
     */
    public function startingBaseName(string $baseName): array
    {
        $features = [];
        $prefix = '';
        foreach (str_split($baseName) as $character) {
            $prefix .= $character;

            if (\array_key_exists($prefix, $this->positionByName)) {
                $features[] = $prefix;
            }
        }

        return $features;
    }

    /**
     * The features named, whatever the case, by a directory between the
     * project root and the file: the first segment of the path and its file
     * name are not between two slashes.
     *
     * @return list<string>
     */
    public function namedByDirectory(string $relativePath): array
    {
        $features = [];
        foreach (\array_slice(explode('/', $relativePath), 1, -1) as $directory) {
            $features = [...$features, ...$this->namesByFoldedName[self::folded($directory)] ?? []];
        }

        return $features;
    }

    /**
     * The longest of `$features`, the first one declared when several are as
     * long, or `null` when there is none.
     *
     * @param list<string> $features
     */
    public function mostSpecific(array $features): ?string
    {
        usort($features, fn (string $a, string $b): int => [\strlen($b), $this->positionByName[$a]] <=> [\strlen($a), $this->positionByName[$b]]);

        return $features[0] ?? null;
    }

    private static function folded(string $text): string
    {
        return u($text)->folded()->toString();
    }
}
