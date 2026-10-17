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
 * Compares a replay with its recording. Maps are compared key by key, so a
 * difference names the dotted path of what changed (for instance
 * `runs.0.stdout.json.vulnerabilities.1.severity`); lists are aligned on the
 * items they share first, and text kept as `lines` is compared line by line,
 * so an inserted item or line is one difference instead of a shifted rest.
 *
 * A key a report gained is no difference: `docs/versioning.md` lets a `MINOR`
 * add keys to the JSON a command prints or writes, so inside a JSON document
 * only a key that is gone or a value that changed counts — except for the
 * PHP API's accessors, where a new one is listed like any other change.
 */
final readonly class ObservationDiffer
{
    private const string JSON_DOCUMENT = 'json';

    private function __construct(
        private bool $acceptsAddedJsonKeys,
        private bool $insideJsonDocument,
    ) {}

    public static function forReports(): self
    {
        return new self(true, false);
    }

    public static function exact(): self
    {
        return new self(false, false);
    }

    /**
     * @return list<Difference>
     */
    public function diff(mixed $recorded, mixed $replayed, string $path = ''): array
    {
        if ($recorded === $replayed) {
            return [];
        }

        $recordedLines = $this->lines($recorded);
        $replayedLines = $this->lines($replayed);
        if (null !== $recordedLines && null !== $replayedLines) {
            return LineDiff::between(\sprintf('%slines', $this->prefix($path)), $recordedLines, $replayedLines);
        }

        if (!\is_array($recorded) || !\is_array($replayed) || array_is_list($recorded) !== array_is_list($replayed)) {
            return [Difference::ofValue($path, $recorded, $replayed)];
        }

        return array_is_list($recorded) && array_is_list($replayed) && [] !== $recorded ? ListDiff::between($path, $recorded, $replayed, $this) : $this->diffKeys($recorded, $replayed, $path);
    }

    /**
     * @param array<array-key, mixed> $recorded
     * @param array<array-key, mixed> $replayed
     *
     * @return list<Difference>
     */
    private function diffKeys(array $recorded, array $replayed, string $path): array
    {
        $differences = [];
        foreach (array_keys($recorded + $replayed) as $key) {
            $childPath = \sprintf('%s%s', $this->prefix($path), $key);
            $differences = [...$differences, ...match (true) {
                !\array_key_exists($key, $replayed) => [Difference::ofValue($childPath, $recorded[$key], Difference::ABSENT)],
                !\array_key_exists($key, $recorded) => $this->added($childPath, $replayed[$key]),
                default => $this->inside($recorded, $key)->diff($recorded[$key], $replayed[$key], $childPath),
            }];
        }

        return $differences;
    }

    /**
     * @return list<Difference>
     */
    private function added(string $path, mixed $replayed): array
    {
        return $this->acceptsAddedJsonKeys && $this->insideJsonDocument ? [] : [Difference::ofValue($path, Difference::ABSENT, $replayed)];
    }

    /**
     * @param array<array-key, mixed> $map
     */
    private function inside(array $map, int|string $key): self
    {
        return self::JSON_DOCUMENT === $key && [self::JSON_DOCUMENT] === array_keys($map) ? new self($this->acceptsAddedJsonKeys, true) : $this;
    }

    private function prefix(string $path): string
    {
        return '' === $path ? '' : \sprintf('%s.', $path);
    }

    /**
     * @return list<string>|null
     */
    private function lines(mixed $value): ?array
    {
        if (!\is_array($value) || ['lines'] !== array_keys($value) || !\is_array($value['lines']) || !array_is_list($value['lines'])) {
            return null;
        }

        $lines = array_filter($value['lines'], \is_string(...));

        return \count($lines) === \count($value['lines']) ? array_values($lines) : null;
    }
}
