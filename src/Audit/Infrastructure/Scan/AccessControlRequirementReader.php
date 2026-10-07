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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AccessControlRequirementReader
{
    /**
     * @var list<string>
     */
    private const array REQUIREMENT_KEYS = ['roles', 'role', 'allow_if', 'methods', 'ips', 'requires_channel', 'host', 'port'];

    /**
     * Distinguishes an entry that declares a requirement key but with an
     * empty value (`roles: []` — a deliberate public rule) from one that
     * declares no requirement key at all (a degenerate entry with nothing to
     * record).
     *
     * @param array<string, mixed> $entry
     */
    public function hasAnyRequirementKey(array $entry): bool
    {
        foreach (self::REQUIREMENT_KEYS as $requirementKey) {
            if (\array_key_exists($requirementKey, $entry)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $entry
     *
     * @return list<string>
     */
    public function requirementsOf(array $entry): array
    {
        $requirements = $this->stringListOf($entry['roles'] ?? $entry['role'] ?? null);

        if (\is_string($entry['allow_if'] ?? null)) {
            $requirements[] = \sprintf('allow_if: %s', $entry['allow_if']);
        }

        return [...$requirements, ...$this->listedRequirements($entry), ...$this->scalarRequirements($entry)];
    }

    /**
     * @param array<string, mixed> $entry
     *
     * @return list<string>
     */
    private function listedRequirements(array $entry): array
    {
        $requirements = [];
        foreach (['methods' => '|', 'ips' => ', '] as $key => $separator) {
            $values = $this->stringListOf($entry[$key] ?? null);
            if ('methods' === $key) {
                $values = array_map(strtoupper(...), $values);
            }

            if ([] !== $values) {
                $requirements[] = \sprintf('%s: %s', $key, implode($separator, $values));
            }
        }

        return $requirements;
    }

    /**
     * @param array<string, mixed> $entry
     *
     * @return list<string>
     */
    private function scalarRequirements(array $entry): array
    {
        $scalarValues = array_filter(
            ['requires_channel' => $entry['requires_channel'] ?? null, 'host' => $entry['host'] ?? null, 'port' => $entry['port'] ?? null],
            static fn (mixed $value): bool => \is_string($value) || \is_int($value),
        );

        return array_map(
            static fn (string $key, string|int $value): string => \sprintf('%s: %s', $key, $value),
            array_keys($scalarValues),
            $scalarValues,
        );
    }

    /**
     * @return list<string>
     */
    private function stringListOf(mixed $value): array
    {
        if (\is_string($value)) {
            $parts = array_map(trim(...), explode(',', $value));

            return array_values(array_filter($parts, static fn (string $part): bool => '' !== $part));
        }

        if (!\is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, is_string(...)));
    }
}
