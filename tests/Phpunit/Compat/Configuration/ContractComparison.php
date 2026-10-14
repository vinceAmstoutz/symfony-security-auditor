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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Configuration;

/**
 * How the contract of one path narrowed between the recorded release and
 * this tree; a path that only widened (a new choice, a value it now takes,
 * a looser bound) yields nothing.
 */
final readonly class ContractComparison
{
    private const array WIDER_KINDS = [
        'integer' => ['float', 'scalar', 'variable'],
        'float' => ['scalar', 'variable'],
        'boolean' => ['scalar', 'variable'],
        'enum' => ['scalar', 'variable'],
        'scalar' => ['variable'],
    ];

    /**
     * @param array<string, mixed> $recorded
     * @param array<string, mixed> $current
     *
     * @return list<string>
     */
    public static function narrowings(array $recorded, array $current): array
    {
        $recordedNode = self::map($recorded['node'] ?? []);
        $currentNode = self::map($current['node'] ?? []);

        return [
            ...self::nodeNarrowings($recordedNode, $currentNode),
            ...self::valueNarrowings(self::map($recorded['values'] ?? []), self::map($current['values'] ?? [])),
            ...(true === ($recorded['environment_placeholder'] ?? null) && true !== ($current['environment_placeholder'] ?? null) ? ['an %env()% placeholder is refused'] : []),
            ...(($recorded['project_config'] ?? null) !== ($current['project_config'] ?? null) ? [\sprintf('a project configuration setting it is %s', self::text($current['project_config'] ?? null))] : []),
        ];
    }

    /**
     * @param array<array-key, mixed> $recorded
     * @param array<array-key, mixed> $current
     *
     * @return list<string>
     */
    private static function nodeNarrowings(array $recorded, array $current): array
    {
        $kind = self::text($recorded['kind'] ?? null);
        $newKind = self::text($current['kind'] ?? null);

        return array_keys(array_filter([
            \sprintf('its kind narrowed from %s to %s', $kind, $newKind) => $kind !== $newKind && !\in_array($newKind, self::WIDER_KINDS[$kind] ?? [], true),
            'it became required' => false === ($recorded['required'] ?? null) && true === ($current['required'] ?? null),
            \sprintf('its default changed to %s', self::canonical($current['default'] ?? null)) => self::canonical($recorded['default'] ?? null) !== self::canonical($current['default'] ?? null),
            'it lost a choice' => [] !== array_diff(self::list($recorded['values'] ?? []), self::list($current['values'] ?? [])),
            'its minimum was raised' => self::isLowerBoundRaised($recorded['min'] ?? null, $current['min'] ?? null),
            'its maximum was lowered' => self::isUpperBoundLowered($recorded['max'] ?? null, $current['max'] ?? null),
        ]));
    }

    /**
     * @param array<array-key, mixed> $recorded
     * @param array<array-key, mixed> $current
     *
     * @return list<string>
     */
    private static function valueNarrowings(array $recorded, array $current): array
    {
        $narrowings = [];
        foreach ($recorded as $probe => $outcome) {
            $recordedOutcome = self::map($outcome);
            if (true !== ($recordedOutcome['accepted'] ?? null)) {
                continue;
            }

            if (self::canonical($recordedOutcome) !== self::canonical($current[$probe] ?? null)) {
                $narrowings[] = \sprintf('the "%s" probe is now %s', $probe, self::canonical($current[$probe] ?? null));
            }
        }

        return $narrowings;
    }

    private static function isLowerBoundRaised(mixed $recorded, mixed $current): bool
    {
        return null !== $current && (null === $recorded || (is_numeric($recorded) && is_numeric($current) && $current > $recorded));
    }

    private static function isUpperBoundLowered(mixed $recorded, mixed $current): bool
    {
        return null !== $current && (null === $recorded || (is_numeric($recorded) && is_numeric($current) && $current < $recorded));
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function map(mixed $value): array
    {
        return \is_array($value) ? $value : [];
    }

    /**
     * @return list<string>
     */
    private static function list(mixed $value): array
    {
        return array_values(array_map(self::canonical(...), self::map($value)));
    }

    private static function canonical(mixed $value): string
    {
        return (string) json_encode($value, \JSON_PRESERVE_ZERO_FRACTION | \JSON_UNESCAPED_SLASHES);
    }

    private static function text(mixed $value): string
    {
        return \is_string($value) ? $value : self::canonical($value);
    }
}
