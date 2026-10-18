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

use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

/**
 * The settings a user fills with prose or a regex (a risk pattern, a scrubbing
 * pattern, a skill's instructions), and the names a user gives (a risk-pattern
 * bucket or label, a skill), which the container reads too, where a `%` is far
 * more likely to be text than a container reference. A path setting is left
 * alone on purpose: a `%LOCALAPPDATA%` there is an environment reference the
 * user meant, and taking it literally would create a folder of that name
 * instead of stopping.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FreeTextSettings
{
    private const array PATHS = [
        ['scan', 'custom_risk_patterns', null, null, 'regex'],
        ['scan', 'custom_risk_patterns', null, null, 'description'],
        ['scan', 'secret_scrubbing', 'additional_patterns', null],
        ['audit', 'custom_skills', null, 'instructions'],
    ];

    private const array NAME_PATHS = [
        ['scan', 'custom_risk_patterns', null],
        ['scan', 'custom_risk_patterns', null, null],
        ['audit', 'custom_skills', null],
    ];

    /**
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     */
    public static function literalIn(array $config, ParameterBagInterface $parameterBag): array
    {
        return self::walk($config, $parameterBag, []);
    }

    /**
     * @param array<array-key, mixed> $config
     * @param list<string>            $parentPath
     *
     * @return array<array-key, mixed>
     */
    private static function walk(array $config, ParameterBagInterface $parameterBag, array $parentPath): array
    {
        $walked = [];

        foreach ($config as $key => $value) {
            $path = [...$parentPath, (string) $key];
            $walked[self::walkKey($key, $parameterBag, $path)] = self::walkValue($value, $parameterBag, $path);
        }

        return $walked;
    }

    /**
     * @param list<string> $path
     */
    private static function walkKey(int|string $key, ParameterBagInterface $parameterBag, array $path): int|string
    {
        return \is_string($key) && self::isAt(self::NAME_PATHS, $path) ? ContainerParameterSyntax::escapeUnresolvable($key, $parameterBag) : $key;
    }

    /**
     * @param list<string> $path
     */
    private static function walkValue(mixed $value, ParameterBagInterface $parameterBag, array $path): mixed
    {
        return match (true) {
            \is_array($value) => self::walk($value, $parameterBag, $path),
            \is_string($value) && self::isAt(self::PATHS, $path) => ContainerParameterSyntax::escapeUnresolvable($value, $parameterBag),
            default => $value,
        };
    }

    /**
     * @param list<list<string|null>> $patterns
     * @param list<string>            $path
     */
    private static function isAt(array $patterns, array $path): bool
    {
        foreach ($patterns as $pattern) {
            if (self::matches($pattern, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string|null> $pattern
     * @param list<string>      $path
     */
    private static function matches(array $pattern, array $path): bool
    {
        return \count($pattern) === \count($path)
            && [] === array_filter($pattern, static fn (?string $segment, int $index): bool => null !== $segment && $segment !== $path[$index], \ARRAY_FILTER_USE_BOTH);
    }
}
