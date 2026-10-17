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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner;

final readonly class ExpandedConfig
{
    /**
     * @param array<string, mixed> $config
     *
     * @return array<string, mixed>
     */
    public static function of(array $config, Workspace $workspace): array
    {
        $expanded = [];
        foreach (self::expanded($config, $workspace) as $key => $value) {
            $expanded[(string) $key] = $value;
        }

        return $expanded;
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     */
    private static function expanded(array $config, Workspace $workspace): array
    {
        $expanded = [];
        foreach ($config as $key => $value) {
            $expanded[$key] = match (true) {
                \is_string($value) => $workspace->expand($value),
                \is_array($value) => self::expanded($value, $workspace),
                default => $value,
            };
        }

        return $expanded;
    }
}
