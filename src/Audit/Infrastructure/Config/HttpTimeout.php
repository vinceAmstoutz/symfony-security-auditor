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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigUserOnlyKeyException;

/**
 * How long the standalone binary's HTTP client waits for a provider that sends
 * nothing, in seconds — the idle timeout of every request; how long a request
 * takes in total is not bounded. Without it the client falls back to PHP's
 * `default_socket_timeout`, 60 seconds, and gives up on a non-streamed answer
 * that a slow local model or a self-hosted gateway takes longer to start
 * sending.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class HttpTimeout
{
    public const string KEY = 'http_timeout';

    public const float DEFAULT_SECONDS = 600.0;

    /**
     * @param array<array-key, mixed> $config
     *
     * @throws MalformedProjectConfigException
     */
    public static function in(array $config, string $configFile): float
    {
        if (!\array_key_exists(self::KEY, $config)) {
            return self::DEFAULT_SECONDS;
        }

        return self::seconds($config[self::KEY]) ?? throw MalformedProjectConfigException::forHttpTimeout($configFile, self::KEY);
    }

    /**
     * A repository may give a slow provider more time, never less: a shorter
     * timeout than the user's could cut every call of its own audit short.
     *
     * @param array<array-key, mixed> $projectConfig
     *
     * @return ?float the timeout the project config raises the user's to, or null when it sets none
     *
     * @throws ProjectConfigUserOnlyKeyException
     */
    public static function raisedBy(array $projectConfig, float $userTimeout, string $projectConfigFile): ?float
    {
        if (!\array_key_exists(self::KEY, $projectConfig)) {
            return null;
        }

        $seconds = self::seconds($projectConfig[self::KEY]);

        return null !== $seconds && $seconds >= $userTimeout ? $seconds : throw ProjectConfigUserOnlyKeyException::forShortenedTimeout($projectConfigFile, self::KEY);
    }

    private static function seconds(mixed $value): ?float
    {
        return (\is_int($value) || \is_float($value)) && $value > 0 && is_finite($value) ? $value : null;
    }
}
