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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat;

use JsonException;

/**
 * The digest a recorder writes into the fixture it records, over everything
 * else the fixture holds. A fixture is only ever recorded from a release, so
 * a digest that no longer matches means it was edited by hand: record it
 * again instead.
 */
final readonly class FixtureSeal
{
    public const string KEY = 'seal';

    /**
     * @param array<string, mixed> $fixture
     *
     * @return array<string, mixed>
     *
     * @throws JsonException
     */
    public static function sealed(array $fixture): array
    {
        unset($fixture[self::KEY]);

        return [...$fixture, self::KEY => self::digest($fixture)];
    }

    /**
     * @param array<string, mixed> $fixture
     *
     * @throws JsonException
     */
    public static function isIntact(array $fixture): bool
    {
        $seal = $fixture[self::KEY] ?? null;
        unset($fixture[self::KEY]);

        return self::digest($fixture) === $seal;
    }

    /**
     * @param array<string, mixed> $fixture
     *
     * @throws JsonException
     */
    private static function digest(array $fixture): string
    {
        return hash('sha256', json_encode($fixture, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_PRESERVE_ZERO_FRACTION));
    }
}
