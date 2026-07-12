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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Advisory;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\InMemoryAdvisoryDatabase;

final class InMemoryAdvisoryDatabaseTest extends TestCase
{
    public function test_lookup_returns_empty_array_when_package_unknown(): void
    {
        $inMemoryAdvisoryDatabase = new InMemoryAdvisoryDatabase([]);

        self::assertSame([], $inMemoryAdvisoryDatabase->lookup('unknown/pkg', '1.0.0'));
    }

    public function test_lookup_returns_advisories_for_known_package_regardless_of_version(): void
    {
        $advisory = [
            'cve' => 'CVE-1',
            'title' => 't',
            'summary' => 's',
            'affected_versions' => '<6.0.5',
            'link' => null,
        ];
        $inMemoryAdvisoryDatabase = new InMemoryAdvisoryDatabase(['sym/x' => [$advisory]]);

        self::assertSame([$advisory], $inMemoryAdvisoryDatabase->lookup('sym/x', '6.0.0'));
    }

    public function test_lookup_returns_all_entries_when_package_has_many(): void
    {
        $a = ['cve' => 'CVE-A', 'title' => 'A', 'summary' => 's', 'affected_versions' => '<2.0', 'link' => null];
        $b = ['cve' => 'CVE-B', 'title' => 'B', 'summary' => 's', 'affected_versions' => '<3.0', 'link' => null];
        $inMemoryAdvisoryDatabase = new InMemoryAdvisoryDatabase(['sym/x' => [$a, $b]]);

        self::assertSame([$a, $b], $inMemoryAdvisoryDatabase->lookup('sym/x', '1.0.0'));
    }

    public function test_lookup_matches_a_differently_cased_package_name(): void
    {
        $advisory = ['cve' => 'CVE-1', 'title' => 't', 'summary' => 's', 'affected_versions' => '<6.0.5', 'link' => null];
        $inMemoryAdvisoryDatabase = new InMemoryAdvisoryDatabase(['symfony/http-foundation' => [$advisory]]);

        self::assertSame([$advisory], $inMemoryAdvisoryDatabase->lookup('Symfony/Http-Foundation', '6.0.0'));
    }

    public function test_lookup_matches_a_package_name_with_leading_or_trailing_whitespace(): void
    {
        $advisory = ['cve' => 'CVE-1', 'title' => 't', 'summary' => 's', 'affected_versions' => '<6.0.5', 'link' => null];
        $inMemoryAdvisoryDatabase = new InMemoryAdvisoryDatabase(['symfony/http-foundation' => [$advisory]]);

        self::assertSame([$advisory], $inMemoryAdvisoryDatabase->lookup(' symfony/http-foundation ', '6.0.0'));
    }
}
