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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\AccessControlRequirementReader;

final class AccessControlRequirementReaderTest extends TestCase
{
    #[DataProvider('requirementKeyCases')]
    public function test_it_detects_an_entry_that_declares_a_requirement_key(string $requirementKey): void
    {
        self::assertTrue((new AccessControlRequirementReader())->hasAnyRequirementKey([$requirementKey => []]));
    }

    public function test_it_detects_an_entry_that_declares_no_requirement_key(): void
    {
        self::assertFalse((new AccessControlRequirementReader())->hasAnyRequirementKey(['path' => '^/admin', 'priority' => 1]));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function requirementKeyCases(): iterable
    {
        foreach (['roles', 'role', 'allow_if', 'methods', 'ips', 'requires_channel', 'host', 'port'] as $requirementKey) {
            yield $requirementKey => [$requirementKey];
        }
    }

    /**
     * @param array<string, mixed> $entry
     * @param list<string>         $expected
     */
    #[DataProvider('requirementCases')]
    public function test_it_lists_the_requirements_an_entry_declares(array $entry, array $expected): void
    {
        self::assertSame($expected, (new AccessControlRequirementReader())->requirementsOf($entry));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, list<string>}>
     */
    public static function requirementCases(): iterable
    {
        yield 'an empty roles list is a public rule' => [['roles' => []], []];
        yield 'roles as a comma separated string' => [['roles' => 'ROLE_A, ROLE_B,,'], ['ROLE_A', 'ROLE_B']];
        yield 'roles as a list drops non strings' => [['roles' => ['ROLE_A', 7, 'ROLE_B']], ['ROLE_A', 'ROLE_B']];
        yield 'roles win over the singular role' => [['roles' => 'ROLE_A', 'role' => 'ROLE_B'], ['ROLE_A']];
        yield 'the singular role is a fallback' => [['role' => 'ROLE_B'], ['ROLE_B']];
        yield 'an allow_if expression' => [['allow_if' => 'is_granted("ROLE_A")'], ['allow_if: is_granted("ROLE_A")']];
        yield 'methods are upper-cased and pipe separated' => [['methods' => ['get', 'post']], ['methods: GET|POST']];
        yield 'ips are comma separated' => [['ips' => '127.0.0.1, ::1'], ['ips: 127.0.0.1, ::1']];
        yield 'scalar requirements keep string and integer values' => [['requires_channel' => 'https', 'host' => 'example.com', 'port' => 8443], ['requires_channel: https', 'host: example.com', 'port: 8443']];
        yield 'scalar requirements drop other types' => [['requires_channel' => ['https'], 'host' => true, 'port' => 8.5], []];
        yield 'requirements keep roles, allow_if, listed then scalar order' => [
            ['port' => 443, 'ips' => '10.0.0.1', 'methods' => 'get', 'allow_if' => 'x', 'roles' => 'ROLE_A'],
            ['ROLE_A', 'allow_if: x', 'methods: GET', 'ips: 10.0.0.1', 'port: 443'],
        ];
    }
}
