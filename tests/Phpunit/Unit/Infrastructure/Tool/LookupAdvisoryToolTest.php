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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Tool;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\InMemoryAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\LookupAdvisoryTool;

final class LookupAdvisoryToolTest extends TestCase
{
    public function test_definition_matches_expected_full_schema(): void
    {
        $lookupAdvisoryTool = new LookupAdvisoryTool(new InMemoryAdvisoryDatabase());

        $definition = $lookupAdvisoryTool->definition();

        self::assertSame('lookup_advisory', $definition->name);
        self::assertSame(
            [
                'type' => 'object',
                'properties' => [
                    'package' => [
                        'type' => 'string',
                        'description' => 'Composer package name, e.g. symfony/http-foundation',
                    ],
                    'version' => [
                        'type' => 'string',
                        'description' => 'Installed version, e.g. 6.4.2',
                    ],
                ],
                'required' => ['package', 'version'],
            ],
            $definition->parametersSchema,
        );
    }

    public function test_execute_returns_no_advisories_message_when_database_empty(): void
    {
        $lookupAdvisoryTool = new LookupAdvisoryTool(new InMemoryAdvisoryDatabase());

        $result = $lookupAdvisoryTool->execute(['package' => 'symfony/http-foundation', 'version' => '6.0.0']);

        self::assertStringContainsString('No advisories found', $result);
        self::assertStringContainsString('symfony/http-foundation', $result);
    }

    public function test_execute_returns_matching_entries(): void
    {
        $inMemoryAdvisoryDatabase = new InMemoryAdvisoryDatabase([
            'symfony/http-foundation' => [
                [
                    'cve' => 'CVE-2024-1234',
                    'title' => 'Header injection',
                    'summary' => 'A header injection vector',
                    'affected_versions' => '<6.0.5',
                    'link' => 'https://example.com/CVE-2024-1234',
                ],
            ],
        ]);

        $lookupAdvisoryTool = new LookupAdvisoryTool($inMemoryAdvisoryDatabase);
        $result = $lookupAdvisoryTool->execute(['package' => 'symfony/http-foundation', 'version' => '6.0.0']);

        self::assertStringContainsString('CVE-2024-1234', $result);
        self::assertStringContainsString('Header injection', $result);
        self::assertStringContainsString('https://example.com/CVE-2024-1234', $result);
    }

    public function test_execute_returns_error_for_missing_package(): void
    {
        $lookupAdvisoryTool = new LookupAdvisoryTool(new InMemoryAdvisoryDatabase());

        $result = $lookupAdvisoryTool->execute(['version' => '1.0.0']);

        self::assertStringContainsString('Error', $result);
        self::assertStringContainsString('package', $result);
    }

    public function test_execute_returns_error_for_missing_version(): void
    {
        $lookupAdvisoryTool = new LookupAdvisoryTool(new InMemoryAdvisoryDatabase());

        $result = $lookupAdvisoryTool->execute(['package' => 'symfony/x']);

        self::assertStringContainsString('Error', $result);
        self::assertStringContainsString('version', $result);
    }

    public function test_execute_returns_error_for_empty_package(): void
    {
        $lookupAdvisoryTool = new LookupAdvisoryTool(new InMemoryAdvisoryDatabase());

        $result = $lookupAdvisoryTool->execute(['package' => '', 'version' => '1.0']);

        self::assertStringContainsString('Error', $result);
    }

    public function test_execute_returns_error_for_empty_version(): void
    {
        $lookupAdvisoryTool = new LookupAdvisoryTool(new InMemoryAdvisoryDatabase());

        $result = $lookupAdvisoryTool->execute(['package' => 'symfony/x', 'version' => '']);

        self::assertStringContainsString('Error', $result);
    }

    public function test_execute_returns_error_for_non_string_package(): void
    {
        $lookupAdvisoryTool = new LookupAdvisoryTool(new InMemoryAdvisoryDatabase());

        $result = $lookupAdvisoryTool->execute(['package' => 123, 'version' => '1.0']);

        self::assertStringContainsString('Error', $result);
    }

    public function test_execute_returns_error_for_non_string_version(): void
    {
        $lookupAdvisoryTool = new LookupAdvisoryTool(new InMemoryAdvisoryDatabase());

        $result = $lookupAdvisoryTool->execute(['package' => 'a/b', 'version' => 1]);

        self::assertStringContainsString('Error', $result);
    }

    public function test_execute_uses_no_cve_label_when_cve_is_null(): void
    {
        $inMemoryAdvisoryDatabase = new InMemoryAdvisoryDatabase([
            'sym/x' => [[
                'cve' => null,
                'title' => 'Untagged',
                'summary' => 'desc',
                'affected_versions' => '<2.0',
                'link' => null,
            ]],
        ]);
        $lookupAdvisoryTool = new LookupAdvisoryTool($inMemoryAdvisoryDatabase);

        $result = $lookupAdvisoryTool->execute(['package' => 'sym/x', 'version' => '1.0']);

        self::assertStringContainsString('(no CVE)', $result);
        self::assertStringContainsString('(no link)', $result);
    }

    public function test_execute_joins_multiple_entries_with_blank_separator(): void
    {
        $inMemoryAdvisoryDatabase = new InMemoryAdvisoryDatabase([
            'sym/x' => [
                ['cve' => 'CVE-A', 'title' => 'A', 'summary' => 'sumA', 'affected_versions' => '<2.0', 'link' => null],
                ['cve' => 'CVE-B', 'title' => 'B', 'summary' => 'sumB', 'affected_versions' => '<2.0', 'link' => null],
            ],
        ]);
        $lookupAdvisoryTool = new LookupAdvisoryTool($inMemoryAdvisoryDatabase);

        $result = $lookupAdvisoryTool->execute(['package' => 'sym/x', 'version' => '1.0']);

        self::assertStringContainsString('CVE-A', $result);
        self::assertStringContainsString('CVE-B', $result);
    }
}
