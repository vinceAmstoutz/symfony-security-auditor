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
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\AdvisorySourceUnavailableException;

final class ComposerAuditAdvisoryDatabaseTest extends TestCase
{
    public function test_lookup_returns_advisories_for_known_package(): void
    {
        $composerAuditRunner = $this->stubRunner($this->validJson());

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder('/proj'), new NullLogger());

        self::assertCount(1, $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.2.3'));
    }

    public function test_lookup_returns_empty_for_unknown_package(): void
    {
        $composerAuditRunner = $this->stubRunner($this->validJson());

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder('/proj'), new NullLogger());

        self::assertSame([], $composerAuditAdvisoryDatabase->lookup('vendor/unknown', '1.0.0'));
    }

    public function test_lookup_returns_entries_for_each_distinct_package_in_payload(): void
    {
        $json = (string) json_encode([
            'advisories' => [
                'vendor/foo' => [['title' => 'Foo advisory', 'affectedVersions' => '>=1.0']],
                'vendor/bar' => [['title' => 'Bar advisory', 'affectedVersions' => '>=2.0']],
            ],
        ]);

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($this->stubRunner($json), new AuditedProjectPathHolder('/proj'), new NullLogger());

        self::assertCount(1, $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.5.0'));
        self::assertCount(1, $composerAuditAdvisoryDatabase->lookup('vendor/bar', '2.5.0'));
    }

    public function test_lookup_advisory_entry_shape_matches_interface_contract(): void
    {
        $composerAuditRunner = $this->stubRunner($this->validJson());

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder('/proj'), new NullLogger());
        $entry = $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.2.3')[0];

        self::assertSame('CVE-2024-0001', $entry['cve']);
        self::assertSame('SQL injection in vendor/foo', $entry['title']);
        self::assertSame('Detailed explanation of the issue', $entry['summary']);
        self::assertSame('>=1.0,<1.3.0', $entry['affected_versions']);
        self::assertSame('https://example.com/advisory/CVE-2024-0001', $entry['link']);
    }

    public function test_lookup_returns_empty_when_runner_reports_source_unavailable(): void
    {
        $runner = self::createStub(ComposerAuditRunnerInterface::class);
        $runner->method('run')->willThrowException(AdvisorySourceUnavailableException::forBinaryNotFound());

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($runner, new AuditedProjectPathHolder('/proj'), new NullLogger());

        self::assertSame([], $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.2.3'));
    }

    public function test_lookup_returns_empty_when_payload_is_invalid_json(): void
    {
        $composerAuditRunner = $this->stubRunner('not json at all');

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder('/proj'), new NullLogger());

        self::assertSame([], $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.2.3'));
    }

    public function test_lookup_returns_empty_when_advisories_key_is_missing(): void
    {
        $composerAuditRunner = $this->stubRunner('{"abandoned": {}}');

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder('/proj'), new NullLogger());

        self::assertSame([], $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.2.3'));
    }

    public function test_lookup_returns_empty_when_runner_throws_unexpected_exception(): void
    {
        $runner = self::createStub(ComposerAuditRunnerInterface::class);
        $runner->method('run')->willThrowException(new RuntimeException('network blew up'));

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($runner, new AuditedProjectPathHolder('/proj'), new NullLogger());

        self::assertSame([], $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.2.3'));
    }

    public function test_logger_records_warning_when_source_unavailable(): void
    {
        $runner = self::createStub(ComposerAuditRunnerInterface::class);
        $runner->method('run')->willThrowException(AdvisorySourceUnavailableException::forBinaryNotFound());

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('composer audit unavailable'),
                [
                    'project' => '/proj',
                    'error' => 'composer binary not found on PATH; cannot run advisory audit',
                ],
            );

        new ComposerAuditAdvisoryDatabase($runner, new AuditedProjectPathHolder('/proj'), $logger);
    }

    public function test_logger_records_warning_when_payload_malformed(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('unparseable'),
                self::callback(static function (array $context): bool {
                    return '/proj' === $context['project']
                        && \is_string($context['error'])
                        && str_contains($context['error'], 'invalid JSON');
                }),
            );

        new ComposerAuditAdvisoryDatabase($this->stubRunner('garbage'), new AuditedProjectPathHolder('/proj'), $logger);
    }

    public function test_logger_records_warning_on_unexpected_throwable(): void
    {
        $runner = self::createStub(ComposerAuditRunnerInterface::class);
        $runner->method('run')->willThrowException(new RuntimeException('boom'));

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('Unexpected composer audit failure'),
                [
                    'project' => '/proj',
                    'error' => 'boom',
                ],
            );

        new ComposerAuditAdvisoryDatabase($runner, new AuditedProjectPathHolder('/proj'), $logger);
    }

    public function test_lookup_returns_all_advisories_for_package_with_multiple_entries(): void
    {
        $json = (string) json_encode([
            'advisories' => [
                'vendor/foo' => [
                    ['title' => 'First advisory', 'affectedVersions' => '>=1.0,<1.5'],
                    ['title' => 'Second advisory', 'affectedVersions' => '>=1.5,<2.0'],
                    ['title' => 'Third advisory', 'affectedVersions' => '>=2.0,<2.3'],
                ],
            ],
        ]);

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($this->stubRunner($json), new AuditedProjectPathHolder('/proj'), new NullLogger());
        $entries = $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.2');

        self::assertCount(3, $entries);
        self::assertSame('First advisory', $entries[0]['title']);
        self::assertSame('Second advisory', $entries[1]['title']);
        self::assertSame('Third advisory', $entries[2]['title']);
    }

    public function test_lookup_continues_past_advisory_with_missing_title_to_keep_subsequent_entries(): void
    {
        $json = (string) json_encode([
            'advisories' => [
                'vendor/foo' => [
                    ['cve' => 'CVE-2024-1111'],
                    ['title' => 'Valid advisory after the broken one', 'affectedVersions' => '>=1.0'],
                ],
            ],
        ]);

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($this->stubRunner($json), new AuditedProjectPathHolder('/proj'), new NullLogger());
        $entries = $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.5.0');

        self::assertCount(1, $entries);
        self::assertSame('Valid advisory after the broken one', $entries[0]['title']);
    }

    public function test_lookup_skips_entries_with_missing_title(): void
    {
        $json = (string) json_encode([
            'advisories' => [
                'vendor/foo' => [
                    [
                        'cve' => 'CVE-2024-0002',
                        'affectedVersions' => '>=1.0,<2.0',
                    ],
                ],
            ],
        ]);

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($this->stubRunner($json), new AuditedProjectPathHolder('/proj'), new NullLogger());

        self::assertSame([], $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.5.0'));
    }

    public function test_lookup_falls_back_to_title_when_summary_missing(): void
    {
        $json = (string) json_encode([
            'advisories' => [
                'vendor/foo' => [
                    [
                        'title' => 'Standalone title',
                        'affectedVersions' => '>=1.0,<2.0',
                    ],
                ],
            ],
        ]);

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($this->stubRunner($json), new AuditedProjectPathHolder('/proj'), new NullLogger());
        $entry = $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.5.0')[0];

        self::assertSame('Standalone title', $entry['summary']);
    }

    public function test_lookup_returns_null_cve_when_absent_or_empty(): void
    {
        $json = (string) json_encode([
            'advisories' => [
                'vendor/foo' => [
                    [
                        'title' => 'No CVE entry',
                        'cve' => '',
                        'affectedVersions' => '>=1.0',
                    ],
                ],
            ],
        ]);

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($this->stubRunner($json), new AuditedProjectPathHolder('/proj'), new NullLogger());
        $entry = $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.5.0')[0];

        self::assertNull($entry['cve']);
    }

    public function test_lookup_returns_null_link_when_absent_or_empty(): void
    {
        $json = (string) json_encode([
            'advisories' => [
                'vendor/foo' => [
                    [
                        'title' => 'No link entry',
                        'link' => '',
                        'affectedVersions' => '>=1.0',
                    ],
                ],
            ],
        ]);

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($this->stubRunner($json), new AuditedProjectPathHolder('/proj'), new NullLogger());
        $entry = $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.5.0')[0];

        self::assertNull($entry['link']);
    }

    public function test_lookup_skips_non_array_advisory_entries(): void
    {
        $json = (string) json_encode([
            'advisories' => [
                'vendor/foo' => [
                    'not an advisory dict',
                    [
                        'title' => 'Real advisory',
                        'affectedVersions' => '>=1.0',
                    ],
                ],
            ],
        ]);

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($this->stubRunner($json), new AuditedProjectPathHolder('/proj'), new NullLogger());

        self::assertCount(1, $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.5.0'));
    }

    public function test_lookup_skips_advisories_grouped_under_non_array_package_value(): void
    {
        $json = (string) json_encode([
            'advisories' => [
                'vendor/foo' => 'unexpected scalar',
                'vendor/bar' => [
                    ['title' => 'Bar advisory', 'affectedVersions' => '>=1.0'],
                ],
            ],
        ]);

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($this->stubRunner($json), new AuditedProjectPathHolder('/proj'), new NullLogger());

        self::assertSame([], $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.0.0'));
        self::assertCount(1, $composerAuditAdvisoryDatabase->lookup('vendor/bar', '1.0.0'));
    }

    public function test_the_audit_runs_against_the_path_the_holder_carries(): void
    {
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::once())->method('run')->with('/audited/project')->willReturn($this->validJson());
        $auditedProjectPathHolder = new AuditedProjectPathHolder('/container/default');
        $auditedProjectPathHolder->set('/audited/project');

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($composerAuditRunner, $auditedProjectPathHolder, new NullLogger());

        self::assertCount(1, $composerAuditAdvisoryDatabase->lookup('vendor/foo', '1.2.3'));
    }

    private function stubRunner(string $json): ComposerAuditRunnerInterface
    {
        $runner = self::createStub(ComposerAuditRunnerInterface::class);
        $runner->method('run')->willReturn($json);

        return $runner;
    }

    private function validJson(): string
    {
        return (string) json_encode([
            'advisories' => [
                'vendor/foo' => [
                    [
                        'advisoryId' => 'PKSA-AAAA-BBBB-CCCC',
                        'packageName' => 'vendor/foo',
                        'affectedVersions' => '>=1.0,<1.3.0',
                        'title' => 'SQL injection in vendor/foo',
                        'cve' => 'CVE-2024-0001',
                        'link' => 'https://example.com/advisory/CVE-2024-0001',
                        'summary' => 'Detailed explanation of the issue',
                    ],
                ],
            ],
            'abandoned' => [],
        ]);
    }
}
