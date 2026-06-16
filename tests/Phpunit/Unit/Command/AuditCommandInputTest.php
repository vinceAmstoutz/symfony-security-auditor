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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommandInput;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\WorkingDirectoryUnavailableException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\OutputFormat;

final class AuditCommandInputTest extends TestCase
{
    public function test_is_machine_readable_to_stdout_true_when_no_output_file_and_json_format(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '/app';
        $auditCommandInput->output = null;
        $auditCommandInput->format = OutputFormat::Json;

        self::assertTrue($auditCommandInput->isMachineReadableToStdout());
    }

    public function test_is_machine_readable_to_stdout_true_when_no_output_file_and_sarif_format(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '/app';
        $auditCommandInput->output = null;
        $auditCommandInput->format = OutputFormat::Sarif;

        self::assertTrue($auditCommandInput->isMachineReadableToStdout());
    }

    public function test_is_machine_readable_to_stdout_false_when_console_format_even_without_output_file(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '/app';
        $auditCommandInput->output = null;
        $auditCommandInput->format = OutputFormat::Console;

        self::assertFalse($auditCommandInput->isMachineReadableToStdout());
    }

    public function test_is_machine_readable_to_stdout_false_when_output_file_is_set_with_json_format(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '/app';
        $auditCommandInput->output = '/tmp/report.json';
        $auditCommandInput->format = OutputFormat::Json;

        self::assertFalse($auditCommandInput->isMachineReadableToStdout());
    }

    public function test_default_format_is_console(): void
    {
        $auditCommandInput = new AuditCommandInput();

        self::assertSame(OutputFormat::Console, $auditCommandInput->format);
    }

    public function test_default_output_is_null(): void
    {
        $auditCommandInput = new AuditCommandInput();

        self::assertNull($auditCommandInput->output);
    }

    public function test_default_project_path_is_null(): void
    {
        $auditCommandInput = new AuditCommandInput();

        self::assertNull($auditCommandInput->projectPath);
    }

    public function test_resolved_project_path_returns_cwd_when_property_is_null(): void
    {
        $auditCommandInput = new AuditCommandInput();

        self::assertSame(getcwd(), $auditCommandInput->resolvedProjectPath());
    }

    public function test_resolved_project_path_returns_cwd_when_property_is_empty_string(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '';

        self::assertSame(getcwd(), $auditCommandInput->resolvedProjectPath());
    }

    public function test_resolved_project_path_returns_cwd_when_property_is_whitespace_only(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '   ';

        self::assertSame(getcwd(), $auditCommandInput->resolvedProjectPath());
    }

    public function test_resolved_project_path_returns_provided_path_when_set(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '/tmp/project';

        self::assertSame('/tmp/project', $auditCommandInput->resolvedProjectPath());
    }

    public function test_resolved_project_path_trims_surrounding_whitespace_and_returns_absolute(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = ' /tmp/project ';

        self::assertSame('/tmp/project', $auditCommandInput->resolvedProjectPath());
    }

    public function test_resolved_project_path_resolves_dot_to_the_working_directory(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '.';

        self::assertSame('/custom/cwd', $auditCommandInput->resolvedProjectPath(static fn (): string => '/custom/cwd'));
    }

    public function test_resolved_project_path_resolves_a_relative_path_against_the_working_directory(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = 'app';

        self::assertSame('/custom/cwd/app', $auditCommandInput->resolvedProjectPath(static fn (): string => '/custom/cwd'));
    }

    public function test_resolved_project_path_throws_when_cwd_lookup_returns_false(): void
    {
        $auditCommandInput = new AuditCommandInput();

        $this->expectException(WorkingDirectoryUnavailableException::class);
        $this->expectExceptionMessage('Failed to determine current working directory');

        $auditCommandInput->resolvedProjectPath(static fn (): false => false);
    }

    public function test_resolved_project_path_uses_injected_resolver_when_property_is_null(): void
    {
        $auditCommandInput = new AuditCommandInput();

        self::assertSame('/custom/cwd', $auditCommandInput->resolvedProjectPath(static fn (): string => '/custom/cwd'));
    }

    public function test_default_paths_is_empty_list(): void
    {
        $auditCommandInput = new AuditCommandInput();

        self::assertSame([], $auditCommandInput->paths);
    }

    public function test_scan_paths_returns_input_paths_unchanged(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->paths = ['apps/api/src', 'libs/shared/src'];

        self::assertSame(['apps/api/src', 'libs/shared/src'], $auditCommandInput->scanPaths());
    }

    public function test_scan_paths_drops_blank_entries(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->paths = ['apps/api/src', '', '   ', 'libs'];

        self::assertSame(['apps/api/src', 'libs'], $auditCommandInput->scanPaths());
    }

    public function test_scan_paths_normalizes_trailing_separators(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->paths = ['apps/api/src/', 'libs/shared/'];

        self::assertSame(['apps/api/src', 'libs/shared'], $auditCommandInput->scanPaths());
    }

    public function test_default_no_cache_is_false(): void
    {
        $auditCommandInput = new AuditCommandInput();

        self::assertFalse($auditCommandInput->noCache);
    }

    public function test_default_fail_on_is_null(): void
    {
        $auditCommandInput = new AuditCommandInput();

        self::assertNull($auditCommandInput->failOn);
    }

    public function test_fail_on_accepts_a_risk_level(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->failOn = RiskLevel::High;

        self::assertSame(RiskLevel::High, $auditCommandInput->failOn);
    }
}
