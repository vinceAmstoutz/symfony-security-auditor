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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommandDefaults;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommandInput;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ConflictingCommandOptionsException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InvalidMinScoreException;
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

    public function test_the_report_file_is_the_output_option_when_a_report_is_written(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->output = '/tmp/report.json';

        self::assertSame('/tmp/report.json', $auditCommandInput->reportFile());
    }

    public function test_show_scanned_alone_has_no_report_file_since_it_writes_no_report(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->output = '/tmp/report.json';
        $auditCommandInput->showScanned = true;

        self::assertNull($auditCommandInput->reportFile());
    }

    public function test_show_scanned_with_dry_run_keeps_the_report_file_of_its_estimate(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->output = '/tmp/report.json';
        $auditCommandInput->showScanned = true;
        $auditCommandInput->dryRun = true;

        self::assertSame('/tmp/report.json', $auditCommandInput->reportFile());
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

    /**
     * @throws WorkingDirectoryUnavailableException
     */
    public function test_resolved_project_path_returns_cwd_when_property_is_null(): void
    {
        $auditCommandInput = new AuditCommandInput();

        self::assertSame(getcwd(), $auditCommandInput->resolvedProjectPath());
    }

    /**
     * @throws WorkingDirectoryUnavailableException
     */
    public function test_resolved_project_path_returns_cwd_when_property_is_empty_string(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '';

        self::assertSame(getcwd(), $auditCommandInput->resolvedProjectPath());
    }

    /**
     * @throws WorkingDirectoryUnavailableException
     */
    public function test_resolved_project_path_returns_cwd_when_property_is_whitespace_only(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '   ';

        self::assertSame(getcwd(), $auditCommandInput->resolvedProjectPath());
    }

    /**
     * @throws WorkingDirectoryUnavailableException
     */
    public function test_resolved_project_path_returns_provided_path_when_set(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '/tmp/project';

        self::assertSame('/tmp/project', $auditCommandInput->resolvedProjectPath());
    }

    /**
     * @throws WorkingDirectoryUnavailableException
     */
    public function test_resolved_project_path_trims_surrounding_whitespace_and_returns_absolute(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = ' /tmp/project ';

        self::assertSame('/tmp/project', $auditCommandInput->resolvedProjectPath());
    }

    /**
     * @throws WorkingDirectoryUnavailableException
     */
    public function test_resolved_project_path_resolves_dot_to_the_working_directory(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '.';

        self::assertSame('/custom/cwd', $auditCommandInput->resolvedProjectPath(static fn (): string => '/custom/cwd'));
    }

    /**
     * @throws WorkingDirectoryUnavailableException
     */
    public function test_resolved_project_path_resolves_a_relative_path_against_the_working_directory(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = 'app';

        self::assertSame('/custom/cwd/app', $auditCommandInput->resolvedProjectPath(static fn (): string => '/custom/cwd'));
    }

    /**
     * @throws WorkingDirectoryUnavailableException
     */
    public function test_resolved_project_path_throws_when_cwd_lookup_returns_false(): void
    {
        $auditCommandInput = new AuditCommandInput();

        $this->expectException(WorkingDirectoryUnavailableException::class);
        $this->expectExceptionMessage('Failed to determine current working directory');

        $auditCommandInput->resolvedProjectPath(static fn (): false => false);
    }

    /**
     * @throws WorkingDirectoryUnavailableException
     */
    public function test_resolved_project_path_does_not_need_the_working_directory_for_an_already_absolute_path(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = '/an/explicit/absolute/path';

        self::assertSame('/an/explicit/absolute/path', $auditCommandInput->resolvedProjectPath(static fn (): false => false));
    }

    /**
     * @throws WorkingDirectoryUnavailableException
     */
    public function test_resolved_project_path_uses_injected_resolver_when_property_is_null(): void
    {
        $auditCommandInput = new AuditCommandInput();

        self::assertSame('/custom/cwd', $auditCommandInput->resolvedProjectPath(static fn (): string => '/custom/cwd'));
    }

    /**
     * @throws WorkingDirectoryUnavailableException
     */
    #[DataProvider('projectPathsThatAreNotValidUtf8')]
    public function test_resolved_project_path_accepts_a_path_that_is_not_valid_utf8(string $projectPath, string $expected): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->projectPath = $projectPath;

        self::assertSame($expected, $auditCommandInput->resolvedProjectPath(static fn (): string => '/custom/cwd'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function projectPathsThatAreNotValidUtf8(): iterable
    {
        yield 'an absolute path' => ["/srv/caf\xE9", "/srv/caf\xE9"];
        yield 'an absolute path with surrounding whitespace' => [" \t/srv/caf\xE9\n ", "/srv/caf\xE9"];
        yield 'a relative path' => ["caf\xE9", "/custom/cwd/caf\xE9"];
        yield 'a relative path with surrounding whitespace' => [" caf\xE9 ", "/custom/cwd/caf\xE9"];
    }

    /**
     * @param list<string> $paths
     * @param list<string> $expected
     */
    #[DataProvider('scanPathsThatAreNotValidUtf8')]
    public function test_scan_paths_accept_paths_that_are_not_valid_utf8(array $paths, array $expected): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->paths = $paths;

        self::assertSame($expected, $auditCommandInput->scanPaths());
    }

    /**
     * @return iterable<string, array{list<string>, list<string>}>
     */
    public static function scanPathsThatAreNotValidUtf8(): iterable
    {
        yield 'a plain path' => [["src/caf\xE9"], ["src/caf\xE9"]];
        yield 'surrounding whitespace' => [[" src/caf\xE9 "], ["src/caf\xE9"]];
        yield 'trailing separators' => [["src/caf\xE9//"], ["src/caf\xE9"]];
        yield 'a leading current directory segment' => [["./src/caf\xE9"], ["src/caf\xE9"]];
        yield 'a doubled leading current directory segment' => [[".//./caf\xE9"], ["caf\xE9"]];
        yield 'a blank entry between two paths' => [["caf\xE9", '  ', "src/caf\xE9"], ["caf\xE9", "src/caf\xE9"]];
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

    public function test_scan_paths_drops_a_slash_only_entry(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->paths = ['/', 'apps/api/src'];

        self::assertSame(['apps/api/src'], $auditCommandInput->scanPaths());
    }

    public function test_scan_paths_strips_a_leading_dot_slash_segment(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->paths = ['./src', 'apps/api/src'];

        self::assertSame(['src', 'apps/api/src'], $auditCommandInput->scanPaths());
    }

    public function test_scan_paths_drops_a_bare_dot_entry(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->paths = ['.', 'apps/api/src'];

        self::assertSame(['apps/api/src'], $auditCommandInput->scanPaths());
    }

    public function test_scan_paths_strips_a_leading_dot_slash_segment_with_a_doubled_separator(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->paths = ['.//src', 'apps/api/src'];

        self::assertSame(['src', 'apps/api/src'], $auditCommandInput->scanPaths());
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

    public function test_default_fail_on_incomplete_is_unset_so_the_configuration_can_decide(): void
    {
        self::assertNull((new AuditCommandInput())->failOnIncomplete);
    }

    public function test_the_configured_defaults_fill_what_the_command_line_left_unset(): void
    {
        $auditCommandInput = new AuditCommandInput();

        $auditCommandInput->applyDefaults(new AuditCommandDefaults(80, true, OutputFormat::Sarif, 'audit.sarif'), false);

        self::assertSame(80, $auditCommandInput->minScore);
        self::assertTrue($auditCommandInput->failsOnIncomplete());
        self::assertSame(OutputFormat::Sarif, $auditCommandInput->format);
        self::assertSame('audit.sarif', $auditCommandInput->output);
    }

    public function test_what_the_command_line_gave_wins_over_the_configured_defaults(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->minScore = 50;
        $auditCommandInput->failOnIncomplete = false;
        $auditCommandInput->format = OutputFormat::Markdown;
        $auditCommandInput->output = 'cli.md';

        $auditCommandInput->applyDefaults(new AuditCommandDefaults(80, true, OutputFormat::Sarif, 'audit.sarif'), true);

        self::assertSame(50, $auditCommandInput->minScore);
        self::assertFalse($auditCommandInput->failsOnIncomplete());
        self::assertSame(OutputFormat::Markdown, $auditCommandInput->format);
        self::assertSame('cli.md', $auditCommandInput->output);
    }

    public function test_a_format_named_on_the_command_line_wins_even_when_it_is_the_default_one(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->format = OutputFormat::Console;

        $auditCommandInput->applyDefaults(new AuditCommandDefaults(format: OutputFormat::Json), true);

        self::assertSame(OutputFormat::Console, $auditCommandInput->format);
    }

    public function test_an_unset_fail_on_incomplete_does_not_fail_the_run_when_nothing_configures_it(): void
    {
        $auditCommandInput = new AuditCommandInput();

        $auditCommandInput->applyDefaults(new AuditCommandDefaults(), false);

        self::assertFalse($auditCommandInput->failsOnIncomplete());
        self::assertNull($auditCommandInput->minScore);
        self::assertSame(OutputFormat::Console, $auditCommandInput->format);
        self::assertNull($auditCommandInput->output);
    }

    public function test_the_configured_format_decides_whether_the_report_goes_to_stdout(): void
    {
        $auditCommandInput = new AuditCommandInput();

        $auditCommandInput->applyDefaults(new AuditCommandDefaults(format: OutputFormat::Json), false);

        self::assertTrue($auditCommandInput->isMachineReadableToStdout());
    }

    public function test_fail_on_accepts_a_risk_level(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->failOn = RiskLevel::High;

        self::assertSame(RiskLevel::High, $auditCommandInput->failOn);
    }

    /**
     * @throws ConflictingCommandOptionsException
     */
    public function test_assert_no_conflicting_options_allows_generate_baseline_alone(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->generateBaseline = 'baseline.json';

        $auditCommandInput->assertNoConflictingOptions();

        self::assertSame('baseline.json', $auditCommandInput->generateBaseline);
    }

    /**
     * @throws ConflictingCommandOptionsException
     */
    public function test_assert_no_conflicting_options_allows_dry_run_alone(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->dryRun = true;

        $auditCommandInput->assertNoConflictingOptions();

        self::assertTrue($auditCommandInput->dryRun);
    }

    /**
     * @throws ConflictingCommandOptionsException
     */
    public function test_assert_no_conflicting_options_rejects_generate_baseline_with_dry_run(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->generateBaseline = 'baseline.json';
        $auditCommandInput->dryRun = true;

        $this->expectException(ConflictingCommandOptionsException::class);
        $this->expectExceptionMessage('--generate-baseline requires a real audit run and cannot be combined with --dry-run, which exits before the LLM is ever invoked.');

        $auditCommandInput->assertNoConflictingOptions();
    }

    /**
     * @throws ConflictingCommandOptionsException
     */
    public function test_assert_no_conflicting_options_rejects_generate_baseline_with_show_scanned(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->generateBaseline = 'baseline.json';
        $auditCommandInput->showScanned = true;

        $this->expectException(ConflictingCommandOptionsException::class);
        $this->expectExceptionMessage('--generate-baseline requires a real audit run and cannot be combined with --show-scanned, which exits before the LLM is ever invoked.');

        $auditCommandInput->assertNoConflictingOptions();
    }

    /**
     * @throws InvalidMinScoreException
     */
    #[DataProvider('scoresWithinTheRange')]
    public function test_assert_min_score_in_range_allows_a_score_from_zero_to_one_hundred(?int $minScore): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->minScore = $minScore;

        $auditCommandInput->assertMinScoreInRange();

        self::assertSame($minScore, $auditCommandInput->minScore);
    }

    /**
     * @return iterable<string, array{?int}>
     */
    public static function scoresWithinTheRange(): iterable
    {
        yield 'no gate' => [null];
        yield 'the floor' => [0];
        yield 'a middle score' => [75];
        yield 'the ceiling' => [100];
    }

    /**
     * @throws InvalidMinScoreException
     */
    #[DataProvider('scoresOutsideTheRange')]
    public function test_assert_min_score_in_range_rejects_a_score_the_normalized_range_cannot_hold(int $minScore): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->minScore = $minScore;

        $this->expectException(InvalidMinScoreException::class);
        $this->expectExceptionMessage(\sprintf('--min-score must be between 0 and 100, got %d.', $minScore));

        $auditCommandInput->assertMinScoreInRange();
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function scoresOutsideTheRange(): iterable
    {
        yield 'just below the floor' => [-1];
        yield 'far below the floor' => [-50];
        yield 'just above the ceiling' => [101];
        yield 'far above the ceiling' => [150];
    }

    public function test_a_no_output_flag_keeps_the_configured_output_from_applying(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->noOutput = true;

        $auditCommandInput->applyDefaults(new AuditCommandDefaults(output: 'audit.sarif'), true);

        self::assertNull($auditCommandInput->reportFile());
    }

    public function test_a_dry_run_does_not_write_its_estimate_over_the_configured_output(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->dryRun = true;

        $auditCommandInput->applyDefaults(new AuditCommandDefaults(output: 'audit.sarif'), true);

        self::assertNull($auditCommandInput->reportFile());
    }

    public function test_a_dry_run_still_writes_to_an_output_given_on_the_command_line(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->dryRun = true;
        $auditCommandInput->output = 'estimate.json';

        $auditCommandInput->applyDefaults(new AuditCommandDefaults(output: 'audit.sarif'), true);

        self::assertSame('estimate.json', $auditCommandInput->reportFile());
    }

    public function test_a_no_output_flag_prints_a_machine_readable_report_to_stdout(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->noOutput = true;
        $auditCommandInput->format = OutputFormat::Json;

        $auditCommandInput->applyDefaults(new AuditCommandDefaults(output: 'audit.json'), true);

        self::assertTrue($auditCommandInput->isMachineReadableToStdout());
    }

    /**
     * @throws ConflictingCommandOptionsException
     */
    public function test_assert_no_conflicting_options_allows_no_output_alone(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->noOutput = true;

        $auditCommandInput->assertNoConflictingOptions();

        self::assertTrue($auditCommandInput->noOutput);
    }

    /**
     * @throws ConflictingCommandOptionsException
     */
    public function test_assert_no_conflicting_options_rejects_output_with_no_output(): void
    {
        $auditCommandInput = new AuditCommandInput();
        $auditCommandInput->output = 'report.json';
        $auditCommandInput->noOutput = true;

        $this->expectException(ConflictingCommandOptionsException::class);
        $this->expectExceptionMessage('--output and --no-output cannot be combined: one writes the report to a file, the other prints it.');

        $auditCommandInput->assertNoConflictingOptions();
    }
}
