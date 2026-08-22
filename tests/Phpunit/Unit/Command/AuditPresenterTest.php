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

use InvalidArgumentException;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatterInterface;
use Symfony\Component\Console\Input\StringInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;

final class AuditPresenterTest extends TestCase
{
    private AuditPresenter $auditPresenter;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->auditPresenter = new AuditPresenter($this->pricingProviderKnowing('claude-opus-4-7', 'claude-haiku-4-5-20251001'));
        $this->tmpDir = sys_get_temp_dir().'/presenter_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    public function test_error_for_invalid_argument_exception_uses_message_as_is(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->error($symfonyStyle, new InvalidArgumentException('Project path missing'));

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('Project path missing', $display);
        self::assertStringNotContainsString('Unexpected error:', $display);
    }

    public function test_error_for_generic_throwable_prefixes_message_with_unexpected_error(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->error($symfonyStyle, new RuntimeException('Disk full'));

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('Unexpected error: Disk full', $display);
    }

    public function test_long_run_notice_warns_that_the_audit_can_take_a_while(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->longRunNotice($symfonyStyle);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('many LLM calls', $display);
        self::assertStringContainsString('20+ minutes', $display);
    }

    public function test_header_includes_project_path(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->header($symfonyStyle, '/path/to/project');

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('Project:', $display);
        self::assertStringContainsString('/path/to/project', $display);
        self::assertStringContainsString('Pipeline:', $display);
    }

    public function test_header_neutralizes_console_markup_in_the_project_path(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->header($symfonyStyle, '/var/www/<fg=grey>oops</>');

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('/var/www/<fg=grey>oops</>', $display);
    }

    public function test_header_shows_the_mark_and_wordmark_in_the_brand_palette_when_decorated(): void
    {
        $display = $this->headerIn(['LC_ALL' => 'en_US.UTF-8'], true);
        $outputFormatter = (new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL, true))->getFormatter();

        self::assertStringContainsString($this->formatted($outputFormatter, '<fg=#e71c55;options=bold>◉ >> SECURITY</>'), $display);
        self::assertStringContainsString($this->formatted($outputFormatter, '<fg=#5b6fd6;options=bold>AUDITOR</>'), $display);
        self::assertStringStartsWith(\PHP_EOL, $display, 'the header must not abut whatever printed before it');
    }

    public function test_header_keeps_the_same_layout_without_colour_when_not_decorated(): void
    {
        $display = $this->headerIn(['LC_ALL' => 'en_US.UTF-8'], false);

        self::assertStringContainsString(' ◉ >> SECURITY AUDITOR', $display);
        self::assertStringContainsString('Symfony - multi-agent LLM audit', $display);
        self::assertStringNotContainsString("\033[", $display, 'CI output must carry no escape sequences');
    }

    public function test_the_tagline_starts_under_the_wordmark_not_under_the_mark(): void
    {
        $lines = explode(\PHP_EOL, $this->headerIn(['LC_ALL' => 'en_US.UTF-8'], false));

        self::assertSame(
            mb_strpos($lines[1], 'SECURITY'),
            mb_strpos($lines[2], 'Symfony'),
            'the tagline offset is derived from the lead string, so it tracks the mark width',
        );
    }

    public function test_a_console_without_utf8_drops_the_mark_and_keeps_the_wordmark(): void
    {
        $display = $this->headerIn(['LC_ALL' => 'C'], false);

        self::assertStringNotContainsString('◉', $display, 'the mark is outside CP437/CP850/CP1252 and would be substituted');
        self::assertStringContainsString(' SECURITY AUDITOR', $display);
        self::assertStringContainsString('Symfony - multi-agent LLM audit', $display);
    }

    public function test_a_console_without_utf8_still_gets_the_brand_palette(): void
    {
        $display = $this->headerIn(['LC_ALL' => 'C'], true);
        $outputFormatter = (new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL, true))->getFormatter();

        self::assertStringContainsString($this->formatted($outputFormatter, '<fg=#e71c55;options=bold>SECURITY</>'), $display);
        self::assertStringContainsString($this->formatted($outputFormatter, '<fg=#5b6fd6;options=bold>AUDITOR</>'), $display);
    }

    /**
     * @param array<string, string> $locale
     */
    #[DataProvider('utf8Announcements')]
    public function test_any_locale_variable_announcing_utf8_earns_the_mark(array $locale): void
    {
        self::assertStringContainsString('◉', $this->headerIn($locale, false));
    }

    /** @return iterable<string, array{array<string, string>}> */
    public static function utf8Announcements(): iterable
    {
        yield 'LC_ALL' => [['LC_ALL' => 'en_US.UTF-8']];
        yield 'LC_CTYPE only' => [['LC_CTYPE' => 'en_US.UTF-8']];
        yield 'LANG only' => [['LANG' => 'en_US.UTF-8']];
        yield 'lowercase spelling' => [['LANG' => 'en_us.utf-8']];
        yield 'unhyphenated spelling' => [['LANG' => 'en_US.utf8']];
    }

    public function test_a_console_that_announces_no_locale_at_all_drops_the_mark(): void
    {
        $display = $this->headerIn([], false);

        self::assertStringNotContainsString('◉', $display);
        self::assertStringContainsString(' SECURITY AUDITOR', $display);
    }

    #[DataProvider('consoleModes')]
    public function test_the_header_is_pure_ascii_without_utf8_support(bool $decorated): void
    {
        $withoutEscapes = (string) preg_replace('/\033\[[0-9;]*m/', '', $this->headerIn(['LC_ALL' => 'C'], $decorated));

        self::assertMatchesRegularExpression('/^[\x00-\x7F]*$/', $withoutEscapes);
    }

    /** @return iterable<string, array{bool}> */
    public static function consoleModes(): iterable
    {
        yield 'decorated' => [true];
        yield 'plain' => [false];
    }

    /**
     * Every locale variable is pinned individually, and any not named is
     * cleared: setting all three to one value hides which of them
     * `localeSetting()` actually read.
     *
     * @param array<string, string> $locale
     */
    private function headerIn(array $locale, bool $decorated): string
    {
        $variables = ['LC_ALL', 'LC_CTYPE', 'LANG'];
        $previous = [];

        foreach ($variables as $variable) {
            $previous[$variable] = getenv($variable);
            $value = $locale[$variable] ?? null;
            putenv(null === $value ? $variable : \sprintf('%s=%s', $variable, $value));
        }

        try {
            $bufferedOutput = new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL, $decorated);
            $this->auditPresenter->header(new SymfonyStyle(new StringInput(''), $bufferedOutput), '/path/to/project');

            return $bufferedOutput->fetch();
        } finally {
            foreach ($variables as $variable) {
                $restored = $previous[$variable];
                putenv(false === $restored ? $variable : \sprintf('%s=%s', $variable, $restored));
            }
        }
    }

    private function formatted(OutputFormatterInterface $outputFormatter, string $tag): string
    {
        $formatted = $outputFormatter->format($tag);
        self::assertNotNull($formatted);

        return $formatted;
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_result_for_failure_exit_omits_success_message(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->result($symfonyStyle, $this->makeCriticalReport(), Command::FAILURE);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('CRITICAL', $display);
        self::assertStringContainsString('vulnerabilities found', $display);
        self::assertStringNotContainsString('Audit complete. Risk:', $display);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_result_for_failure_exit_reflects_the_actual_risk_level_not_a_hardcoded_critical(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->result($symfonyStyle, $this->makeHighRiskReport(), Command::FAILURE);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('Risk: HIGH', $display);
        self::assertStringNotContainsString('CRITICAL', $display);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_result_for_failure_exit_uses_singular_wording_for_exactly_one_vulnerability(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->result($symfonyStyle, $this->makeSingleVulnerabilityReport(), Command::FAILURE);

        $flattened = preg_replace('/[\s!]+/', ' ', $bufferedOutput->fetch()) ?? '';
        self::assertStringContainsString('1 vulnerability found.', $flattened);
        self::assertStringNotContainsString('1 vulnerabilities found', $flattened);
    }

    /**
     * `AuditExitCodeResolver` fails a run when the risk gate OR the independent
     * `--min-score` gate trips, and only the exit code reaches the presenter —
     * so it must not attribute the failure to one specific gate. A LOW-risk
     * report failing under `--fail-on=critical --min-score=96` is a
     * score-only failure the old wording described as a fail-on breach.
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_result_for_failure_exit_does_not_blame_a_gate_it_cannot_identify(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->result($symfonyStyle, $this->makeLowRiskReport(), Command::FAILURE);

        $flattened = preg_replace('/\s+/', ' ', $bufferedOutput->fetch()) ?? '';
        self::assertStringNotContainsString('at or above the fail-on threshold', $flattened);
        self::assertStringContainsString('Risk: LOW', $flattened);
        self::assertStringContainsString('Score: 95/100', $flattened);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_result_for_success_exit_emits_success_message(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->result($symfonyStyle, AuditReport::fromContext(AuditContext::forProject($this->tmpDir)), Command::SUCCESS);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('Audit complete. Risk:', $display);
        self::assertStringNotContainsString('CRITICAL risk level', $display);
    }

    public function test_preflight_warnings_emit_secret_scrubbing_warning_when_disabled(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->preflightWarnings($symfonyStyle, secretScrubbingEnabled: false);

        $display = $bufferedOutput->fetch();
        $flattened = preg_replace('/\s+/', ' ', $display) ?? '';
        self::assertStringContainsString('Secret scrubbing is disabled. File contents will be sent verbatim to the configured LLM provider.', $flattened);
        self::assertStringContainsString('If that provider runs in the cloud, credentials in committed configs or .env.dist files may be exposed.', $flattened);
        self::assertStringContainsString('Re-enable scan.secret_scrubbing.enabled (the default) or confirm you are using a local provider.', $flattened);
    }

    public function test_preflight_warnings_are_silent_when_secret_scrubbing_enabled(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->preflightWarnings($symfonyStyle, secretScrubbingEnabled: true);

        self::assertSame('', $bufferedOutput->fetch());
    }

    public function test_preflight_warnings_print_each_config_notice(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->preflightWarnings($symfonyStyle, secretScrubbingEnabled: true, configNotices: [
            'first notice about the cache',
            'second notice about batching',
        ]);

        $flattened = preg_replace('/\s+/', ' ', $bufferedOutput->fetch()) ?? '';
        self::assertStringContainsString('first notice about the cache', $flattened);
        self::assertStringContainsString('second notice about batching', $flattened);
    }

    public function test_baseline_generated_reports_the_path_and_count(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->baselineGenerated($symfonyStyle, '.security-baseline.json', 3);

        $flattened = preg_replace('/\s+/', ' ', $bufferedOutput->fetch()) ?? '';
        self::assertStringContainsString('Baseline written to .security-baseline.json', $flattened);
        self::assertStringContainsString('3 finding fingerprint(s)', $flattened);
    }

    public function test_running_section_emits_section_header(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->runningSection($symfonyStyle);

        self::assertStringContainsString('Running audit pipeline', $bufferedOutput->fetch());
    }

    public function test_estimating_section_emits_dry_run_section_header(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->estimatingSection($symfonyStyle);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('dry run', $display);
        self::assertStringNotContainsString('Running audit pipeline', $display);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_dry_run_result_shows_completion_without_audit_language(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->dryRunResult($symfonyStyle, AuditReport::fromContext(AuditContext::forProject($this->tmpDir)));

        $display = $bufferedOutput->fetch();
        $flattened = preg_replace('/[\s!]+/', ' ', $display) ?? '';
        self::assertStringContainsString('Dry run complete', $flattened);
        self::assertStringContainsString('a real run typically costs less', $flattened);
        self::assertStringContainsString('no LLM calls', $flattened);
        self::assertStringNotContainsString('Audit complete', $display);
        self::assertStringNotContainsString('RISK LEVEL', $display);
        self::assertStringNotContainsString('vulnerabilities found', $display);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_dry_run_result_reports_completion_as_a_light_line_not_a_boxed_block(): void
    {
        $bufferedOutput = new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL, true);
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->dryRunResult($symfonyStyle, AuditReport::fromContext(AuditContext::forProject($this->tmpDir)));

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('✅ Dry run complete.', $display);
        self::assertStringNotContainsString('[OK]', $display);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_dry_run_result_omits_the_emoji_when_not_decorated(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->dryRunResult($symfonyStyle, AuditReport::fromContext(AuditContext::forProject($this->tmpDir)));

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('Dry run complete.', $display);
        self::assertStringNotContainsString('✅', $display);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_dry_run_result_leaves_a_blank_line_after_the_completion_line(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->dryRunResult($symfonyStyle, AuditReport::fromContext(AuditContext::forProject($this->tmpDir)));

        self::assertStringEndsWith("Dry run complete.\n\n", $bufferedOutput->fetch());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_dry_run_result_shows_cost_breakdown_when_cost_present(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext, AuditCost::of(1000, 200, 0.0123, 'claude-opus-4-7'));

        $this->auditPresenter->dryRunResult($symfonyStyle, $auditReport);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('claude-opus-4-7', $display);
        self::assertStringContainsString('1,000', $display);
        self::assertStringContainsString('0.0123', $display);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_dry_run_result_formats_cost_with_a_period_regardless_of_the_process_numeric_locale(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext, AuditCost::of(1000, 200, 1234.5, 'claude-opus-4-7', [
            'attacker' => ['model' => 'claude-opus-4-7', 'input_tokens' => 800, 'output_tokens' => 150, 'estimated_cost_usd' => 567.25],
        ]));

        $previousLocale = setlocale(\LC_NUMERIC, '0');
        setlocale(\LC_NUMERIC, 'de_DE.UTF-8');

        try {
            $this->auditPresenter->dryRunResult($symfonyStyle, $auditReport);
        } finally {
            setlocale(\LC_NUMERIC, false !== $previousLocale ? $previousLocale : 'C');
        }

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('1234.5000', $display);
        self::assertStringContainsString('567.2500', $display);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_dry_run_result_formats_costs_to_exactly_four_decimal_places(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext, AuditCost::of(1000, 200, 0.0123, 'claude-opus-4-7', [
            'attacker' => ['model' => 'claude-opus-4-7', 'input_tokens' => 800, 'output_tokens' => 150, 'estimated_cost_usd' => 0.0456],
        ]));

        $this->auditPresenter->dryRunResult($symfonyStyle, $auditReport);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('$0.0123 (estimate)', $display);
        self::assertStringNotContainsString('0.01230', $display);
        self::assertStringNotContainsString('0.04560', $display);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_scanned_files_lists_each_file_grouped_by_type(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->scannedFiles($symfonyStyle, [
            ProjectFile::create('src/Controller/HomeController.php', '/p/src/Controller/HomeController.php', '<?php class HomeController {}'),
            ProjectFile::create('config/packages/security.yaml', '/p/config/packages/security.yaml', 'security:'),
        ]);

        $flattened = preg_replace('/\s+/', ' ', $bufferedOutput->fetch()) ?? '';
        self::assertStringContainsString('Scanned files (2)', $flattened);
        self::assertStringContainsString('controller (1)', $flattened);
        self::assertStringContainsString('src/Controller/HomeController.php', $flattened);
        self::assertStringContainsString('config (1)', $flattened);
        self::assertStringContainsString('config/packages/security.yaml', $flattened);
        self::assertStringContainsString('2 file(s) in scope.', $flattened);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_scanned_files_labels_the_generic_php_bucket_as_uncategorized(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->scannedFiles($symfonyStyle, [
            ProjectFile::create('src/Utility/Helper.php', '/p/src/Utility/Helper.php', '<?php class Helper {}'),
        ]);

        $flattened = preg_replace('/\s+/', ' ', $bufferedOutput->fetch()) ?? '';
        self::assertStringContainsString('php · uncategorized (1)', $flattened);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_scanned_files_labels_the_generic_other_bucket_as_uncategorized(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->scannedFiles($symfonyStyle, [
            ProjectFile::create('README.md', '/p/README.md', '# readme'),
        ]);

        $flattened = preg_replace('/\s+/', ' ', $bufferedOutput->fetch()) ?? '';
        self::assertStringContainsString('other · uncategorized (1)', $flattened);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_scanned_files_renders_the_uncategorized_php_and_other_buckets_last(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->scannedFiles($symfonyStyle, [
            ProjectFile::create('src/Utility/Helper.php', '/p/src/Utility/Helper.php', '<?php class Helper {}'),
            ProjectFile::create('README.md', '/p/README.md', '# readme'),
            ProjectFile::create('src/Controller/HomeController.php', '/p/src/Controller/HomeController.php', '<?php class HomeController {}'),
        ]);

        $flattened = $bufferedOutput->fetch();
        $controllerPosition = mb_strpos($flattened, 'controller (1)');
        $phpPosition = mb_strpos($flattened, 'php · uncategorized (1)');
        $otherPosition = mb_strpos($flattened, 'other · uncategorized (1)');

        self::assertIsInt($controllerPosition);
        self::assertIsInt($phpPosition);
        self::assertIsInt($otherPosition);
        self::assertLessThan($phpPosition, $controllerPosition);
        self::assertLessThan($otherPosition, $phpPosition);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_scanned_files_does_not_render_a_crafted_file_path_as_console_markup(): void
    {
        $bufferedOutput = new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL, true);
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->scannedFiles($symfonyStyle, [
            ProjectFile::create('src/PwnController<fg=grey>.php', '/p/src/PwnController<fg=grey>.php', '<?php'),
        ]);

        self::assertStringContainsString('src/PwnController<fg=grey>.php', $bufferedOutput->fetch());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_scanned_files_strips_control_characters_from_a_crafted_file_path(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->scannedFiles($symfonyStyle, [
            ProjectFile::create("src/Evil.php\n * [CRITICAL] forged\x1b[31m\u{202E}x", '/p/src/Evil.php', '<?php'),
        ]);
        $output = $bufferedOutput->fetch();

        self::assertStringNotContainsString("\x1b", $output);
        self::assertStringNotContainsString("\u{202E}", $output);
        self::assertDoesNotMatchRegularExpression('/\n\s*\* \[CRITICAL] forged/', $output);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_scanned_files_reports_the_file_count_as_a_light_line_not_a_boxed_block(): void
    {
        $bufferedOutput = new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL, true);
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->scannedFiles($symfonyStyle, [
            ProjectFile::create('src/Controller/HomeController.php', '/p/src/Controller/HomeController.php', '<?php class HomeController {}'),
        ]);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('✅ 1 file(s) in scope.', $display);
        self::assertStringNotContainsString('[OK]', $display);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_scanned_files_omits_the_emoji_when_not_decorated(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->scannedFiles($symfonyStyle, [
            ProjectFile::create('src/Controller/HomeController.php', '/p/src/Controller/HomeController.php', '<?php class HomeController {}'),
        ]);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('1 file(s) in scope.', $display);
        self::assertStringNotContainsString('✅', $display);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_scanned_files_leaves_a_blank_line_after_the_file_count_line(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->scannedFiles($symfonyStyle, [
            ProjectFile::create('src/Controller/HomeController.php', '/p/src/Controller/HomeController.php', '<?php class HomeController {}'),
        ]);

        self::assertStringEndsWith("1 file(s) in scope.\n\n", $bufferedOutput->fetch());
    }

    public function test_scanned_files_warns_when_nothing_matched(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->scannedFiles($symfonyStyle, []);

        $flattened = preg_replace('/\s+/', ' ', $bufferedOutput->fetch()) ?? '';
        self::assertStringContainsString('No files matched.', $flattened);
        self::assertStringContainsString('included_paths', $flattened);
        self::assertStringNotContainsString('file(s) in scope', $flattened);
    }

    public function test_scanned_files_hint_points_to_the_flag_with_the_file_count(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->scannedFilesHint($symfonyStyle, 7);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('--show-scanned', $display);
        self::assertStringContainsString('7 file(s)', $display);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_unsupported_model_warning_names_every_unsupported_model(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->unsupportedModelWarnings($symfonyStyle, $this->reportWithRoleModels('made-up-attacker-model', 'made-up-reviewer-model'));

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('made-up-attacker-model', $display);
        self::assertStringContainsString('made-up-reviewer-model', $display);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_unsupported_model_warning_ignores_supported_models(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->unsupportedModelWarnings($symfonyStyle, $this->reportWithRoleModels('made-up-attacker-model', 'claude-opus-4-7'));

        self::assertStringNotContainsString('claude-opus-4-7', $bufferedOutput->fetch());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_unsupported_model_warning_is_silent_when_all_models_supported(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->unsupportedModelWarnings($symfonyStyle, $this->reportWithRoleModels('claude-opus-4-7', 'claude-haiku-4-5-20251001'));

        self::assertSame('', $bufferedOutput->fetch());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_unsupported_model_warning_is_silent_when_no_models_present(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->unsupportedModelWarnings($symfonyStyle, AuditReport::fromContext(AuditContext::forProject($this->tmpDir)));

        self::assertSame('', $bufferedOutput->fetch());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_unsupported_model_warning_names_a_shared_model_only_once(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->unsupportedModelWarnings($symfonyStyle, $this->reportWithRoleModels('made-up-model', 'made-up-model'));

        self::assertSame(1, substr_count($bufferedOutput->fetch(), 'made-up-model'));
    }

    /**
     * @throws InvalidAuditCostException
     * @throws InvalidAuditContextException
     */
    private function reportWithRoleModels(string $attackerModel, string $reviewerModel): AuditReport
    {
        $auditCost = AuditCost::of(1000, 200, 0.0, $attackerModel, [
            'attacker' => ['model' => $attackerModel, 'input_tokens' => 800, 'output_tokens' => 150, 'estimated_cost_usd' => 0.0],
            'reviewer' => ['model' => $reviewerModel, 'input_tokens' => 200, 'output_tokens' => 50, 'estimated_cost_usd' => 0.0],
        ]);

        return AuditReport::fromContext(AuditContext::forProject($this->tmpDir), $auditCost);
    }

    private function pricingProviderKnowing(string ...$supportedModels): PricingProviderInterface
    {
        return new class($supportedModels) implements PricingProviderInterface {
            /** @param array<string> $supportedModels */
            public function __construct(private array $supportedModels) {}

            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return \in_array($model, $this->supportedModels, true);
            }
        };
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeSingleVulnerabilityReport(): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability(
            Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'Critical vuln', 0.9),
                new CodeLocation('src/File.php', 1, 5),
                new VulnerabilityNarrative('desc', 'inject', "' OR 1", 'fix'),
                '$q',
            )->withReviewerValidation(true),
        );

        return AuditReport::fromContext($auditContext);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeCriticalReport(): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        for ($i = 1; $i <= 5; ++$i) {
            $auditContext->addVulnerability(
                Vulnerability::of(
                    new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'Critical vuln '.$i, 0.9),
                    new CodeLocation('src/File'.$i.'.php', 1, 5),
                    new VulnerabilityNarrative('desc', 'inject', "' OR 1", 'fix'),
                    '$q',
                )->withReviewerValidation(true),
            );
        }

        return AuditReport::fromContext($auditContext);
    }

    /**
     * One MEDIUM finding scores 5, so risk is LOW and the normalized score is
     * 95 — the shape a `--min-score=96` run fails on while the risk gate passes.
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeLowRiskReport(): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability(
            Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::MEDIUM, 'Medium vuln', 0.9),
                new CodeLocation('src/File.php', 1, 5),
                new VulnerabilityNarrative('desc', 'inject', "' OR 1", 'fix'),
                '$q',
            )->withReviewerValidation(true),
        );

        return AuditReport::fromContext($auditContext);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeHighRiskReport(): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        for ($i = 1; $i <= 5; ++$i) {
            $auditContext->addVulnerability(
                Vulnerability::of(
                    new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'High vuln '.$i, 0.9),
                    new CodeLocation('src/File'.$i.'.php', 1, 5),
                    new VulnerabilityNarrative('desc', 'inject', "' OR 1", 'fix'),
                    '$q',
                )->withReviewerValidation(true),
            );
        }

        return AuditReport::fromContext($auditContext);
    }
}
