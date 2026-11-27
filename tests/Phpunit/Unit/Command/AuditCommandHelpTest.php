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
use ReflectionClass;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommandHelp;
use VinceAmstoutz\SymfonySecurityAuditor\Command\OutputFormat;

final class AuditCommandHelpTest extends TestCase
{
    private const string BUNDLE_CONFIGURATION = 'via <info>config/packages/symfony_security_auditor.yaml</info>.';

    private const string STANDALONE_CONFIGURATION = "via the <info>config.yaml</info> <info>init</info> writes, or a <info>.symfony-security-auditor.yaml</info>\nin the folder you run from or in the project.";

    private const string CONFIGURATION = '<configuration>';

    private const int HELP_LINE_DESCRIPTION_WIDTH = 70;

    private const int HELP_LINE_WIDTH = 100;

    #[DataProvider('outputFormats')]
    public function test_the_help_lists_every_output_format(OutputFormat $outputFormat): void
    {
        self::assertMatchesRegularExpression($this->standaloneWord($outputFormat), AuditCommandHelp::HELP);
    }

    public function test_exit_code_two_documentation_covers_the_preflight_unpriced_model_abort_with_no_report_emitted(): void
    {
        self::assertStringContainsString('or an unpriced model made the cost budget unenforceable and the run never started (no report)', $this->flattened());
    }

    public function test_exit_code_two_documentation_still_covers_the_mid_run_budget_abort_with_a_partial_report(): void
    {
        self::assertStringContainsString('2 a token or cost budget stopped the run (partial report)', $this->flattened());
    }

    public function test_exit_code_one_documentation_covers_a_run_with_no_verdict(): void
    {
        self::assertStringContainsString('or no verdict: no file found, or none analyzed and no finding', $this->flattened());
    }

    public function test_the_baseline_example_says_baselined_findings_leave_the_exit_code_alone(): void
    {
        self::assertStringContainsString('--baseline=baseline.json then report and gate on new ones only', $this->flattened());
    }

    public function test_exit_code_zero_documentation_says_a_generated_baseline_does_not_fail_on_findings(): void
    {
        self::assertStringContainsString('or --generate-baseline wrote its baseline, whatever the findings', $this->flattened());
    }

    public function test_exit_code_three_documentation_does_not_claim_a_run_with_no_verdict_passes_without_the_option(): void
    {
        self::assertStringContainsString('3 --fail-on-incomplete and some file could not be fully analyzed; without it, a warning', $this->flattened());
    }

    public function test_the_output_documentation_names_the_flag_that_prints_a_configured_report(): void
    {
        self::assertStringContainsString('--no-output prints the report when audit.output names a file', $this->flattened());
    }

    public function test_the_format_option_shows_no_default_of_its_own_since_audit_format_supplies_it(): void
    {
        $inputOption = $this->auditCommandOption('format');

        self::assertNull($inputOption->getDefault());
        self::assertSame('Report format; the list and its default are below', $inputOption->getDescription());
    }

    public function test_the_help_says_the_output_extension_picks_the_format_when_none_is_chosen(): void
    {
        self::assertStringContainsString('Without --format, audit.format sets it, else the --output extension: .html, .json, .sarif, .md, .xml (junit), else console. A name without one is deprecated.', $this->flattened());
    }

    public function test_the_min_score_option_names_the_configuration_key_it_overrides(): void
    {
        self::assertStringEndsWith('(overrides audit.min_score)', $this->auditCommandOption('min-score')->getDescription());
    }

    public function test_the_output_option_names_the_configuration_key_it_overrides(): void
    {
        self::assertSame('Write the report to this file (overrides audit.output)', $this->auditCommandOption('output')->getDescription());
    }

    public function test_the_bundle_help_names_the_bundle_configuration_file(): void
    {
        self::assertStringContainsString(self::BUNDLE_CONFIGURATION, AuditCommandHelp::HELP);
    }

    public function test_the_standalone_help_names_the_standalone_configuration_files_instead(): void
    {
        self::assertStringContainsString(self::STANDALONE_CONFIGURATION, AuditCommandHelp::standalone());
        self::assertStringNotContainsString('config/packages/', AuditCommandHelp::standalone());
    }

    public function test_every_argument_and_option_of_its_own_fits_one_help_line(): void
    {
        $inputDefinition = (new Command(null, (new ReflectionClass(AuditCommand::class))->newInstanceWithoutConstructor()))->getDefinition();
        $descriptions = array_map(
            static fn (InputArgument|InputOption $input): string => $input->getDescription(),
            [...$inputDefinition->getArguments(), ...$inputDefinition->getOptions()],
        );

        self::assertSame([], array_filter($descriptions, static fn (string $description): bool => mb_strlen($description) > self::HELP_LINE_DESCRIPTION_WIDTH));
    }

    public function test_no_line_of_the_help_is_wider_than_a_terminal(): void
    {
        $lines = explode("\n", strip_tags(AuditCommandHelp::standalone()));

        self::assertSame([], array_filter($lines, static fn (string $line): bool => mb_strlen($line) > self::HELP_LINE_WIDTH));
    }

    public function test_the_standalone_help_is_the_bundle_help_with_only_the_configuration_files_swapped(): void
    {
        self::assertSame(
            str_replace(self::BUNDLE_CONFIGURATION, self::CONFIGURATION, AuditCommandHelp::HELP),
            str_replace(self::STANDALONE_CONFIGURATION, self::CONFIGURATION, AuditCommandHelp::standalone()),
        );
    }

    /**
     * @return iterable<string, array{OutputFormat}>
     */
    public static function outputFormats(): iterable
    {
        foreach (OutputFormat::cases() as $outputFormat) {
            yield $outputFormat->value => [$outputFormat];
        }
    }

    private function standaloneWord(OutputFormat $outputFormat): string
    {
        return \sprintf('/(?<![\w-])%s(?![\w-])/', preg_quote($outputFormat->value, '/'));
    }

    private function auditCommandOption(string $name): InputOption
    {
        return (new Command(null, (new ReflectionClass(AuditCommand::class))->newInstanceWithoutConstructor()))->getDefinition()->getOption($name);
    }

    private function flattened(): string
    {
        return (string) preg_replace('/\s+/', ' ', strip_tags(AuditCommandHelp::HELP));
    }
}
