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
use ReflectionProperty;
use Symfony\Component\Console\Attribute\Option;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommandHelp;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommandInput;
use VinceAmstoutz\SymfonySecurityAuditor\Command\OutputFormat;

final class AuditCommandHelpTest extends TestCase
{
    #[DataProvider('outputFormats')]
    public function test_the_help_lists_every_output_format(OutputFormat $outputFormat): void
    {
        self::assertMatchesRegularExpression($this->standaloneWord($outputFormat), AuditCommandHelp::HELP);
    }

    #[DataProvider('outputFormats')]
    public function test_the_format_option_description_names_every_output_format(OutputFormat $outputFormat): void
    {
        $option = (new ReflectionProperty(AuditCommandInput::class, 'format'))->getAttributes(Option::class)[0]->newInstance();

        self::assertMatchesRegularExpression($this->standaloneWord($outputFormat), $option->description);
    }

    public function test_exit_code_two_documentation_covers_the_preflight_unpriced_model_abort_with_no_report_emitted(): void
    {
        self::assertStringContainsString('an unpriced model', AuditCommandHelp::HELP);
        self::assertStringContainsString('no report emitted in that case', AuditCommandHelp::HELP);
    }

    public function test_exit_code_two_documentation_still_covers_the_mid_run_budget_abort_with_a_partial_report(): void
    {
        self::assertStringContainsString('partial report still emitted', AuditCommandHelp::HELP);
    }

    public function test_exit_code_one_documentation_covers_a_run_with_no_verdict(): void
    {
        self::assertStringContainsString('or the run reached no verdict (its scan found no file, or it analyzed none and found nothing)', $this->flattened());
    }

    public function test_exit_code_three_documentation_does_not_claim_a_run_with_no_verdict_passes_without_the_option(): void
    {
        self::assertStringContainsString('without the option, a run that analyzed some of its files or holds a finding keeps the code its gates earn and prints a warning', $this->flattened());
    }

    public function test_the_output_documentation_names_the_flag_that_prints_a_configured_report(): void
    {
        self::assertStringContainsString('switched off for one run by --no-output, which prints the report', $this->flattened());
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

    private function flattened(): string
    {
        return (string) preg_replace('/\s+/', ' ', strip_tags(AuditCommandHelp::HELP));
    }
}
