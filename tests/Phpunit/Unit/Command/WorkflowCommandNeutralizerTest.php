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
use VinceAmstoutz\SymfonySecurityAuditor\Command\OutputFormat;
use VinceAmstoutz\SymfonySecurityAuditor\Command\WorkflowCommandNeutralizer;

final class WorkflowCommandNeutralizerTest extends TestCase
{
    private const string REPORT = "report\n    ::error::forged ##[warning]x\n";

    public function test_it_leaves_a_report_and_a_message_alone_outside_github_actions(): void
    {
        $workflowCommandNeutralizer = new WorkflowCommandNeutralizer(false);

        self::assertSame(self::REPORT, $workflowCommandNeutralizer->report(OutputFormat::Console, self::REPORT));
        self::assertSame('Unexpected error: a ::error::x', $workflowCommandNeutralizer->message('Unexpected error: a ::error::x'));
    }

    /**
     * @return iterable<string, array{OutputFormat, string}>
     */
    public static function reportsOnARunner(): iterable
    {
        yield 'the console report' => [OutputFormat::Console, "report\n    :\\:error::forged #\\#[warning]x\n"];
        yield 'the executive summary' => [OutputFormat::Executive, "report\n    :\\:error::forged #\\#[warning]x\n"];
        yield 'the Markdown report' => [OutputFormat::Markdown, "report\n    :\\:error::forged #\\#[warning]x\n"];
        yield 'the pull-request comment' => [OutputFormat::GithubComment, "report\n    :\\:error::forged #\\#[warning]x\n"];
        yield 'the JUnit report' => [OutputFormat::Junit, "report\n    :\\:error::forged #\\#[warning]x\n"];
        yield 'the HTML report' => [OutputFormat::Html, "report\n    :\\:error::forged #\\#[warning]x\n"];
        yield 'the JSON report' => [OutputFormat::Json, "report\n    ::error::forged #\\u0023[warning]x\n"];
        yield 'the SARIF report' => [OutputFormat::Sarif, "report\n    ::error::forged #\\u0023[warning]x\n"];
        yield 'the annotations meant for the runner' => [OutputFormat::GithubAnnotations, self::REPORT];
    }

    #[DataProvider('reportsOnARunner')]
    public function test_a_report_printed_on_a_runner_has_its_workflow_commands_defused_as_its_format_allows(OutputFormat $outputFormat, string $defused): void
    {
        self::assertSame($defused, (new WorkflowCommandNeutralizer(true))->report($outputFormat, self::REPORT));
    }

    public function test_a_message_printed_on_a_runner_has_every_workflow_command_defused(): void
    {
        self::assertSame('Unexpected error: a :\\:error:\\:x', (new WorkflowCommandNeutralizer(true))->message('Unexpected error: a ::error::x'));
    }

    /**
     * @return iterable<string, array{string|false, bool}>
     */
    public static function environments(): iterable
    {
        yield 'a GitHub Actions runner' => ['true', true];
        yield 'another CI declaring the variable false' => ['false', false];
        yield 'a terminal without the variable' => [false, false];
    }

    #[DataProvider('environments')]
    public function test_it_defuses_only_on_a_github_actions_runner(string|false $githubActions, bool $defused): void
    {
        $previous = getenv('GITHUB_ACTIONS');
        putenv(false === $githubActions ? 'GITHUB_ACTIONS' : \sprintf('GITHUB_ACTIONS=%s', $githubActions));

        try {
            $message = WorkflowCommandNeutralizer::fromEnvironment()->message('a ::error::x');
        } finally {
            putenv(false === $previous ? 'GITHUB_ACTIONS' : \sprintf('GITHUB_ACTIONS=%s', $previous));
        }

        self::assertSame($defused, 'a ::error::x' !== $message);
    }
}
