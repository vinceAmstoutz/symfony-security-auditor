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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Progress;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ConsoleProgressReporter;

final class ConsoleProgressReporterTest extends TestCase
{
    private BufferedOutput $bufferedOutput;

    private ConsoleProgressReporter $consoleProgressReporter;

    public function test_it_renders_progress_bar_across_full_pipeline_lifecycle(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['ingestion', 'mapping', 'audit']]);
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'ingestion']);
        $this->consoleProgressReporter->report('stage.completed');
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'mapping']);
        $this->consoleProgressReporter->report('stage.completed');
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'audit']);
        $this->consoleProgressReporter->report('stage.completed');
        $this->consoleProgressReporter->report('pipeline.completed');

        $rendered = $this->bufferedOutput->fetch();

        self::assertStringContainsString('3/3', $rendered);
        self::assertStringContainsString('100%', $rendered);
    }

    public function test_it_shows_stage_name_in_progress_bar_message(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['ingestion', 'mapping', 'audit']]);
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'mapping']);

        self::assertStringContainsString('mapping', $this->bufferedOutput->fetch());
    }

    public function test_it_writes_trailing_newline_on_pipeline_completed(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['ingestion']]);
        $this->consoleProgressReporter->report('stage.completed');
        $this->consoleProgressReporter->report('pipeline.completed');

        self::assertStringEndsWith("\n", $this->bufferedOutput->fetch());
    }

    public function test_it_shows_starting_message_when_pipeline_starts(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['ingestion']]);

        self::assertStringContainsString('starting…', $this->bufferedOutput->fetch());
    }

    public function test_stage_completed_advances_progress_bar(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['a', 'b', 'c']]);
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'a']);
        $this->consoleProgressReporter->report('stage.completed');
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'b']);

        self::assertStringContainsString('1/3', $this->bufferedOutput->fetch());
    }

    public function test_pipeline_completed_forces_progress_bar_to_max(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['a', 'b', 'c']]);
        $this->consoleProgressReporter->report('stage.completed');

        $this->bufferedOutput->fetch();

        $this->consoleProgressReporter->report('pipeline.completed');

        self::assertStringContainsString('3/3', $this->bufferedOutput->fetch());
    }

    public function test_it_ignores_unknown_events(): void
    {
        $this->consoleProgressReporter->report('some.unknown.event', ['foo' => 'bar']);

        self::assertSame('', $this->bufferedOutput->fetch());
    }

    public function test_stage_events_before_pipeline_started_are_no_ops(): void
    {
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'ingestion']);
        $this->consoleProgressReporter->report('stage.completed');
        $this->consoleProgressReporter->report('pipeline.completed');

        self::assertSame('', $this->bufferedOutput->fetch());
    }

    public function test_it_sizes_bar_to_stage_count(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['a', 'b']]);
        $this->consoleProgressReporter->report('stage.completed');
        $this->consoleProgressReporter->report('stage.completed');
        $this->consoleProgressReporter->report('pipeline.completed');

        self::assertStringContainsString('2/2', $this->bufferedOutput->fetch());
    }

    public function test_it_handles_missing_stages_context_gracefully(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', []);
        $this->consoleProgressReporter->report('pipeline.completed');

        self::assertStringContainsString('0/0', $this->bufferedOutput->fetch());
    }

    public function test_it_handles_missing_stage_name_gracefully(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['ingestion']]);
        $this->consoleProgressReporter->report('stage.started', []);

        $rendered = $this->bufferedOutput->fetch();
        self::assertNotEmpty($rendered);
    }

    public function test_audit_iteration_event_shows_iteration_in_bar_message(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['ingestion', 'mapping', 'audit']]);
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'audit']);
        $this->consoleProgressReporter->report('audit.iteration.started', ['iteration' => 1, 'max_iterations' => 3]);

        self::assertStringContainsString('audit · iteration 1/3', $this->bufferedOutput->fetch());
    }

    public function test_attacker_chunk_event_shows_chunk_progress_in_bar_message(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['audit']]);
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'audit']);
        $this->consoleProgressReporter->report('audit.iteration.started', ['iteration' => 2, 'max_iterations' => 3]);
        $this->consoleProgressReporter->report('attacker.chunk.started', ['chunk' => 4, 'total_chunks' => 12]);

        self::assertStringContainsString('audit · iteration 2/3 · attacker chunk 4/12', $this->bufferedOutput->fetch());
    }

    public function test_review_event_shows_finding_count_in_bar_message(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['audit']]);
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'audit']);
        $this->consoleProgressReporter->report('audit.iteration.started', ['iteration' => 1, 'max_iterations' => 3]);
        $this->consoleProgressReporter->report('review.started', ['findings' => 4]);

        self::assertStringContainsString('audit · iteration 1/3 · reviewing 4 finding(s)', $this->bufferedOutput->fetch());
    }

    public function test_next_stage_clears_stale_iteration_label(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['audit', 'poc_synthesis']]);
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'audit']);
        $this->consoleProgressReporter->report('audit.iteration.started', ['iteration' => 1, 'max_iterations' => 3]);
        $this->consoleProgressReporter->report('stage.completed');

        $this->bufferedOutput->fetch();

        $this->consoleProgressReporter->report('stage.started', ['stage' => 'poc_synthesis']);

        $rendered = $this->bufferedOutput->fetch();
        self::assertStringContainsString('poc_synthesis', $rendered);
        self::assertStringNotContainsString('iteration', $rendered);
    }

    public function test_chunk_event_without_prior_iteration_omits_iteration_segment(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['audit']]);
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'audit']);
        $this->consoleProgressReporter->report('attacker.chunk.started', ['chunk' => 1, 'total_chunks' => 2]);

        self::assertStringContainsString('audit · attacker chunk 1/2', $this->bufferedOutput->fetch());
    }

    public function test_detail_events_with_malformed_context_keep_previous_message(): void
    {
        $this->consoleProgressReporter->report('pipeline.started', ['stages' => ['audit']]);
        $this->consoleProgressReporter->report('stage.started', ['stage' => 'audit']);

        $this->bufferedOutput->fetch();

        $this->consoleProgressReporter->report('audit.iteration.started', ['iteration' => 'one']);
        $this->consoleProgressReporter->report('attacker.chunk.started', ['chunk' => 1]);
        $this->consoleProgressReporter->report('review.started', []);

        self::assertSame('', $this->bufferedOutput->fetch());
    }

    public function test_detail_events_before_pipeline_started_are_no_ops(): void
    {
        $this->consoleProgressReporter->report('audit.iteration.started', ['iteration' => 1, 'max_iterations' => 3]);
        $this->consoleProgressReporter->report('attacker.chunk.started', ['chunk' => 1, 'total_chunks' => 2]);
        $this->consoleProgressReporter->report('review.started', ['findings' => 2]);

        self::assertSame('', $this->bufferedOutput->fetch());
    }

    protected function setUp(): void
    {
        $this->bufferedOutput = new BufferedOutput();
        $this->consoleProgressReporter = new ConsoleProgressReporter($this->bufferedOutput);
    }
}
