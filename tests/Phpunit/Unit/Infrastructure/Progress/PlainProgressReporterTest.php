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

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\PlainProgressReporter;

final class PlainProgressReporterTest extends TestCase
{
    private BufferedOutput $bufferedOutput;

    private PlainProgressReporter $plainProgressReporter;

    public function test_it_prints_an_audit_overview_line(): void
    {
        $this->plainProgressReporter->report('audit.started', ['files' => 4, 'controllers' => 2, 'voters' => 1, 'forms' => 3]);

        self::assertSame(
            "Auditing 4 file(s) — 2 controller(s), 1 voter(s), 3 form(s)\n",
            $this->bufferedOutput->fetch(),
        );
    }

    public function test_it_omits_zero_count_categories_from_the_overview(): void
    {
        $this->plainProgressReporter->report('audit.started', ['files' => 21, 'controllers' => 15, 'voters' => 0, 'forms' => 0]);

        self::assertSame("Auditing 21 file(s) — 15 controller(s)\n", $this->bufferedOutput->fetch());
    }

    public function test_it_defaults_missing_overview_counts_to_zero(): void
    {
        $this->plainProgressReporter->report('audit.started', []);

        self::assertSame("Auditing 0 file(s)\n", $this->bufferedOutput->fetch());
    }

    public function test_it_prints_an_iteration_header(): void
    {
        $this->plainProgressReporter->report('audit.iteration.started', ['iteration' => 1, 'max_iterations' => 3]);

        self::assertSame("Iteration 1/3\n", $this->bufferedOutput->fetch());
    }

    public function test_it_prints_a_chunk_heartbeat(): void
    {
        $this->plainProgressReporter->report('attacker.chunk.started', ['chunk' => 2, 'total_chunks' => 5]);

        self::assertSame("  Analyzing chunk 2/5\n", $this->bufferedOutput->fetch());
    }

    public function test_it_prints_a_chunk_completion_with_duration(): void
    {
        $this->plainProgressReporter->report('attacker.chunk.completed', ['chunk' => 1, 'total_chunks' => 3, 'elapsed_seconds' => 47.0]);

        self::assertSame("  ✓ chunk 1/3 done (47s)\n", $this->bufferedOutput->fetch());
    }

    public function test_it_omits_duration_for_a_sub_second_chunk_completion(): void
    {
        $this->plainProgressReporter->report('attacker.chunk.completed', ['chunk' => 2, 'total_chunks' => 3, 'elapsed_seconds' => 0.0]);

        self::assertSame("  ✓ chunk 2/3 done\n", $this->bufferedOutput->fetch());
    }

    public function test_it_streams_each_recorded_finding(): void
    {
        $this->plainProgressReporter->report('attacker.finding.recorded', ['severity' => 'high', 'type' => 'sql_injection', 'file' => 'src/X.php', 'line' => 42]);

        self::assertSame("  [HIGH] sql_injection — src/X.php:42\n", $this->bufferedOutput->fetch());
    }

    public function test_it_defaults_missing_finding_strings_to_empty(): void
    {
        $this->plainProgressReporter->report('attacker.finding.recorded', ['line' => 7]);

        self::assertSame("  []  — :7\n", $this->bufferedOutput->fetch());
    }

    public function test_it_prints_review_start(): void
    {
        $this->plainProgressReporter->report('review.started', ['findings' => 3]);

        self::assertSame("Reviewing 3 finding(s)…\n", $this->bufferedOutput->fetch());
    }

    public function test_it_prints_review_summary(): void
    {
        $this->plainProgressReporter->report('review.completed', ['accepted' => 2, 'rejected' => 1]);

        self::assertSame("  2 validated, 1 rejected\n", $this->bufferedOutput->fetch());
    }

    public function test_it_ignores_pipeline_and_stage_events(): void
    {
        $this->plainProgressReporter->report('pipeline.started', ['stages' => ['ingestion']]);
        $this->plainProgressReporter->report('stage.started', ['stage' => 'ingestion']);
        $this->plainProgressReporter->report('stage.completed');
        $this->plainProgressReporter->report('pipeline.completed');

        self::assertSame('', $this->bufferedOutput->fetch());
    }

    public function test_it_ignores_unknown_events(): void
    {
        $this->plainProgressReporter->report('some.unknown.event', ['foo' => 'bar']);

        self::assertSame('', $this->bufferedOutput->fetch());
    }

    public function test_it_prints_a_validated_review_line(): void
    {
        $this->plainProgressReporter->report('review.finding.reviewed', ['accepted' => true, 'type' => 'sql_injection', 'file' => 'src/X.php', 'line' => 18]);

        self::assertSame("  [VALIDATED] sql_injection — src/X.php:18\n", $this->bufferedOutput->fetch());
    }

    public function test_it_prints_a_rejected_review_line(): void
    {
        $this->plainProgressReporter->report('review.finding.reviewed', ['accepted' => false, 'type' => 'sql_injection', 'file' => 'src/X.php', 'line' => 40]);

        self::assertSame("  [REJECTED] sql_injection — src/X.php:40\n", $this->bufferedOutput->fetch());
    }

    public function test_it_never_emits_carriage_returns(): void
    {
        $this->plainProgressReporter->report('audit.started', ['files' => 1, 'controllers' => 1, 'voters' => 0, 'forms' => 0]);
        $this->plainProgressReporter->report('attacker.finding.recorded', ['severity' => 'high', 'type' => 'xss', 'file' => 'a.php', 'line' => 1]);

        self::assertStringNotContainsString("\r", $this->bufferedOutput->fetch());
    }

    #[Override]
    protected function setUp(): void
    {
        $this->bufferedOutput = new BufferedOutput();
        $this->plainProgressReporter = new PlainProgressReporter($this->bufferedOutput);
    }
}
