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
    private BufferedOutput $output;

    private ConsoleProgressReporter $reporter;

    public function test_it_renders_progress_bar_across_full_pipeline_lifecycle(): void
    {
        $this->reporter->report('pipeline.started', ['stages' => ['ingestion', 'mapping', 'audit']]);
        $this->reporter->report('stage.started', ['stage' => 'ingestion']);
        $this->reporter->report('stage.completed');
        $this->reporter->report('stage.started', ['stage' => 'mapping']);
        $this->reporter->report('stage.completed');
        $this->reporter->report('stage.started', ['stage' => 'audit']);
        $this->reporter->report('stage.completed');
        $this->reporter->report('pipeline.completed');

        $rendered = $this->output->fetch();

        self::assertStringContainsString('3/3', $rendered);
        self::assertStringContainsString('100%', $rendered);
    }

    public function test_it_shows_stage_name_in_progress_bar_message(): void
    {
        $this->reporter->report('pipeline.started', ['stages' => ['ingestion', 'mapping', 'audit']]);
        $this->reporter->report('stage.started', ['stage' => 'mapping']);

        self::assertStringContainsString('mapping', $this->output->fetch());
    }

    public function test_it_writes_trailing_newline_on_pipeline_completed(): void
    {
        $this->reporter->report('pipeline.started', ['stages' => ['ingestion']]);
        $this->reporter->report('stage.completed');
        $this->reporter->report('pipeline.completed');

        self::assertStringEndsWith("\n", $this->output->fetch());
    }

    public function test_it_ignores_unknown_events(): void
    {
        $this->reporter->report('some.unknown.event', ['foo' => 'bar']);

        self::assertSame('', $this->output->fetch());
    }

    public function test_stage_events_before_pipeline_started_are_no_ops(): void
    {
        $this->reporter->report('stage.started', ['stage' => 'ingestion']);
        $this->reporter->report('stage.completed');
        $this->reporter->report('pipeline.completed');

        self::assertSame('', $this->output->fetch());
    }

    public function test_it_sizes_bar_to_stage_count(): void
    {
        $this->reporter->report('pipeline.started', ['stages' => ['a', 'b']]);
        $this->reporter->report('stage.completed');
        $this->reporter->report('stage.completed');
        $this->reporter->report('pipeline.completed');

        self::assertStringContainsString('2/2', $this->output->fetch());
    }

    public function test_it_handles_missing_stages_context_gracefully(): void
    {
        $this->reporter->report('pipeline.started', []);
        $this->reporter->report('pipeline.completed');

        self::assertStringContainsString('0/0', $this->output->fetch());
    }

    public function test_it_handles_missing_stage_name_gracefully(): void
    {
        $this->reporter->report('pipeline.started', ['stages' => ['ingestion']]);
        $this->reporter->report('stage.started', []);

        $rendered = $this->output->fetch();
        self::assertNotEmpty($rendered);
    }

    protected function setUp(): void
    {
        $this->output = new BufferedOutput();
        $this->reporter = new ConsoleProgressReporter($this->output);
    }
}
