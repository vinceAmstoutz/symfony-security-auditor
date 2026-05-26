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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress;

use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Output\OutputInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProgressEvent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * Renders a Symfony ProgressBar to the console.
 *
 * Driven by the four pipeline events emitted by AuditPipeline:
 *   pipeline.started  → creates and starts a bar sized to stage count
 *   stage.started     → updates the bar message to the current stage name
 *   stage.completed   → advances the bar by one step
 *   pipeline.completed → finishes the bar and writes a trailing newline
 *
 * All other events are silently ignored. Mutable because ProgressBar is
 * stateful (tracks current step, format, and output position).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class ConsoleProgressReporter implements ProgressReporterInterface
{
    private ?ProgressBar $progressBar = null;

    public function __construct(private readonly OutputInterface $output) {}

    /**
     * {@inheritDoc}
     */
    public function report(string $event, array $context = []): void
    {
        match (ProgressEvent::tryFrom($event)) {
            ProgressEvent::PipelineStarted => $this->onPipelineStarted($context),
            ProgressEvent::StageStarted => $this->onStageStarted($context),
            ProgressEvent::StageCompleted => $this->onStageCompleted(),
            ProgressEvent::PipelineCompleted => $this->onPipelineCompleted(),
            null => null,
        };
    }

    /** @param array<string, mixed> $context */
    private function onPipelineStarted(array $context): void
    {
        $stages = \is_array($context['stages'] ?? null) ? $context['stages'] : [];
        $this->progressBar = new ProgressBar($this->output, \count($stages));
        $this->progressBar->setFormat(' %current%/%max% [%bar%] %percent:3s%% — %message%');
        $this->progressBar->setMessage('starting…');
        $this->progressBar->start();
    }

    /** @param array<string, mixed> $context */
    private function onStageStarted(array $context): void
    {
        $this->progressBar?->setMessage(\is_string($context['stage'] ?? null) ? $context['stage'] : '');
        $this->progressBar?->display();
    }

    private function onStageCompleted(): void
    {
        $this->progressBar?->advance();
    }

    private function onPipelineCompleted(): void
    {
        if (!$this->progressBar instanceof ProgressBar) {
            return;
        }

        $this->progressBar->finish();
        $this->output->writeln('');
    }
}
