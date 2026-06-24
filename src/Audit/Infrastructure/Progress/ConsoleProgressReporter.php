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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * Renders an animated Symfony ProgressBar to a decorated (TTY) console.
 *
 * The pipeline events drive the bar itself: pipeline.started creates a bar
 * sized to the stage count, stage.started/audit.iteration.started/
 * attacker.chunk.started/review.started refresh its message (the chunk message
 * reads "⏳ querying model …" so a slow model call reads as waiting, not hung),
 * stage.completed advances it, and pipeline.completed finishes it. The audit
 * narrative is printed as lines above the bar: audit.started (attack-surface
 * overview), attacker.finding.recorded (each finding as it is flagged),
 * attacker.chunk.completed (each chunk with its elapsed time), and
 * review.completed (the reviewer tally). Unhandled events are ignored. The
 * non-decorated counterpart is PlainProgressReporter.
 *
 * Mutable because ProgressBar is stateful (tracks current step, format, and
 * output position).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class ConsoleProgressReporter implements ProgressReporterInterface
{
    private ?ProgressBar $progressBar = null;

    private string $stageName = '';

    private string $iterationLabel = '';

    private int $reviewTotal = 0;

    private int $reviewedCount = 0;

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
            ProgressEvent::AuditStarted => $this->onAuditStarted($context),
            ProgressEvent::AuditIterationStarted => $this->onAuditIterationStarted($context),
            ProgressEvent::AttackerChunkStarted => $this->onAttackerChunkStarted($context),
            ProgressEvent::AttackerChunkCompleted => $this->onAttackerChunkCompleted($context),
            ProgressEvent::AttackerFindingRecorded => $this->onAttackerFindingRecorded($context),
            ProgressEvent::ReviewStarted => $this->onReviewStarted($context),
            ProgressEvent::ReviewFindingReviewed => $this->onReviewFindingReviewed($context),
            ProgressEvent::ReviewCompleted => $this->onReviewCompleted($context),
            null => null,
        };
    }

    /** @param array<string, mixed> $context */
    private function onPipelineStarted(array $context): void
    {
        $stages = \is_array($context['stages'] ?? null) ? $context['stages'] : [];
        $this->progressBar = new ProgressBar($this->output, \count($stages));
        $this->progressBar->setFormat(' %current%/%max% [%bar%] %percent:3s%% %elapsed:6s% — %message%');
        $this->progressBar->setMessage('starting…');
        $this->progressBar->start();
    }

    /** @param array<string, mixed> $context */
    private function onAuditStarted(array $context): void
    {
        $this->writeAboveBar(\sprintf('<fg=cyan>🔍 %s</>', AuditOverviewLine::from($context)));
    }

    /** @param array<string, mixed> $context */
    private function onAttackerFindingRecorded(array $context): void
    {
        $severity = ProgressContext::string($context, 'severity');
        $severityEnum = VulnerabilitySeverity::tryFrom($severity);
        $label = $severityEnum?->label() ?? strtoupper($severity);

        $line = \sprintf(
            '  ⚔ %s %s — %s:%d',
            $label,
            ProgressContext::string($context, 'type'),
            ProgressContext::string($context, 'file'),
            ProgressContext::int($context, 'line'),
        );

        if ($severityEnum instanceof VulnerabilitySeverity) {
            $line = \sprintf('<fg=%s>%s</>', SeverityColor::for($severityEnum), $line);
        }

        $this->writeAboveBar($line);
    }

    /** @param array<string, mixed> $context */
    private function onReviewCompleted(array $context): void
    {
        $this->writeAboveBar(\sprintf(
            '<fg=green>  ✓ Reviewed: %d validated, %d rejected</>',
            ProgressContext::int($context, 'accepted'),
            ProgressContext::int($context, 'rejected'),
        ));
    }

    private function writeAboveBar(string $line): void
    {
        if (!$this->progressBar instanceof ProgressBar) {
            return;
        }

        $this->progressBar->clear();
        $this->output->writeln($line);
        $this->progressBar->display();
    }

    /** @param array<string, mixed> $context */
    private function onStageStarted(array $context): void
    {
        $this->stageName = \is_string($context['stage'] ?? null) ? $context['stage'] : '';
        $this->iterationLabel = '';
        $this->updateMessage();
    }

    /** @param array<string, mixed> $context */
    private function onAuditIterationStarted(array $context): void
    {
        $iteration = $context['iteration'] ?? null;
        $maxIterations = $context['max_iterations'] ?? null;

        if (!\is_int($iteration) || !\is_int($maxIterations)) {
            return;
        }

        $this->iterationLabel = \sprintf('iteration %d/%d', $iteration, $maxIterations);
        $this->updateMessage();
    }

    /** @param array<string, mixed> $context */
    private function onAttackerChunkStarted(array $context): void
    {
        $chunk = $context['chunk'] ?? null;
        $totalChunks = $context['total_chunks'] ?? null;

        if (!\is_int($chunk) || !\is_int($totalChunks)) {
            return;
        }

        $this->updateMessage(\sprintf('⏳ querying model · chunk %d/%d', $chunk, $totalChunks));
    }

    /** @param array<string, mixed> $context */
    private function onAttackerChunkCompleted(array $context): void
    {
        $chunk = $context['chunk'] ?? null;
        $totalChunks = $context['total_chunks'] ?? null;

        if (!\is_int($chunk) || !\is_int($totalChunks)) {
            return;
        }

        $this->writeAboveBar(\sprintf(
            '<fg=green>  ✓ chunk %d/%d analyzed%s</>',
            $chunk,
            $totalChunks,
            ProgressContext::durationSuffix($context, 'elapsed_seconds'),
        ));
    }

    /** @param array<string, mixed> $context */
    private function onReviewStarted(array $context): void
    {
        $findings = $context['findings'] ?? null;

        if (!\is_int($findings)) {
            return;
        }

        $this->reviewTotal = $findings;
        $this->reviewedCount = 0;
        $this->updateMessage(\sprintf('reviewing %d finding(s)', $findings));
    }

    /** @param array<string, mixed> $context */
    private function onReviewFindingReviewed(array $context): void
    {
        ++$this->reviewedCount;

        $accepted = true === ($context['accepted'] ?? null);

        $line = \sprintf(
            '  ⚖ %s %s — %s:%d',
            $accepted ? '✓ validated' : '✗ rejected',
            ProgressContext::string($context, 'type'),
            ProgressContext::string($context, 'file'),
            ProgressContext::int($context, 'line'),
        );

        $this->writeAboveBar(\sprintf('<fg=%s>%s</>', $accepted ? 'green' : 'yellow', $line));
        $this->updateMessage(\sprintf('reviewing %d/%d', $this->reviewedCount, $this->reviewTotal));
    }

    private function updateMessage(string $detail = ''): void
    {
        $parts = array_filter(
            [$this->stageName, $this->iterationLabel, $detail],
            static fn (string $part): bool => '' !== $part,
        );

        $this->progressBar?->setMessage(implode(' · ', $parts));
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
