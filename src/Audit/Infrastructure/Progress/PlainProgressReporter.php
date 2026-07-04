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

use Override;
use Symfony\Component\Console\Output\OutputInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProgressEvent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * Append-only, line-oriented reporter for non-interactive output (CI logs,
 * pipes, redirected files). Emits one clean line per meaningful event — no
 * carriage returns, no cursor control, no progress bar — so the audit narrates
 * itself in environments where an animated ProgressBar would be noise. Streams
 * findings as the attacker records them, which also keeps the log alive on long
 * runs. The decorated counterpart is `ConsoleProgressReporter`.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlainProgressReporter implements ProgressReporterInterface
{
    public function __construct(private OutputInterface $output) {}

    /**
     * {@inheritDoc}
     */
    #[Override]
    public function report(string $event, array $context = []): void
    {
        match (ProgressEvent::tryFrom($event)) {
            ProgressEvent::AuditStarted => $this->output->writeln(AuditOverviewLine::from($context)),
            ProgressEvent::AuditIterationStarted => $this->output->writeln($this->iterationLine($context)),
            ProgressEvent::AttackerChunkStarted => $this->output->writeln($this->chunkLine($context)),
            ProgressEvent::AttackerChunkCompleted => $this->output->writeln($this->chunkDoneLine($context)),
            ProgressEvent::AttackerFindingRecorded => $this->output->writeln($this->findingLine($context)),
            ProgressEvent::ReviewStarted => $this->output->writeln($this->reviewStartLine($context)),
            ProgressEvent::ReviewFindingReviewed => $this->output->writeln($this->reviewedLine($context)),
            ProgressEvent::BaselineFindingSkipped => $this->output->writeln($this->baselineSkippedLine($context)),
            ProgressEvent::ReviewCompleted => $this->output->writeln($this->reviewSummaryLine($context)),
            default => null,
        };
    }

    /** @param array<string, mixed> $context */
    private function iterationLine(array $context): string
    {
        return \sprintf('Iteration %d/%d', ProgressContext::int($context, 'iteration'), ProgressContext::int($context, 'max_iterations'));
    }

    /** @param array<string, mixed> $context */
    private function chunkLine(array $context): string
    {
        return \sprintf('  Analyzing chunk %d/%d', ProgressContext::int($context, 'chunk'), ProgressContext::int($context, 'total_chunks'));
    }

    /** @param array<string, mixed> $context */
    private function chunkDoneLine(array $context): string
    {
        return \sprintf(
            '  ✓ chunk %d/%d done%s',
            ProgressContext::int($context, 'chunk'),
            ProgressContext::int($context, 'total_chunks'),
            ProgressContext::durationSuffix($context, 'elapsed_seconds'),
        );
    }

    /** @param array<string, mixed> $context */
    private function findingLine(array $context): string
    {
        return \sprintf(
            '  [%s] %s — %s:%d',
            strtoupper(ProgressContext::string($context, 'severity')),
            ProgressContext::string($context, 'type'),
            ProgressContext::string($context, 'file'),
            ProgressContext::int($context, 'line'),
        );
    }

    /** @param array<string, mixed> $context */
    private function reviewStartLine(array $context): string
    {
        return \sprintf('Reviewing %d finding(s)…', ProgressContext::int($context, 'findings'));
    }

    /** @param array<string, mixed> $context */
    private function baselineSkippedLine(array $context): string
    {
        return \sprintf(
            '  [BASELINE-SKIPPED] %s — %s:%d',
            ProgressContext::string($context, 'type'),
            ProgressContext::string($context, 'file'),
            ProgressContext::int($context, 'line'),
        );
    }

    /** @param array<string, mixed> $context */
    private function reviewedLine(array $context): string
    {
        return \sprintf(
            '  [%s] %s — %s:%d',
            true === ($context['accepted'] ?? null) ? 'VALIDATED' : 'REJECTED',
            ProgressContext::string($context, 'type'),
            ProgressContext::string($context, 'file'),
            ProgressContext::int($context, 'line'),
        );
    }

    /** @param array<string, mixed> $context */
    private function reviewSummaryLine(array $context): string
    {
        return \sprintf('  %d validated, %d rejected', ProgressContext::int($context, 'accepted'), ProgressContext::int($context, 'rejected'));
    }
}
