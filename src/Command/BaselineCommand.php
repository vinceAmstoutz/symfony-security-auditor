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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\TerminalTextSanitizer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedBaselineFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;

use function Symfony\Component\String\u;

#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
/** @internal not part of the BC promise — the command *name* (`audit:baseline`) is public, but the PHP class itself is for internal use only. */
final readonly class BaselineCommand
{
    public const string NAME = 'audit:baseline';

    public const string DESCRIPTION = 'Create or update an accepted-finding baseline from a JSON audit report, preserving existing entries and their reasons';

    public function __construct(
        private BaselineMergerInterface $baselineMerger,
    ) {}

    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[Argument(description: 'Path to a JSON report produced by audit:run --format=json.', name: 'report')] string $report,
        #[Argument(description: 'Baseline file to create or update.', name: 'baseline')] string $baseline = '.security-baseline.json',
        #[Option(description: 'Drop baseline entries whose findings no longer appear in the report.', name: 'prune')] bool $prune = false,
        #[Option(description: 'Ask a reason for each newly accepted finding; reasoned entries teach the reviewer the mitigating control.', name: 'annotate')] bool $annotate = false,
    ): int {
        try {
            $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, $prune);
            $this->baselineMerger->commit($baseline, $baselineMergePlan, $annotate ? $this->reasons($symfonyStyle, $baselineMergePlan) : []);
        } catch (ReportFileNotReadableException|MalformedReportFileException|MalformedBaselineFileException|UnsafeBaselineWriteException $exception) {
            $symfonyStyle->error($exception->getMessage());

            return ExitCode::Failure->value;
        }

        $symfonyStyle->success(\sprintf(
            'Baseline %s: %d added, %d kept, %d pruned (%d entries).',
            $this->sanitize($baseline),
            \count($baselineMergePlan->newFindings),
            \count($baselineMergePlan->keptEntries),
            $baselineMergePlan->prunedCount,
            \count($baselineMergePlan->newFindings) + \count($baselineMergePlan->keptEntries),
        ));

        return ExitCode::Success->value;
    }

    /**
     * @return array<int, string>
     */
    private function reasons(SymfonyStyle $symfonyStyle, BaselineMergePlan $baselineMergePlan): array
    {
        $reasons = [];
        foreach ($baselineMergePlan->newFindings as $index => $newFinding) {
            $reason = $symfonyStyle->ask(\sprintf(
                'Reason for accepting "%s" in %s (leave empty to skip)',
                $this->sanitize($newFinding->title),
                $this->sanitize($newFinding->file),
            ));

            if (\is_string($reason) && !u($reason)->trim()->isEmpty()) {
                $reasons[$index] = $reason;
            }
        }

        return $reasons;
    }

    /**
     * Finding titles and file paths originate in the audited project and the
     * LLM's output, and the baseline path is echoed back verbatim — exactly
     * as the trend presenter does, each value is collapsed to a single line
     * and stripped of control/ANSI/bidi characters so a crafted value cannot
     * spoof the terminal.
     */
    private function sanitize(string $value): string
    {
        return TerminalTextSanitizer::collapseToSingleLine(mb_scrub($value, 'UTF-8'));
    }
}
