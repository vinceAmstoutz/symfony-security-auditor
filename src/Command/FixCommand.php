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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InvalidProjectPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;

/**
 * Applies the suggested fixes of a JSON report to the project. A dry run by
 * default: it says which fixes apply cleanly and changes nothing until
 * `--apply`. A fix that no longer applies cleanly is refused, never forced,
 * and the command then exits `1`.
 *
 * @internal not part of the BC promise — the command *name* (`audit:fix`) is public, but the PHP class itself is for internal use only
 */
#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
final readonly class FixCommand
{
    public const string NAME = 'audit:fix';

    public const string DESCRIPTION = 'Apply the suggested fixes of a JSON audit report to the project (a dry run unless --apply)';

    public function __construct(
        private SuggestedFixReader $suggestedFixReader = new SuggestedFixReader(),
        private FixPlanner $fixPlanner = new FixPlanner(),
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[Argument(description: 'Path to a JSON report written with audit.fix_synthesis enabled.')] string $report,
        #[Argument(description: 'The project the report audited.', name: 'project-path')] string $projectPath = '.',
        #[Option(description: 'Write the fixes that apply cleanly instead of only listing them.')] bool $apply = false,
    ): int {
        try {
            $fixPlan = $this->fixPlanner->plan($this->suggestedFixReader->read($report), $projectPath);
        } catch (ReportFileNotReadableException|MalformedReportFileException|InvalidProjectPathException $exception) {
            $symfonyStyle->error($exception->getMessage());

            return ExitCode::Failure->value;
        }

        foreach ($fixPlan->outcomes as $fixOutcome) {
            $symfonyStyle->writeln($this->describe($fixOutcome, $apply));
        }

        $this->conclude($symfonyStyle, $fixPlan, $apply);

        return $fixPlan->appliedCount() === \count($fixPlan->outcomes) ? ExitCode::Success->value : ExitCode::Failure->value;
    }

    private function describe(FixOutcome $fixOutcome, bool $apply): string
    {
        $verdict = $apply ? 'applied' : 'applies cleanly';

        return \sprintf(
            '%s (%s): %s',
            $fixOutcome->suggestedFix->title,
            $fixOutcome->suggestedFix->file,
            $fixOutcome->applies() ? $verdict : \sprintf('not applied, %s', $fixOutcome->refusal),
        );
    }

    private function conclude(SymfonyStyle $symfonyStyle, FixPlan $fixPlan, bool $apply): void
    {
        $applied = $fixPlan->appliedCount();
        if (!$apply) {
            $symfonyStyle->writeln(\sprintf('Dry run: no file was changed. Run again with --apply to write the %d %s that %s.', $applied, 1 === $applied ? 'fix' : 'fixes', 1 === $applied ? 'applies' : 'apply'));

            return;
        }

        foreach ($fixPlan->contents as $path => $content) {
            $this->filesystem->dumpFile($path, $content);
        }

        $symfonyStyle->writeln(\sprintf('%d of %d suggested fixes applied.', $applied, \count($fixPlan->outcomes)));
    }
}
