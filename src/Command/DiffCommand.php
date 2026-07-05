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
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;

#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
/** @internal not part of the BC promise — the command *name* (`audit:diff`) is public, but the PHP class itself is for internal use only. */
final readonly class DiffCommand
{
    public const string NAME = 'audit:diff';

    public const string DESCRIPTION = 'Compare two previously generated JSON audit reports and show new, fixed, and persisting findings';

    public function __construct(
        private ReportDifferInterface $reportDiffer,
        private DiffPresenterInterface $diffPresenter,
    ) {}

    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[Argument(description: 'Path to the earlier JSON report.')] string $previousReport,
        #[Argument(description: 'Path to the later JSON report.')] string $currentReport,
        #[Option(description: 'Output format: console or json', name: 'format', shortcut: 'f')] DiffOutputFormat $diffOutputFormat = DiffOutputFormat::Console,
    ): int {
        try {
            $reportDiff = $this->reportDiffer->diff($previousReport, $currentReport);
        } catch (ReportFileNotReadableException|MalformedReportFileException $exception) {
            $symfonyStyle->error($exception->getMessage());

            return ExitCode::Failure->value;
        }

        $this->diffPresenter->present($symfonyStyle, $reportDiff, $diffOutputFormat);

        return ExitCode::Success->value;
    }
}
