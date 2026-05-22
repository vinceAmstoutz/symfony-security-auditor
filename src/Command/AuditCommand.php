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

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\MapInput;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;

#[AsCommand(
    name: 'audit:run',
    description: 'Run AI-powered multi-agent security audit on a Symfony project',
)]
final readonly class AuditCommand
{
    public function __construct(
        private RunAuditUseCase $runAuditUseCase,
        private ReportWriterInterface $reportWriter,
        private ValidatorInterface $validator,
        private AuditExitCodeResolverInterface $auditExitCodeResolver,
        private AuditPresenterInterface $auditPresenter,
    ) {}

    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[MapInput] AuditCommandInput $auditCommandInput,
    ): int {
        $constraintViolationList = $this->validator->validate($auditCommandInput);
        if (\count($constraintViolationList) > 0) {
            $this->auditPresenter->violations($symfonyStyle, $constraintViolationList);

            return Command::FAILURE;
        }

        try {
            $projectPath = $auditCommandInput->resolvedProjectPath();
        } catch (Throwable $throwable) {
            $this->auditPresenter->error($symfonyStyle, $throwable);

            return Command::FAILURE;
        }

        $this->auditPresenter->header($symfonyStyle, $projectPath);

        try {
            $this->auditPresenter->runningSection($symfonyStyle);

            $report = $this->runAuditUseCase->execute($projectPath);
            $this->reportWriter->write($report, $auditCommandInput->format, $auditCommandInput->output, $symfonyStyle);

            $exitCode = $this->auditExitCodeResolver->resolve($report);

            if (!$auditCommandInput->isMachineReadableToStdout()) {
                $this->auditPresenter->result($symfonyStyle, $report, $exitCode);
            }

            return $exitCode;
        } catch (Throwable $throwable) {
            $this->auditPresenter->error($symfonyStyle, $throwable);

            return Command::FAILURE;
        }
    }
}
