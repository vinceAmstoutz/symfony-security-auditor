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

use InvalidArgumentException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Validator\ConstraintViolationListInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

final readonly class AuditPresenter implements AuditPresenterInterface
{
    public function header(SymfonyStyle $symfonyStyle, string $projectPath): void
    {
        $symfonyStyle->title('Symfony LLM Security Auditor');
        $symfonyStyle->text([
            \sprintf('Project: <info>%s</info>', $projectPath),
            'Pipeline: Ingestion → Mapping → Audit (Attacker ⚔ Reviewer)',
            '',
        ]);
    }

    public function runningSection(SymfonyStyle $symfonyStyle): void
    {
        $symfonyStyle->section('Running audit pipeline...');
    }

    public function violations(SymfonyStyle $symfonyStyle, ConstraintViolationListInterface $constraintViolationList): void
    {
        foreach ($constraintViolationList as $violation) {
            $symfonyStyle->error((string) $violation->getMessage());
        }
    }

    public function error(SymfonyStyle $symfonyStyle, Throwable $throwable): void
    {
        $message = $throwable instanceof InvalidArgumentException
            ? $throwable->getMessage()
            : \sprintf('Unexpected error: %s', $throwable->getMessage());

        $symfonyStyle->error($message);
    }

    public function result(SymfonyStyle $symfonyStyle, AuditReport $auditReport, int $exitCode): void
    {
        if (Command::FAILURE === $exitCode) {
            $symfonyStyle->caution(\sprintf(
                'Audit completed with CRITICAL risk level. %d vulnerabilities found.',
                $auditReport->totalVulnerabilities(),
            ));

            return;
        }

        $symfonyStyle->success(\sprintf(
            'Audit complete. Risk: %s | Vulnerabilities: %d',
            $auditReport->riskLevel(),
            $auditReport->totalVulnerabilities(),
        ));
    }
}
