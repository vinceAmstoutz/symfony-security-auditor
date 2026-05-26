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
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

/** @internal not part of the BC promise — see docs/versioning.md */
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

    public function estimatingSection(SymfonyStyle $symfonyStyle): void
    {
        $symfonyStyle->section('Estimating audit cost (dry run)...');
    }

    public function dryRunResult(SymfonyStyle $symfonyStyle, AuditReport $auditReport): void
    {
        $cost = $auditReport->cost();

        if ($cost !== null) {
            $lines = [];
            $lines[] = \sprintf('Model : %s', $cost->primaryModel());
            $lines[] = \sprintf(
                'Tokens: %s in / %s out (total: %s)',
                number_format($cost->inputTokens()),
                number_format($cost->outputTokens()),
                number_format($cost->totalTokens()),
            );
            $lines[] = \sprintf('Cost  : $%.4f (estimate)', $cost->estimatedCostUsd());

            foreach ($cost->byRole() as $role => $entry) {
                $lines[] = \sprintf(
                    '  %-8s (%s): $%.4f — %s in / %s out',
                    $role,
                    $entry['model'],
                    $entry['estimated_cost_usd'],
                    number_format($entry['input_tokens']),
                    number_format($entry['output_tokens']),
                );
            }

            $symfonyStyle->listing($lines);
        }

        $symfonyStyle->note('Dry run — no LLM calls were made. This is a cost estimate only.');
        $symfonyStyle->success('Dry run complete.');
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
