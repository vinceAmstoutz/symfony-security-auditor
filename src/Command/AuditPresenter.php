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
use Override;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\TerminalTextSanitizer;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AuditPresenter implements AuditPresenterInterface
{
    public function __construct(private PricingProviderInterface $pricingProvider) {}

    #[Override]
    public function header(SymfonyStyle $symfonyStyle, string $projectPath): void
    {
        $symfonyStyle->title('Symfony LLM Security Auditor');
        $symfonyStyle->text([
            \sprintf('Project: <info>%s</info>', OutputFormatter::escape($projectPath)),
            'Pipeline: Ingestion → Mapping → Audit (Attacker ⚔ Reviewer)',
            '',
        ]);
    }

    /**
     * @param list<string> $configNotices
     */
    #[Override]
    public function preflightWarnings(SymfonyStyle $symfonyStyle, bool $secretScrubbingEnabled, array $configNotices = []): void
    {
        foreach ($configNotices as $configNotice) {
            $symfonyStyle->getErrorStyle()->note($configNotice);
        }

        if ($secretScrubbingEnabled) {
            return;
        }

        $symfonyStyle->getErrorStyle()->warning('Secret scrubbing is disabled. File contents will be sent verbatim to the configured LLM provider. If that provider runs in the cloud, credentials in committed configs or .env.dist files may be exposed. Re-enable scan.secret_scrubbing.enabled (the default) or confirm you are using a local provider.');
    }

    #[Override]
    public function unsupportedModelWarnings(SymfonyStyle $symfonyStyle, AuditReport $auditReport): void
    {
        $unsupportedModels = $this->unsupportedModels($auditReport->cost());

        if ([] === $unsupportedModels) {
            return;
        }

        $symfonyStyle->getErrorStyle()->warning(\sprintf(
            'No published pricing for the configured model(s): %s. The dry-run cost estimate shows $0.00 for these. If you are running a local or self-hosted model (e.g. Ollama, LM Studio), $0.00 is correct — you can ignore this notice. Otherwise the name is likely a typo or an unlisted model: check it in your symfony_security_auditor configuration against the models supported by your symfony/ai platform.',
            implode(', ', $unsupportedModels),
        ));
    }

    /** @return array<string, string> */
    private function unsupportedModels(AuditCost $auditCost): array
    {
        $unsupportedModels = [];
        foreach ($auditCost->byRole() as $entry) {
            $model = $entry['model'];
            if (!$this->pricingProvider->hasModel($model)) {
                $unsupportedModels[$model] = $model;
            }
        }

        return $unsupportedModels;
    }

    #[Override]
    public function runningSection(SymfonyStyle $symfonyStyle): void
    {
        $symfonyStyle->section('Running audit pipeline...');
    }

    #[Override]
    public function longRunNotice(SymfonyStyle $symfonyStyle): void
    {
        $symfonyStyle->writeln([
            ' <fg=gray>The audit makes many LLM calls — typically several minutes, 20+ minutes on large projects.</>',
            ' <fg=gray>Live progress and findings stream below as they happen.</>',
            '',
        ]);
    }

    #[Override]
    public function estimatingSection(SymfonyStyle $symfonyStyle): void
    {
        $symfonyStyle->section('Estimating audit cost (dry run)...');
    }

    #[Override]
    public function dryRunResult(SymfonyStyle $symfonyStyle, AuditReport $auditReport): void
    {
        $cost = $auditReport->cost();

        if ('' !== $cost->primaryModel()) {
            $lines = [];
            $lines[] = \sprintf('Model : %s', $cost->primaryModel());
            $lines[] = \sprintf(
                'Tokens: %s in / %s out (total: %s)',
                number_format($cost->inputTokens()),
                number_format($cost->outputTokens()),
                number_format($cost->totalTokens()),
            );
            $lines[] = \sprintf('Cost  : $%s (estimate)', number_format($cost->estimatedCostUsd(), 4, '.', ''));

            foreach ($cost->byRole() as $role => $entry) {
                $lines[] = \sprintf(
                    '  %-8s (%s): $%s — %s in / %s out',
                    $role,
                    $entry['model'],
                    number_format($entry['estimated_cost_usd'], 4, '.', ''),
                    number_format($entry['input_tokens']),
                    number_format($entry['output_tokens']),
                );
            }

            $symfonyStyle->listing($lines);
        }

        $symfonyStyle->note('Dry run — no LLM calls were made. This is a cost estimate only. It excludes provider prompt-cache discounts and warm attacker/reviewer caches, so a real run typically costs less than shown.');
        $symfonyStyle->success('Dry run complete.');
    }

    #[Override]
    public function scannedFiles(SymfonyStyle $symfonyStyle, array $projectFiles): void
    {
        if ([] === $projectFiles) {
            $symfonyStyle->warning('No files matched. Check your included_paths configuration and any --path filters.');

            return;
        }

        $symfonyStyle->section(\sprintf('Scanned files (%d)', \count($projectFiles)));

        foreach ($this->relativePathsByType($projectFiles) as $type => $relativePaths) {
            $symfonyStyle->writeln(\sprintf(' <info>%s</info> (%d)', $type, \count($relativePaths)));
            $symfonyStyle->listing(array_map($this->sanitizePathForListing(...), $relativePaths));
        }

        $symfonyStyle->success(\sprintf('%d file(s) in scope.', \count($projectFiles)));
    }

    #[Override]
    public function scannedFilesHint(SymfonyStyle $symfonyStyle, int $fileCount): void
    {
        $symfonyStyle->writeln(\sprintf(
            ' <fg=gray>Tip: run with --show-scanned to list the %d file(s) that would be audited.</>',
            $fileCount,
        ));
    }

    /**
     * A scanned file's relative path comes from the audited (untrusted) project,
     * where a filename may legally contain a newline, ANSI escape or bidi
     * override. `OutputFormatter::escape()` neutralises `<`/`>` markup but not
     * those characters, so the path is first collapsed to a single line and
     * stripped of control/bidi characters — a crafted filename cannot forge a
     * fake listing entry or spoof the terminal.
     */
    private function sanitizePathForListing(string $relativePath): string
    {
        return OutputFormatter::escape(TerminalTextSanitizer::collapseToSingleLine(mb_scrub($relativePath, 'UTF-8')));
    }

    /**
     * @param list<ProjectFile> $projectFiles
     *
     * @return array<string, list<string>>
     */
    private function relativePathsByType(array $projectFiles): array
    {
        $byType = [];
        foreach ($projectFiles as $projectFile) {
            $byType[$projectFile->type()][] = $projectFile->relativePath();
        }

        return $byType;
    }

    #[Override]
    public function error(SymfonyStyle $symfonyStyle, Throwable $throwable): void
    {
        $message = $throwable instanceof InvalidArgumentException
            ? $throwable->getMessage()
            : \sprintf('Unexpected error: %s', $throwable->getMessage());

        $symfonyStyle->error($message);
    }

    #[Override]
    public function result(SymfonyStyle $symfonyStyle, AuditReport $auditReport, int $exitCode): void
    {
        if (Command::FAILURE === $exitCode) {
            $totalVulnerabilities = $auditReport->totalVulnerabilities();
            $symfonyStyle->caution(\sprintf(
                'Audit completed at or above the fail-on threshold. Risk: %s. %d %s found.',
                $auditReport->riskLevel(),
                $totalVulnerabilities,
                1 === $totalVulnerabilities ? 'vulnerability' : 'vulnerabilities',
            ));

            return;
        }

        $symfonyStyle->success(\sprintf(
            'Audit complete. Risk: %s | Vulnerabilities: %d',
            $auditReport->riskLevel(),
            $auditReport->totalVulnerabilities(),
        ));
    }

    #[Override]
    public function baselineGenerated(SymfonyStyle $symfonyStyle, string $path, int $fingerprintCount): void
    {
        $symfonyStyle->success(\sprintf(
            'Baseline written to %s with %d finding fingerprint(s). Future runs will suppress these unless you pass a different --baseline.',
            $path,
            $fingerprintCount,
        ));
    }
}
