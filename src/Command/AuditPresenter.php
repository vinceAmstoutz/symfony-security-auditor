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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\TerminalTextSanitizer;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AuditPresenter implements AuditPresenterInterface
{
    private const string SCAN_MARK = '◉ >>';

    private const string SCAN_MARK_PORTABLE = '';

    private const string WORDMARK_LEAD = 'SECURITY';

    private const string WORDMARK_TAIL = 'AUDITOR';

    private const string TAGLINE = 'Symfony - multi-agent LLM audit';

    /** Sampled from the circular bug glyph in `assets/banner.webp`. */
    private const string BANNER_PINK = '#e71c55';

    /**
     * Brightened from the wordmark's `#242d5c` in `assets/banner.webp` — that
     * navy sits on the banner image's light background, but as terminal
     * foreground text it degrades toward black on a 16-colour palette and
     * disappears on the dark background most terminals default to.
     */
    private const string BANNER_NAVY = '#5b6fd6';

    public function __construct(private PricingProviderInterface $pricingProvider) {}

    #[Override]
    public function header(SymfonyStyle $symfonyStyle, string $projectPath): void
    {
        $this->wordmark($symfonyStyle);

        $symfonyStyle->text([
            \sprintf('Project: <info>%s</info>', OutputFormatter::escape($projectPath)),
            'Pipeline: Ingestion -> Mapping -> Audit (Attacker vs Reviewer)',
            '',
        ]);
    }

    /**
     * One code path for both terminal states: `OutputFormatter` drops the
     * style tags when the output is not decorated, so CI logs and a colour
     * terminal show the same layout rather than two different headers. Every
     * character is ASCII, so a Windows console on a legacy code page renders
     * it without substitution and without the double-width cells that break
     * column alignment.
     */
    private function wordmark(SymfonyStyle $symfonyStyle): void
    {
        $scanMark = $this->scanMark();
        $markedLead = '' === $scanMark ? '' : \sprintf('%s ', $scanMark);

        $symfonyStyle->writeln([
            '',
            \sprintf(
                ' <fg=%s;options=bold>%s%s</> <fg=%s;options=bold>%s</>',
                self::BANNER_PINK,
                $markedLead,
                self::WORDMARK_LEAD,
                self::BANNER_NAVY,
                self::WORDMARK_TAIL,
            ),
            \sprintf(' %s%s', str_repeat(' ', mb_strlen($markedLead)), self::TAGLINE),
            '',
        ]);
    }

    /**
     * `◉` is outside CP437/CP850/CP1252, so a console on a legacy code page
     * substitutes it. Dropping the mark there keeps the colour and the
     * wordmark, which carry the identity on their own.
     */
    private function scanMark(): string
    {
        return $this->consoleRendersUtf8() ? self::SCAN_MARK : self::SCAN_MARK_PORTABLE;
    }

    /**
     * The locale variables are the portable signal, and a Windows console
     * sets none of them unless the shell is UTF-8 aware — so Windows lands on
     * the ASCII wordmark without this needing a platform branch, which could
     * only ever be exercised on one platform's CI leg.
     */
    private function consoleRendersUtf8(): bool
    {
        $locale = strtoupper($this->localeSetting());

        return str_contains($locale, 'UTF-8') || str_contains($locale, 'UTF8');
    }

    private function localeSetting(): string
    {
        foreach (['LC_ALL', 'LC_CTYPE', 'LANG'] as $variable) {
            $value = getenv($variable);
            if (\is_string($value) && '' !== $value) {
                return $value;
            }
        }

        return '';
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

    #[Override]
    public function synthesisCostWarnings(SymfonyStyle $symfonyStyle, bool $pocSynthesisEnabled, bool $fixSynthesisEnabled): void
    {
        if ($pocSynthesisEnabled && $fixSynthesisEnabled) {
            $symfonyStyle->getErrorStyle()->warning('PoC synthesis (audit.poc_synthesis.enabled) and fix synthesis (audit.fix_synthesis.enabled) are both enabled. Their LLM calls are not included in this cost estimate, so a real run will cost more than the figure shown.');

            return;
        }

        if ($pocSynthesisEnabled) {
            $symfonyStyle->getErrorStyle()->warning('PoC synthesis is enabled (audit.poc_synthesis.enabled). Its LLM calls are not included in this cost estimate, so a real run will cost more than the figure shown.');
        }

        if ($fixSynthesisEnabled) {
            $symfonyStyle->getErrorStyle()->warning('Fix synthesis is enabled (audit.fix_synthesis.enabled). Its LLM calls are not included in this cost estimate, so a real run will cost more than the figure shown.');
        }
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
        $this->lightConfirmation($symfonyStyle, 'Dry run complete.');
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
            $symfonyStyle->writeln(\sprintf(' <info>%s</info> (%d)', $this->bucketLabel($type), \count($relativePaths)));
            $symfonyStyle->listing(array_map($this->sanitizePathForListing(...), $relativePaths));
        }

        $this->lightConfirmation($symfonyStyle, \sprintf('%d file(s) in scope.', \count($projectFiles)));
    }

    /**
     * A lighter-weight replacement for `SymfonyStyle::success()` on
     * intermediate confirmations — no boxed `[OK]` block, just a short line —
     * but keeping its leading marker (gated on `isDecorated()`, since a
     * redirected/CI log has no use for an emoji) and its trailing blank line,
     * so it doesn't abut whatever prints next.
     */
    private function lightConfirmation(SymfonyStyle $symfonyStyle, string $message): void
    {
        $symfonyStyle->writeln(\sprintf($symfonyStyle->isDecorated() ? '  ✅ %s' : '  %s', $message));
        $symfonyStyle->newLine();
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

        return $this->withUncategorizedBucketsLast($byType);
    }

    /**
     * @param array<string, list<string>> $byType
     *
     * @return array<string, list<string>>
     */
    private function withUncategorizedBucketsLast(array $byType): array
    {
        $trailing = [];
        foreach ([ProjectFileType::PHP->value, ProjectFileType::OTHER->value] as $trailingType) {
            if (\array_key_exists($trailingType, $byType)) {
                $trailing[$trailingType] = $byType[$trailingType];
                unset($byType[$trailingType]);
            }
        }

        return $byType + $trailing;
    }

    private function bucketLabel(string $type): string
    {
        return match ($type) {
            ProjectFileType::PHP->value => 'php · uncategorized',
            ProjectFileType::OTHER->value => 'other · uncategorized',
            default => $type,
        };
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
                'Audit failed a configured gate. Risk: %s. Score: %d/100. %d %s found.',
                $auditReport->riskLevel(),
                $auditReport->normalizedScore(),
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
