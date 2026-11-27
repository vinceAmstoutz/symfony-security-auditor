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
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Filesystem\Path;
use Symfony\Component\String\AbstractString;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\PathText;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ConflictingCommandOptionsException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\WorkingDirectoryUnavailableException;

use function Symfony\Component\String\u;

/**
 * Not readonly: Console's MapInput needs public mutable properties with
 * defaults. A context carrier per .claude/rules/php-classes.md.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class AuditCommandInput
{
    private const int LOWEST_MIN_SCORE = 0;

    private const int HIGHEST_MIN_SCORE = 100;

    #[Argument(description: 'Path to the Symfony project to audit. Defaults to the current working directory. A folder that holds no composer.json and no file scan.included_paths reaches audits the Composer project it lies in, narrowed to that folder, and reads a --path relative to it.')]
    public ?string $projectPath = null;

    #[Option(description: 'Output format: console, executive, json, sarif, html, markdown, junit, github or github-comment. Defaults to the audit.format config key, else the format the --output extension names, else console.', name: 'format', shortcut: 'f')]
    public ?OutputFormat $givenFormat = null;

    public OutputFormat $format = OutputFormat::Console;

    #[Option(description: 'Output file path (any format). Without --format or audit.format, its extension (.html, .json, .sarif, .md, .xml) picks the format; a name without one is deprecated. Overrides the audit.output config key for this run.', shortcut: 'o')]
    public ?string $output = null;

    #[Option(description: 'Print the report instead of writing it to a file, whatever audit.output says. Cannot be combined with --output.', name: 'no-output')]
    public bool $noOutput = false;

    #[Option(description: 'Estimate token usage and cost without invoking the LLM; emits a report with zero vulnerabilities and an estimated cost block.')]
    public bool $dryRun = false;

    #[Option(description: 'List the files that would be audited (those of the configured included_paths, or of the --path values in their place) and exit, without invoking the LLM. Use it to confirm your scan scope. Combine with --dry-run to also print the cost estimate.', name: 'show-scanned')]
    public bool $showScanned = false;

    #[Option(description: 'Bypass the attacker and reviewer caches for this run: skip cache reads so every chunk and verdict hits the LLM, and skip cache writes so existing entries stay untouched. Useful after upgrading the auditor or when you need to force a fresh analysis.', name: 'no-cache')]
    public bool $noCache = false;

    /**
     * @var list<string>
     */
    #[Option(description: 'Scan these directories or files of the project (relative to the project root) in place of scan.included_paths for this run; the project root itself keeps the configured scope. Repeat the option to give several. Useful for monorepos where only one app should be audited. By default the configured scope is scanned.', name: 'path', shortcut: 'p')]
    public array $paths = [];

    #[Option(description: 'Diff mode: audit only files changed against the given git ref (e.g. main, origin/main, abc1234). Honors both committed changes (ref...HEAD) and uncommitted working-tree changes. Designed for CI on pull requests; the cache stays warm for unchanged files.', name: 'since')]
    public ?string $since = null;

    #[Option(description: 'Baseline file of accepted-finding fingerprints. Findings whose fingerprint is listed are suppressed from the report and excluded from the exit code. Overrides the audit.baseline config key. A missing file suppresses nothing.', name: 'baseline')]
    public ?string $baseline = null;

    #[Option(description: 'Run the audit, then write every current finding fingerprint to the given file as a baseline and exit 0 without failing on findings (3 under --fail-on-incomplete when some file could not be fully analyzed; a run with no verdict writes no baseline and exits 1). Use this to accept the current findings so future runs only report new ones.', name: 'generate-baseline')]
    public ?string $generateBaseline = null;

    #[Option(description: 'Minimum aggregate risk level (safe|low|medium|high|critical) that makes the command exit 1. Overrides the audit.fail_on config key for this run. Defaults to the configured value (critical) when omitted.', name: 'fail-on')]
    public ?RiskLevel $failOn = null;

    #[Option(description: 'Minimum normalized score (0-100) below which the command exits 1. Independent of --fail-on: the audit fails when either gate trips. Overrides the audit.min_score config key for this run; with neither, the risk level alone gates.', name: 'min-score')]
    public ?int $minScore = null;

    #[Option(description: 'Exit 3 when some file could not be fully analyzed (a scan or LLM call failed), so a partial report cannot pass CI. A tripped --fail-on or --min-score gate still exits 1. Without it, such a run only prints a warning unless audit.fail_on_incomplete is set; --no-fail-on-incomplete turns that off for this run.', name: 'fail-on-incomplete')]
    public ?bool $failOnIncomplete = null;

    private bool $failOnIncompleteFromConfiguration = false;

    /**
     * Fills each flag the command line left unset from its `audit.*` key. An
     * empty `audit.output` prints the report, as an unset one does.
     */
    public function applyDefaults(AuditCommandDefaults $auditCommandDefaults): void
    {
        $this->minScore ??= $auditCommandDefaults->minScore;
        $this->failOnIncompleteFromConfiguration = null === $this->failOnIncomplete;
        $this->failOnIncomplete ??= $auditCommandDefaults->failOnIncomplete;
        $this->output ??= $this->noOutput || $this->dryRun || '' === $auditCommandDefaults->output ? null : $auditCommandDefaults->output;
        $this->format = $this->givenFormat ?? $this->formatFor($auditCommandDefaults->format);
    }

    /**
     * Takes the format from the output file's extension when the configured one is the default `console`.
     */
    private function formatFor(OutputFormat $configuredFormat): OutputFormat
    {
        return OutputFormat::Console === $configuredFormat ? OutputFormat::ofOutputFile($this->output) ?? $configuredFormat : $configuredFormat;
    }

    public function failsOnIncomplete(): bool
    {
        return true === $this->failOnIncomplete;
    }

    /**
     * Names what decides whether an incomplete run fails: the flag, or the
     * configuration key when the command line left the flag unset.
     */
    public function failOnIncompleteSetting(): string
    {
        return $this->failOnIncompleteFromConfiguration ? 'audit.fail_on_incomplete' : '--fail-on-incomplete';
    }

    /**
     * @param ?callable(): (string|false) $cwdResolver defaults to getcwd()
     *
     * @throws WorkingDirectoryUnavailableException
     */
    public function resolvedProjectPath(?callable $cwdResolver = null): string
    {
        $trimmedPath = PathText::of($this->projectPath ?? '')->trim()->toString();
        if (Path::isAbsolute($trimmedPath)) {
            return Path::canonicalize($trimmedPath);
        }

        $cwd = ($cwdResolver ?? \getcwd(...))();
        if (false === $cwd) {
            throw WorkingDirectoryUnavailableException::fromGetcwdFailure();
        }

        return Path::makeAbsolute($trimmedPath, $cwd);
    }

    /**
     * @return list<string> normalized scan-path filters: trimmed, trailing
     *                      separators removed, blanks dropped, in input order
     */
    public function scanPaths(): array
    {
        $normalized = [];
        foreach ($this->paths as $path) {
            $trimmed = $this->stripLeadingCurrentDirSegment(PathText::of($path)->trim()->trimEnd('/'));
            if ($trimmed->isEmpty()) {
                continue;
            }

            $normalized[] = $trimmed->toString();
        }

        return $normalized;
    }

    /**
     * Drops the leading `./` segments, which no scanned relative path has. A
     * bare `.` names the whole project.
     */
    private function stripLeadingCurrentDirSegment(AbstractString $abstractString): AbstractString
    {
        while ($abstractString->startsWith('./')) {
            $abstractString = $abstractString->after('/')->trimStart('/');
        }

        return '.' === $abstractString->toString() ? u('') : $abstractString;
    }

    /**
     * Returns the output file when it has no extension to pick the format from
     * while no format is chosen, null otherwise. A device such as `/dev/null`
     * never lacks one.
     */
    public function outputFileLackingAFormat(): ?string
    {
        if (null === $this->output || !$this->formatIsLeftToTheOutputFile()) {
            return null;
        }

        return '' === Path::getExtension($this->output) && !WritableFilePath::isCharacterDevice($this->output) ? $this->output : null;
    }

    private function formatIsLeftToTheOutputFile(): bool
    {
        return !$this->givenFormat instanceof OutputFormat && OutputFormat::Console === $this->format;
    }

    /**
     * Refuses `--output` with `--no-output` and `--generate-baseline` with
     * `--dry-run` or `--show-scanned`.
     *
     * @throws ConflictingCommandOptionsException
     */
    public function assertNoConflictingOptions(): void
    {
        if ($this->noOutput && null !== $this->output) {
            throw ConflictingCommandOptionsException::forOutputWithNoOutput();
        }

        if (null === $this->generateBaseline) {
            return;
        }

        if ($this->dryRun) {
            throw ConflictingCommandOptionsException::forGenerateBaselineWithPreviewFlag('--dry-run');
        }

        if ($this->showScanned) {
            throw ConflictingCommandOptionsException::forGenerateBaselineWithPreviewFlag('--show-scanned');
        }
    }

    /**
     * Returns a `--min-score` below 0, which is honored and gates no run, else
     * null.
     */
    public function minScoreBelowRange(): ?int
    {
        return null !== $this->minScore && $this->minScore < self::LOWEST_MIN_SCORE ? $this->minScore : null;
    }

    /**
     * Returns a `--min-score` above 100, which is honored and fails every run,
     * else null.
     */
    public function minScoreAboveRange(): ?int
    {
        return null !== $this->minScore && $this->minScore > self::HIGHEST_MIN_SCORE ? $this->minScore : null;
    }

    /**
     * Null for `--show-scanned` without `--dry-run`, which writes no report.
     */
    public function reportFile(): ?string
    {
        return $this->showScanned && !$this->dryRun ? null : $this->output;
    }

    public function isMachineReadableToStdout(): bool
    {
        return null === $this->output && OutputFormat::Console !== $this->format;
    }

    public function isMachineReadableFormat(): bool
    {
        return OutputFormat::Console !== $this->format;
    }
}
