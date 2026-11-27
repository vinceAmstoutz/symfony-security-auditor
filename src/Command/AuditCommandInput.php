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

    #[Argument(description: 'Project to audit (default: the current directory)')]
    public ?string $projectPath = null;

    #[Option(description: 'Report format; the list and its default are below', name: 'format', shortcut: 'f')]
    public ?OutputFormat $givenFormat = null;

    public OutputFormat $format = OutputFormat::Console;

    #[Option(description: 'Write the report to this file (overrides audit.output)', shortcut: 'o')]
    public ?string $output = null;

    #[Option(description: 'Print the report even when audit.output names a file', name: 'no-output')]
    public bool $noOutput = false;

    #[Option(description: 'Estimate tokens and cost without calling the LLM')]
    public bool $dryRun = false;

    #[Option(description: 'List the files in scope and exit; add --dry-run for the cost', name: 'show-scanned')]
    public bool $showScanned = false;

    #[Option(description: 'Neither read nor write the attacker and reviewer caches', name: 'no-cache')]
    public bool $noCache = false;

    /**
     * @var list<string>
     */
    #[Option(description: 'Scan only this file or folder of the project (repeatable)', name: 'path', shortcut: 'p')]
    public array $paths = [];

    #[Option(description: 'Audit only the files changed since this git ref, uncommitted ones too', name: 'since')]
    public ?string $since = null;

    #[Option(description: 'Hide the findings this baseline file lists (overrides audit.baseline)', name: 'baseline')]
    public ?string $baseline = null;

    #[Option(description: 'Run the audit and save its findings to this file as a baseline', name: 'generate-baseline')]
    public ?string $generateBaseline = null;

    #[Option(description: 'Exit 1 from this risk level up (default: audit.fail_on, critical)', name: 'fail-on')]
    public ?RiskLevel $failOn = null;

    #[Option(description: 'Exit 1 below this score, 0-100 (overrides audit.min_score)', name: 'min-score')]
    public ?int $minScore = null;

    #[Option(description: 'Exit 3 when some file could not be fully analyzed', name: 'fail-on-incomplete')]
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
