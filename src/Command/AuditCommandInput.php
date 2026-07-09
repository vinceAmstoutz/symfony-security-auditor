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
use Symfony\Component\String\UnicodeString;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\WorkingDirectoryUnavailableException;

use function Symfony\Component\String\u;

/**
 * Symfony Console MapInput reflects class properties and requires public mutable fields
 * with property-level defaults; promoted readonly ctor params are invisible to its reflection.
 * Treated as a context carrier per .claude/rules/php-classes.md.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class AuditCommandInput
{
    #[Argument(description: 'Path to the Symfony project to audit. Defaults to the current working directory.')]
    public ?string $projectPath = null;

    #[Option(description: 'Output format: console, json, sarif, html, markdown, junit or github', shortcut: 'f')]
    public OutputFormat $format = OutputFormat::Console;

    #[Option(description: 'Output file path (any format)', shortcut: 'o')]
    public ?string $output = null;

    #[Option(description: 'Estimate token usage and cost without invoking the LLM; emits a report with zero vulnerabilities and an estimated cost block.')]
    public bool $dryRun = false;

    #[Option(description: 'List the files that would be audited (after applying included_paths and any --path filters) and exit, without invoking the LLM. Use it to confirm your scan scope. Combine with --dry-run to also print the cost estimate.', name: 'show-scanned')]
    public bool $showScanned = false;

    #[Option(description: 'Bypass the attacker and reviewer caches for this run: skip cache reads so every chunk and verdict hits the LLM, and skip cache writes so existing entries stay untouched. Useful after upgrading the auditor or when you need to force a fresh analysis.', name: 'no-cache')]
    public bool $noCache = false;

    /**
     * @var list<string>
     */
    #[Option(description: 'Restrict the scan to a subdirectory of the project (relative to the project root). Repeat the option to include several subdirectories. Useful for monorepos where only one app should be audited. By default the whole project is scanned.', name: 'path', shortcut: 'p')]
    public array $paths = [];

    #[Option(description: 'Diff mode: audit only files changed against the given git ref (e.g. main, origin/main, abc1234). Honors both committed changes (ref...HEAD) and uncommitted working-tree changes. Designed for CI on pull requests; the cache stays warm for unchanged files.', name: 'since')]
    public ?string $since = null;

    #[Option(description: 'Baseline file of accepted-finding fingerprints. Findings whose fingerprint is listed are suppressed from the report and excluded from the exit code. Overrides the audit.baseline config key. A missing file suppresses nothing.', name: 'baseline')]
    public ?string $baseline = null;

    #[Option(description: 'Run the audit, then write every current finding fingerprint to the given file as a baseline and exit 0 without failing on findings. Use this to accept the current findings so future runs only report new ones.', name: 'generate-baseline')]
    public ?string $generateBaseline = null;

    #[Option(description: 'Minimum aggregate risk level (safe|low|medium|high|critical) that makes the command exit 1. Overrides the audit.fail_on config key for this run. Defaults to the configured value (critical) when omitted.', name: 'fail-on')]
    public ?RiskLevel $failOn = null;

    /**
     * @param ?callable(): (string|false) $cwdResolver defaults to PHP's getcwd; tests inject a stub
     *
     * @throws WorkingDirectoryUnavailableException
     */
    public function resolvedProjectPath(?callable $cwdResolver = null): string
    {
        $trimmedPath = u($this->projectPath ?? '')->trim()->toString();
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
            $trimmed = $this->stripLeadingCurrentDirSegment(u($path)->trim()->trimEnd('/'));
            if ($trimmed->isEmpty()) {
                continue;
            }

            $normalized[] = $trimmed->toString();
        }

        return $normalized;
    }

    /**
     * `Path::makeRelative()` (used to compute every scanned file's relative
     * path) never produces a leading `./` in its output, so a `--path ./src`
     * or bare `--path .` CLI filter could otherwise never match any scanned
     * real relative path — silently scanning zero files instead of the
     * intended subdirectory (or, for a bare `.`, the whole project).
     */
    private function stripLeadingCurrentDirSegment(UnicodeString $unicodeString): UnicodeString
    {
        while ($unicodeString->startsWith('./')) {
            $unicodeString = $unicodeString->after('/')->trimStart('/');
        }

        return '.' === $unicodeString->toString() ? u('') : $unicodeString;
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
