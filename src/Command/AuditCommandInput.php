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
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\WorkingDirectoryUnavailableException;

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

    #[Option(description: 'Output format: console, json or sarif', shortcut: 'f')]
    public OutputFormat $format = OutputFormat::Console;

    #[Option(description: 'Output file path (for json or sarif format)', shortcut: 'o')]
    public ?string $output = null;

    #[Option(description: 'Estimate token usage and cost without invoking the LLM; emits a report with zero vulnerabilities and an estimated cost block.')]
    public bool $dryRun = false;

    #[Option(description: 'Bypass the attacker cache for this run: skip cache reads so every chunk hits the LLM, and skip cache writes so existing entries stay untouched. Useful after upgrading the auditor or when you need to force a fresh analysis.', name: 'no-cache')]
    public bool $noCache = false;

    /**
     * @var list<string>
     */
    #[Option(description: 'Restrict the scan to a subdirectory of the project (relative to the project root). Repeat the option to include several subdirectories. Useful for monorepos where only one app should be audited. By default the whole project is scanned.', name: 'path', shortcut: 'p')]
    public array $paths = [];

    /**
     * @param ?callable(): (string|false) $cwdResolver defaults to PHP's getcwd; tests inject a stub
     */
    public function resolvedProjectPath(?callable $cwdResolver = null): string
    {
        if (null !== $this->projectPath && '' !== trim($this->projectPath)) {
            return $this->projectPath;
        }

        $cwd = ($cwdResolver ?? \getcwd(...))();
        if (false === $cwd) {
            throw WorkingDirectoryUnavailableException::fromGetcwdFailure();
        }

        return $cwd;
    }

    /**
     * @return list<string> normalized scan-path filters: trimmed, trailing
     *                      separators removed, blanks dropped, in input order
     */
    public function scanPaths(): array
    {
        $normalized = [];
        foreach ($this->paths as $path) {
            $trimmed = trim($path);
            if ('' === $trimmed) {
                continue;
            }

            $normalized[] = rtrim($trimmed, '/');
        }

        return $normalized;
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
