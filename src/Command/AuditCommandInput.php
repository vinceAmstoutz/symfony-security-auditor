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

use RuntimeException;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\Option;

// Symfony Console MapInput reflects class properties and requires public mutable fields
// with property-level defaults; promoted readonly ctor params are invisible to its reflection.
// Treated as a context carrier per .claude/rules/php-classes.md.
final class AuditCommandInput
{
    #[Argument(description: 'Path to the Symfony project to audit. Defaults to the current working directory.')]
    public ?string $projectPath = null;

    #[Option(description: 'Output format: console, json or sarif', shortcut: 'f')]
    public OutputFormat $format = OutputFormat::Console;

    #[Option(description: 'Output file path (for json or sarif format)', shortcut: 'o')]
    public ?string $output = null;

    public function resolvedProjectPath(): string
    {
        if (null !== $this->projectPath && '' !== trim($this->projectPath)) {
            return $this->projectPath;
        }

        $cwd = getcwd();
        if (false === $cwd) {
            throw new RuntimeException('Failed to determine current working directory; pass an explicit project path.');
        }

        return $cwd;
    }

    public function isMachineReadableToStdout(): bool
    {
        return null === $this->output && OutputFormat::Console !== $this->format;
    }
}
