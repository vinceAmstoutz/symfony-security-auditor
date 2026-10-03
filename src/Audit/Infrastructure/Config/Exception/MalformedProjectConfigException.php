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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception;

use RuntimeException;
use Symfony\Component\Yaml\Exception\ParseException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\TerminalText;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\WorkflowCommandText;

/** @internal not part of the BC promise — see docs/versioning.md */
final class MalformedProjectConfigException extends RuntimeException
{
    /**
     * The parser quotes the offending line, which the audited repository
     * wrote, so its control characters are escaped before the message reaches
     * a terminal, and its workflow commands are defused, since the console
     * wraps the message wherever it likes. The parse error is not chained: the
     * console renders every previous exception too, and would print that line
     * raw.
     */
    public static function fromParseException(string $configFile, ParseException $parseException): self
    {
        return new self(WorkflowCommandText::inWrappedMessage(TerminalText::escaped(\sprintf('Config file "%s" is not valid YAML: %s', $configFile, $parseException->getMessage()))));
    }

    public static function forHttpTimeout(string $configFile, string $key): self
    {
        return new self(TerminalText::escaped(\sprintf('Config file "%s" sets "%s" to something other than a number of seconds above zero. Give how long a request may wait for the provider to send anything, for example 600.', $configFile, $key)));
    }

    public static function forOversizedConfig(string $configFile, int $valueLimit): self
    {
        return new self(TerminalText::escaped(\sprintf('Config file "%s" holds %d values or more once its YAML aliases are expanded, far more than any configuration needs, so it was not read any further. Remove the aliases that repeat whole sections, or write the values out.', $configFile, $valueLimit)));
    }

    /**
     * Refused before the file is read: a link committed in the audited
     * repository could point at any file of the user's, and a parse error
     * quotes the line it stopped on.
     */
    public static function forSymlink(string $configFile): self
    {
        return new self(TerminalText::escaped(\sprintf('Config file "%s" is a symbolic link. A project config must be a regular file, so the audited repository cannot point it at a file of yours; replace the link with the file itself.', $configFile)));
    }

    /**
     * The value is not quoted: it is what would have reached the terminal.
     */
    public static function forControlCharacter(string $configFile, string $key): self
    {
        return new self(TerminalText::escaped(\sprintf('Config file "%s" sets "%s" to a value holding a control character, a line break, a bidirectional override or bytes that are not UTF-8, which no project setting takes. Give it as plain text.', $configFile, $key)));
    }

    /**
     * The value is not quoted: resolved, it would be what the reference read.
     */
    public static function forContainerReference(string $configFile, string $key): self
    {
        return new self(TerminalText::escaped(\sprintf('Config file "%s" sets "%s" to a value holding a container reference ("%%name%%", "%%env(VAR)%%", "%%%%" or the "env_…" placeholder of one), which would read your environment into a setting the audited repository chose. Write the value itself (a single "%%" stays text), or set it in your user config.', $configFile, $key)));
    }

    public static function forModelName(string $configFile, string $key): self
    {
        return new self(TerminalText::escaped(\sprintf('Config file "%s" sets "%s" to a model name holding more than a model id: a project file names a model with letters, digits and ". _ : / @ + -" alone, without ".." or "//", since request options after "?" and path segments reach the provider as written, tools and headers included. Name the model alone, and set its options in your user config.', $configFile, $key)));
    }

    public static function forWorkflowCommand(string $configFile, string $key): self
    {
        return new self(TerminalText::escaped(\sprintf('Config file "%s" sets "%s" to a value holding a double colon or a double hash before a bracket, which no project setting takes: a CI runner reads either as a workflow command. Remove it from the value.', $configFile, $key)));
    }

    /**
     * The key is not quoted: it holds the very marker the message withholds.
     */
    public static function forWorkflowCommandInKey(string $configFile, string $parentKey): self
    {
        return new self(TerminalText::escaped(\sprintf('Config file "%s" declares a key under "%s" holding a double colon or a double hash before a bracket, which no project setting takes: a CI runner reads either as a workflow command. Remove it from the key.', $configFile, $parentKey)));
    }

    /**
     * The key is quoted: it is the repository's text, never what it resolves to.
     */
    public static function forContainerReferenceInKey(string $configFile, string $key): self
    {
        return new self(TerminalText::escaped(\sprintf('Config file "%s" declares the key "%s", which holds a container reference ("%%name%%", "%%env(VAR)%%", "%%%%" or the "env_…" placeholder of one) that would read your environment into a setting the audited repository chose. Write the key itself.', $configFile, $key)));
    }
}
