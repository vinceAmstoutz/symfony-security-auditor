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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;

/**
 * A project value is echoed back — a model name in the pricing warning, a
 * rejected value in a validation error — and handed to the container, so a
 * value that is not plain text (an escape sequence, a line a CI runner would
 * read as a workflow command, a spoofed line direction) is refused, and so is
 * a value or key the container would resolve (`%env(VAR)%`), which would read
 * the user's environment into a setting the repository chose. A double colon
 * is refused too, since the console wraps a long message wherever it likes
 * and a runner reads a line that starts with one as a workflow command, and a
 * model name must be a model id alone: request options after `?` and path
 * segments reach the provider as written, so `tool_choice` or `server_tools`
 * would silence or widen the audit on the user's key. No setting a project
 * file may set needs any of them.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProjectConfigValueGuard
{
    private const array MODEL_SETTINGS = ['model', 'attacker_model', 'reviewer_model', 'audit.escalation.cheap_model'];

    private const string WORKFLOW_COMMAND_MARKER = '::';

    private const string LEGACY_WORKFLOW_COMMAND_MARKER = '##[';

    private const string MODEL_ID = '/^(?!.*(?:\.\.|\/\/))[A-Za-z0-9._:\/@+-]*$/';

    /**
     * Run before any other guard, since each of them may quote a key back.
     *
     * @param array<array-key, mixed> $projectConfig
     * @param list<array-key>         $parentPath
     *
     * @throws MalformedProjectConfigException
     */
    public function assertPlainKeys(string $projectConfigFile, array $projectConfig, array $parentPath = []): void
    {
        foreach ($projectConfig as $key => $value) {
            $this->assertKey($projectConfigFile, $key, $parentPath);

            if (\is_array($value)) {
                $this->assertPlainKeys($projectConfigFile, $value, [...$parentPath, $key]);
            }
        }
    }

    /**
     * @param array<array-key, mixed> $projectConfig
     *
     * @throws MalformedProjectConfigException
     */
    public function assertLiteralPlainText(string $projectConfigFile, array $projectConfig): void
    {
        $this->assertEntries($projectConfigFile, $projectConfig, []);
    }

    /**
     * @param array<array-key, mixed> $config
     * @param list<array-key>         $path
     *
     * @throws MalformedProjectConfigException
     */
    private function assertEntries(string $projectConfigFile, array $config, array $path): void
    {
        foreach ($config as $key => $value) {
            $this->assertValue($projectConfigFile, $value, [...$path, $key]);
        }
    }

    /**
     * A list node handed a map keeps its keys, and the container resolves
     * keys as it does values; `symfony/config` quotes an unknown key back.
     *
     * @param list<array-key> $parentPath
     *
     * @throws MalformedProjectConfigException
     */
    private function assertKey(string $projectConfigFile, int|string $key, array $parentPath): void
    {
        if (\is_string($key) && $this->holdsWorkflowCommand($key)) {
            throw MalformedProjectConfigException::forWorkflowCommandInKey($projectConfigFile, [] === $parentPath ? 'the top level' : implode('.', $parentPath));
        }

        if (\is_string($key) && $this->isResolvedByTheContainer($key)) {
            throw MalformedProjectConfigException::forContainerReferenceInKey($projectConfigFile, implode('.', [...$parentPath, $key]));
        }
    }

    /**
     * @param list<array-key> $path
     *
     * @throws MalformedProjectConfigException
     */
    private function assertValue(string $projectConfigFile, mixed $value, array $path): void
    {
        if (\is_array($value)) {
            $this->assertEntries($projectConfigFile, $value, $path);
        }

        if (\is_string($value)) {
            $this->assertText($projectConfigFile, $value, implode('.', $path));
        }
    }

    /**
     * @throws MalformedProjectConfigException
     */
    private function assertText(string $projectConfigFile, string $value, string $setting): void
    {
        if (!TerminalText::isPlain($value)) {
            throw MalformedProjectConfigException::forControlCharacter($projectConfigFile, $setting);
        }

        if ($this->holdsWorkflowCommand($value)) {
            throw MalformedProjectConfigException::forWorkflowCommand($projectConfigFile, $setting);
        }

        if ($this->isResolvedByTheContainer($value)) {
            throw MalformedProjectConfigException::forContainerReference($projectConfigFile, $setting);
        }

        if (\in_array($setting, self::MODEL_SETTINGS, true) && 1 !== preg_match(self::MODEL_ID, $value)) {
            throw MalformedProjectConfigException::forModelName($projectConfigFile, $setting);
        }
    }

    private function holdsWorkflowCommand(string $text): bool
    {
        return str_contains($text, self::WORKFLOW_COMMAND_MARKER) || str_contains($text, self::LEGACY_WORKFLOW_COMMAND_MARKER);
    }

    private function isResolvedByTheContainer(string $text): bool
    {
        return ContainerParameterSyntax::holdsReference($text) || ContainerParameterSyntax::holdsEnvPlaceholder($text);
    }
}
