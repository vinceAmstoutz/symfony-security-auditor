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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Override;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Message\MessageInterface;
use Symfony\AI\Platform\Message\SystemMessage;
use Symfony\AI\Platform\Message\UserMessage;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\CliAgentCommandLineTooLongException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\CliAgentPromptTooLongException;

/**
 * Runs a coding agent's CLI on the user's subscription as a plain model, its
 * built-in tools off, so the audited code cannot make it act on the machine.
 * Refuses as too large a prompt over the 128 KiB Linux allows one
 * command-line argument.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CliAgentPlatform implements PlatformInterface
{
    private const int LONGEST_COMMAND_LINE_ARGUMENT = 131071;

    private const int SHARED_ARGUMENT_FRAME = 18;

    // cmd.exe, which Symfony Process starts every command through on Windows, refuses a longer command line.
    private const int LONGEST_WINDOWS_COMMAND_LINE = 8191;

    private const int WINDOWS_PROMPT_ROOM = 7000;

    /**
     * @param CliAgentWorkingDirectory $workingDirectory        the directory the CLI starts in, kept as long as this platform
     * @param array<string, mixed>     $isolatingOptions        the CLI flags that keep the agent from acting, sent in place of the auditor's options
     * @param bool                     $promptsShareOneArgument whether the CLI joins the system and user prompts into one argument, framed by `[System]` and `[User]` lines
     * @param bool                     $onWindows               whether the CLI starts through cmd.exe, whose command line leaves the prompts WINDOWS_PROMPT_ROOM bytes
     */
    public function __construct(
        private PlatformInterface $platform,
        private CliAgentWorkingDirectory $workingDirectory,
        private array $isolatingOptions,
        private bool $promptsShareOneArgument = false,
        private bool $onWindows = \PHP_OS_FAMILY === 'Windows',
    ) {}

    /**
     * @throws CliAgentCommandLineTooLongException when the request cannot start the CLI however it is split
     * @throws CliAgentPromptTooLongException      when a smaller request may fit
     */
    #[Override]
    public function invoke(string|Model $model, array|string|object $input, array $options = []): DeferredResult
    {
        if ($input instanceof MessageBag) {
            $this->assertFitsTheCommandLine($input);
        }

        return $this->platform->invoke($model, $input, [...$this->isolatingOptions, 'cwd' => $this->workingDirectory->path]);
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->platform->getModelCatalog();
    }

    /**
     * @throws CliAgentCommandLineTooLongException when no split can make the request fit
     * @throws CliAgentPromptTooLongException      when a smaller request may fit
     */
    private function assertFitsTheCommandLine(MessageBag $messageBag): void
    {
        if ($this->onWindows) {
            $this->assertFitsTheWindowsCommandLine($messageBag);
        }

        if ($this->outgrowsOneArgument($messageBag)) {
            throw CliAgentPromptTooLongException::forOneArgument(self::LONGEST_COMMAND_LINE_ARGUMENT);
        }
    }

    /**
     * @throws CliAgentCommandLineTooLongException
     * @throws CliAgentPromptTooLongException
     */
    private function assertFitsTheWindowsCommandLine(MessageBag $messageBag): void
    {
        $systemPromptBytes = \strlen((string) $messageBag->getSystemMessage()?->getContent());
        if ($systemPromptBytes > self::WINDOWS_PROMPT_ROOM) {
            throw CliAgentCommandLineTooLongException::onWindows(self::LONGEST_WINDOWS_COMMAND_LINE, $systemPromptBytes);
        }

        if (array_sum($this->promptLengths($messageBag)) > self::WINDOWS_PROMPT_ROOM) {
            throw CliAgentPromptTooLongException::forTheWindowsCommandLine(self::WINDOWS_PROMPT_ROOM);
        }
    }

    /**
     * @return list<int>
     */
    private function promptLengths(MessageBag $messageBag): array
    {
        return array_map(fn (MessageInterface $message): int => \strlen($this->promptOf($message) ?? ''), $messageBag->getMessages());
    }

    private function outgrowsOneArgument(MessageBag $messageBag): bool
    {
        $lengths = $this->promptLengths($messageBag);

        return $this->promptsShareOneArgument
            ? array_sum($lengths) + self::SHARED_ARGUMENT_FRAME > self::LONGEST_COMMAND_LINE_ARGUMENT
            : [] !== array_filter($lengths, static fn (int $length): bool => $length > self::LONGEST_COMMAND_LINE_ARGUMENT);
    }

    private function promptOf(MessageInterface $message): ?string
    {
        return match (true) {
            $message instanceof UserMessage => $message->asText(),
            $message instanceof SystemMessage => (string) $message->getContent(),
            default => null,
        };
    }
}
