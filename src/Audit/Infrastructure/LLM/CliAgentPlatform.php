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
use Symfony\AI\Platform\Exception\ExceedContextSizeException;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Message\MessageInterface;
use Symfony\AI\Platform\Message\SystemMessage;
use Symfony\AI\Platform\Message\UserMessage;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;

/**
 * A platform that runs a coding agent's own CLI on the user's subscription,
 * used as a plain model: the CLI's built-in tools are turned off, so the
 * audited code it reads cannot make it act on the machine. The CLI takes the
 * prompt as one command-line argument, which Linux caps at 128 KiB, so a
 * longer one is refused as too large and the chunk holding it gets split.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CliAgentPlatform implements PlatformInterface
{
    private const int LONGEST_COMMAND_LINE_ARGUMENT = 131071;

    private const int SHARED_ARGUMENT_FRAME = 18;

    /**
     * @param array<string, mixed> $isolatingOptions        the CLI flags that keep the agent from acting, sent in place of the auditor's options
     * @param bool                 $promptsShareOneArgument whether the CLI joins the system and user prompts into one argument, framed by `[System]` and `[User]` lines
     */
    public function __construct(
        private PlatformInterface $platform,
        private array $isolatingOptions,
        private bool $promptsShareOneArgument = false,
    ) {}

    #[Override]
    public function invoke(string|Model $model, array|string|object $input, array $options = []): DeferredResult
    {
        if ($input instanceof MessageBag && $this->outgrowsOneArgument($input)) {
            throw new ExceedContextSizeException(\sprintf('The prompt is longer than the %d bytes one command-line argument of the CLI can carry.', self::LONGEST_COMMAND_LINE_ARGUMENT));
        }

        return $this->platform->invoke($model, $input, $this->isolatingOptions);
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->platform->getModelCatalog();
    }

    private function outgrowsOneArgument(MessageBag $messageBag): bool
    {
        $lengths = array_map(fn (MessageInterface $message): int => \strlen($this->promptOf($message) ?? ''), $messageBag->getMessages());

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
