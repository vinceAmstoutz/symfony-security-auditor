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
    private const array ISOLATING_OPTIONS = ['tools' => [], 'strict_mcp_config' => true];

    private const int LONGEST_COMMAND_LINE_ARGUMENT = 131071;

    public function __construct(
        private PlatformInterface $platform,
    ) {}

    #[Override]
    public function invoke(string|Model $model, array|string|object $input, array $options = []): DeferredResult
    {
        if ($input instanceof MessageBag && $this->longestPrompt($input) > self::LONGEST_COMMAND_LINE_ARGUMENT) {
            throw new ExceedContextSizeException(\sprintf('The prompt is longer than the %d bytes one command-line argument of the CLI can carry.', self::LONGEST_COMMAND_LINE_ARGUMENT));
        }

        return $this->platform->invoke($model, $input, self::ISOLATING_OPTIONS);
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->platform->getModelCatalog();
    }

    private function longestPrompt(MessageBag $messageBag): int
    {
        return max([0, ...array_map($this->promptLength(...), $messageBag->getMessages())]);
    }

    private function promptLength(MessageInterface $message): int
    {
        return match (true) {
            $message instanceof UserMessage => \strlen($message->asText() ?? ''),
            $message instanceof SystemMessage => \strlen((string) $message->getContent()),
            default => 0,
        };
    }
}
