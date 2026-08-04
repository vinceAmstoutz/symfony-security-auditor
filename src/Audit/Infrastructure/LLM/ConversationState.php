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

use Symfony\AI\Platform\Message\MessageBag;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

/**
 * One tool-using conversation's position in the wavefront: its message bag and
 * platform options, the token counters accumulated across rounds, whether a
 * tool has already run (a conversation that ran one cannot be restarted from
 * scratch), the finalized response once it has one, and the running estimate
 * the rate limiter reserves against.
 *
 * Updates are copy-on-write — `$bag` is a mutable collaborator whose contents
 * are appended in place, but every scalar transition returns a new instance.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ConversationState
{
    /**
     * @param array<string, mixed> $options
     */
    public function __construct(
        public MessageBag $bag,
        public array $options,
        public int $input,
        public int $output,
        public int $cacheRead,
        public int $cacheCreation,
        public bool $toolsRan,
        public ?LLMResponse $response,
        public int $estimatedInputTokens,
    ) {}

    public function withRecordedTokens(int $input, int $output, int $cacheRead, int $cacheCreation): self
    {
        return new self(
            $this->bag,
            $this->options,
            $this->input + $input,
            $this->output + $output,
            $this->cacheRead + $cacheRead,
            $this->cacheCreation + $cacheCreation,
            $this->toolsRan,
            $this->response,
            $this->estimatedInputTokens,
        );
    }

    public function withResponse(LLMResponse $llmResponse): self
    {
        return new self(
            $this->bag,
            $this->options,
            $this->input,
            $this->output,
            $this->cacheRead,
            $this->cacheCreation,
            $this->toolsRan,
            $llmResponse,
            $this->estimatedInputTokens,
        );
    }

    public function withExecutedTools(int $estimatedToolResultTokens): self
    {
        return new self(
            $this->bag,
            $this->options,
            $this->input,
            $this->output,
            $this->cacheRead,
            $this->cacheCreation,
            true,
            $this->response,
            $this->estimatedInputTokens + $estimatedToolResultTokens,
        );
    }
}
