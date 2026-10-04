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

use Symfony\AI\Platform\Result\DeferredResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

/**
 * One request of a batch window after dispatch: the deferred answer when the
 * platform took it, null when the dispatch itself failed, or the answer it
 * already has when the rate-limit window refused it as too large to send.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class DispatchedRequest
{
    public function __construct(
        public ?DeferredResult $deferredResult,
        public int $estimatedInputTokens,
        public ?LLMResponse $answer = null,
    ) {}
}
