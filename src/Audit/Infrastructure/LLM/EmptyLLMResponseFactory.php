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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

/**
 * Builds the degraded `LLMResponse` every call path returns for an answer
 * with nothing usable in it.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class EmptyLLMResponseFactory
{
    public function create(string $model, TokenUsageSnapshot $tokenUsageSnapshot, string $stopReason = 'empty_content'): LLMResponse
    {
        return LLMResponse::of('', $model, $stopReason, $tokenUsageSnapshot);
    }
}
