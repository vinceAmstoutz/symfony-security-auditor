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

namespace VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM;

use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\LLMResponse;

/**
 * Builds the degraded `empty_content` `LLMResponse` that every call path
 * returns after `TransientFailureClassifier::isEmptyContent()` classifies a
 * platform failure as "the model answered with no content blocks". Callers
 * keep their own logging (message text and level differ per call site) and
 * only share this terminal construction step.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class EmptyLLMResponseFactory
{
    public function create(string $model, TokenUsageSnapshot $tokenUsageSnapshot): LLMResponse
    {
        return LLMResponse::of('', $model, 'empty_content', $tokenUsageSnapshot);
    }
}
