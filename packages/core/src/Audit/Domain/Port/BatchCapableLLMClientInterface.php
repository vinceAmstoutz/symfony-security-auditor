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

namespace VinceAmstoutz\SecurityAuditor\Audit\Domain\Port;

/**
 * Opt-in extension of {@see LLMClientInterface} for clients that resolve
 * several independent prompts concurrently. Consumers check `instanceof` and
 * fall back to looping {@see LLMClientInterface::complete()}, so adding this
 * capability never breaks an existing client.
 *
 * Implementations MUST preserve input order (response[i] answers requests[i])
 * and MUST be behaviourally identical to calling `complete()` per request — the
 * only difference is latency. One that cannot actually parallelise is free to
 * resolve sequentially.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface BatchCapableLLMClientInterface extends LLMClientInterface
{
    /**
     * @param list<LLMRequest> $requests
     * @param int              $maxConcurrent maximum in-flight requests; the batch is processed
     *                                        in windows of this size
     *
     * @return list<LLMResponse> responses in the same order as $requests
     */
    public function completeBatch(array $requests, int $maxConcurrent): array;
}
