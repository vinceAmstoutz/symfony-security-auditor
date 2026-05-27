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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

/**
 * Opt-in extension of {@see LLMClientInterface} for clients that can resolve
 * several independent prompts concurrently. Consumers check
 * `instanceof BatchCapableLLMClientInterface` and fall back to looping
 * {@see LLMClientInterface::complete()} when it is not implemented, so adding
 * this capability never breaks an existing client.
 *
 * Implementations MUST preserve input order in the returned list (response[i]
 * corresponds to requests[i]) and MUST be behaviourally identical to calling
 * `complete()` once per request — the only difference is wall-clock latency.
 * A best-effort implementation that cannot actually parallelise (e.g. a
 * provider with no async transport) is free to resolve sequentially.
 */
interface BatchCapableLLMClientInterface extends LLMClientInterface
{
    /**
     * @param list<array{system: string, user: string}> $requests
     * @param int                                       $maxConcurrent maximum in-flight requests; the batch is
     *                                                                 processed in windows of this size
     *
     * @return list<LLMResponse> responses in the same order as $requests
     */
    public function completeBatch(array $requests, int $maxConcurrent): array;
}
