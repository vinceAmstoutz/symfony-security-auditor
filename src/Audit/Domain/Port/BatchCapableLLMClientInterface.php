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
 * Optional extension of {@see LLMClientInterface}, checked with `instanceof`:
 * resolves several independent prompts concurrently.
 *
 * Implementations MUST return the responses in request order and behave
 * exactly like one `complete()` per request. One that cannot parallelise may
 * resolve them sequentially.
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
