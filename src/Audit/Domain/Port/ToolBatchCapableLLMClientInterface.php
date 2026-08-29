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
 * Opt-in extension of {@see BatchCapableLLMClientInterface} for clients that
 * resolve several independent tool-using conversations concurrently. Consumers
 * check `instanceof` and fall back to looping
 * {@see LLMClientInterface::completeWithTools()}, so adding this capability
 * never breaks an existing client.
 *
 * Implementations MUST preserve input order (response[i] answers requests[i])
 * and MUST match calling `completeWithTools()` per request — each request's
 * tools run against its own registry; only latency differs.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface ToolBatchCapableLLMClientInterface extends BatchCapableLLMClientInterface
{
    /**
     * @param list<ToolLLMRequest> $requests
     * @param int                  $maxConcurrent     maximum in-flight requests; the batch is
     *                                                processed in windows of this size
     * @param int                  $maxToolIterations per-request cap on tool-using rounds
     *
     * @return list<LLMResponse> responses in the same order as $requests
     */
    public function completeBatchWithTools(array $requests, int $maxConcurrent, int $maxToolIterations): array;
}
