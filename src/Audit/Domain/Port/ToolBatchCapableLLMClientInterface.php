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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Opt-in extension of {@see BatchCapableLLMClientInterface} for clients that
 * can resolve several independent tool-using conversations concurrently.
 * Consumers check `instanceof ToolBatchCapableLLMClientInterface` and fall
 * back to looping {@see LLMClientInterface::completeWithTools()} when it is
 * not implemented, so adding this capability never breaks an existing client.
 *
 * Implementations MUST preserve input order in the returned list (response[i]
 * corresponds to requests[i]) and MUST be behaviourally identical to calling
 * `completeWithTools()` once per request — each request's tools are executed
 * against its own registry, and the only difference is wall-clock latency.
 * A best-effort implementation that cannot actually parallelise is free to
 * resolve sequentially.
 */
interface ToolBatchCapableLLMClientInterface extends BatchCapableLLMClientInterface
{
    /**
     * @param list<array{system: string, user: string, tools: ToolRegistry}> $requests
     * @param int                                                            $maxConcurrent     maximum in-flight requests; the batch is
     *                                                                                          processed in windows of this size
     * @param int                                                            $maxToolIterations per-request cap on tool-using rounds
     *
     * @return list<LLMResponse> responses in the same order as $requests
     */
    public function completeBatchWithTools(array $requests, int $maxConcurrent, int $maxToolIterations): array;
}
