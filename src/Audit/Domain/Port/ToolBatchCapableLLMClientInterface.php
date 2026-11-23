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
 * Optional extension of {@see BatchCapableLLMClientInterface}, checked with
 * `instanceof`: resolves several independent tool conversations concurrently.
 *
 * Implementations MUST return the responses in request order and behave
 * exactly like one `completeWithTools()` per request, each running its tools
 * against its own registry. One that cannot parallelise may resolve them
 * sequentially.
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
