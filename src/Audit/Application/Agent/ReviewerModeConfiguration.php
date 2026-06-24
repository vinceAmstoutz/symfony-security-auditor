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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

/**
 * The reviewer-pass tuning knobs that select and parameterize a review strategy.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReviewerModeConfiguration
{
    public function __construct(
        public int $batchSize = ReviewerAgent::DEFAULT_BATCH_SIZE,
        public bool $toolsEnabled = ReviewerAgent::DEFAULT_TOOLS_ENABLED,
        public int $maxToolIterations = ReviewerAgent::DEFAULT_MAX_TOOL_ITERATIONS,
        public int $maxConcurrent = ReviewerAgent::DEFAULT_MAX_CONCURRENT,
        public bool $useStructuredCollection = ReviewerAgent::DEFAULT_STRUCTURED_COLLECTION,
    ) {}
}
