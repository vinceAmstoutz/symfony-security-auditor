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
 * The scalar config flags driving attacker analysis (tools, lean mode,
 * structured collection, concurrency, tool-iteration budget).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AttackerAnalysisSettings
{
    public function __construct(
        public bool $toolsEnabled = AttackerAgent::DEFAULT_TOOLS_ENABLED,
        public int $maxToolIterations = AttackerAgent::DEFAULT_MAX_TOOL_ITERATIONS,
        public bool $leanMode = AttackerAgent::DEFAULT_LEAN_MODE,
        public bool $useStructuredCollection = AttackerAgent::DEFAULT_STRUCTURED_COLLECTION,
        public int $maxConcurrent = AttackerAgent::DEFAULT_MAX_CONCURRENT,
    ) {}
}
