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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic;

/**
 * How many gaps the coverage critic may name, and whether it records them
 * through `record_coverage_gap` or answers with JSON, as the attacker does
 * under `audit.structured_collection`.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CoverageCriticSettings
{
    public const int DEFAULT_MAX_GAPS = 5;

    public function __construct(
        public int $maxGaps = self::DEFAULT_MAX_GAPS,
        public bool $structuredCollection = true,
    ) {}
}
