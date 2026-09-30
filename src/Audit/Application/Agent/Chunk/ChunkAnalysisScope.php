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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * What every chunk of one attacker pass is analyzed against: the request, the
 * indexed risk markers and the investigation tools. Lets a chunk carved out
 * mid-pass — the half of a chunk the model could not fit — be analyzed exactly
 * like the chunks the pass started with.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkAnalysisScope
{
    public function __construct(
        public AttackerAnalysisRequest $attackerAnalysisRequest,
        public RiskMarkerIndex $riskMarkerIndex,
        public ?ToolRegistry $toolRegistry,
    ) {}
}
