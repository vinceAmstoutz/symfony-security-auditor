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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

/**
 * Builds the tool that records the coverage critic's gaps into a given
 * collector, so the critic (Application) depends on a Domain-port tool without
 * importing the Infrastructure implementation — the bundle wires the concrete
 * factory at the composition root.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface RecordCoverageGapToolFactoryInterface
{
    public function create(CoverageGapCollector $coverageGapCollector): ToolInterface;
}
