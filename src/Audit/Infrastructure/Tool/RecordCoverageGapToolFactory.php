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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\CoverageGapCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\RecordCoverageGapToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class RecordCoverageGapToolFactory implements RecordCoverageGapToolFactoryInterface
{
    #[Override]
    public function create(CoverageGapCollector $coverageGapCollector): ToolInterface
    {
        return new RecordCoverageGapTool($coverageGapCollector);
    }
}
