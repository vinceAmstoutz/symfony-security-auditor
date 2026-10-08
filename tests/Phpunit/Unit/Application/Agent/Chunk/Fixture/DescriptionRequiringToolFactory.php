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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordVulnerabilityToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityTool;

/**
 * Test fake: a custom factory publishing a recording tool that refuses a call
 * without a `description`.
 */
final readonly class DescriptionRequiringToolFactory implements RecordVulnerabilityToolFactoryInterface
{
    #[Override]
    public function create(VulnerabilityCollector $vulnerabilityCollector): ToolInterface
    {
        return new DescriptionRequiringRecordingTool(new RecordVulnerabilityTool($vulnerabilityCollector));
    }
}
