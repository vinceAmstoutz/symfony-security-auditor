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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\RecordingToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;

/**
 * {@see ReachTrackingTool} for a recording tool, which it stays.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReachTrackingRecordingTool implements RecordingToolInterface
{
    public function __construct(
        private RecordingToolInterface $recordingTool,
        private RecordingToolReach $recordingToolReach,
    ) {}

    #[Override]
    public function definition(): ToolDefinition
    {
        $this->recordingToolReach->note();

        return $this->recordingTool->definition();
    }

    #[Override]
    public function execute(array $arguments): string
    {
        $this->recordingToolReach->note();

        return $this->recordingTool->execute($arguments);
    }
}
