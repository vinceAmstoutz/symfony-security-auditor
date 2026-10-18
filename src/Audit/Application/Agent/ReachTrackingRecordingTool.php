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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

/**
 * Tells the turn's {@see RecordingToolReach} every time the client reads the
 * wrapped tool's definition or calls it. The tool a record factory returns is
 * the turn's recording tool whether or not it says so, so a custom factory's
 * tool written before {@see RecordingToolInterface} existed still records on
 * a conversation's last round.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReachTrackingRecordingTool implements RecordingToolInterface
{
    public function __construct(
        private ToolInterface $recordingTool,
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
