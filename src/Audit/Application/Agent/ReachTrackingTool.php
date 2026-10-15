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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

/**
 * Tells the turn's {@see RecordingToolReach} every time the client reads the
 * wrapped tool's definition or calls it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReachTrackingTool implements ToolInterface
{
    public function __construct(
        private ToolInterface $tool,
        private RecordingToolReach $recordingToolReach,
    ) {}

    #[Override]
    public function definition(): ToolDefinition
    {
        $this->recordingToolReach->note();

        return $this->tool->definition();
    }

    #[Override]
    public function execute(array $arguments): string
    {
        $this->recordingToolReach->note();

        return $this->tool->execute($arguments);
    }
}
