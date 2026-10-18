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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\RecordingToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

/**
 * Whether the client of one structured turn reached its recording tool: read
 * the tool's definition to offer it to the model, or called it, once the
 * turn's registry was handed over — building the registry reads the
 * definition too. A client that never does ignored the tools, so the model's
 * answer text is all it said about the work. Mutable by design — opted out of
 * the final readonly rule as a per-run accumulator (see
 * .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class RecordingToolReach
{
    private bool $handedOver = false;

    private bool $reached = false;

    public function track(ToolInterface $tool): RecordingToolInterface
    {
        return new ReachTrackingRecordingTool($tool, $this);
    }

    public function handOver(): void
    {
        $this->handedOver = true;
    }

    public function note(): void
    {
        $this->reached = $this->handedOver;
    }

    public function reached(): bool
    {
        return $this->reached;
    }
}
