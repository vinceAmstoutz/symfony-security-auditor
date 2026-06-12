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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/** @internal not part of the BC promise — the enum *values* (`pipeline.started`, `stage.started`, `stage.completed`, `pipeline.completed`, `audit.iteration.started`, `attacker.chunk.started`, `review.started`) are the wire-format event names carried through `ProgressReporterInterface::report()` and are stable, but the PHP enum itself is for internal use only. */
enum ProgressEvent: string
{
    case PipelineStarted = 'pipeline.started';
    case StageStarted = 'stage.started';
    case StageCompleted = 'stage.completed';
    case PipelineCompleted = 'pipeline.completed';
    case AuditIterationStarted = 'audit.iteration.started';
    case AttackerChunkStarted = 'attacker.chunk.started';
    case ReviewStarted = 'review.started';
}
