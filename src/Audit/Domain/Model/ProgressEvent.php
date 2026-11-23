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

/** @internal not part of the BC promise; its values are the stable event names `ProgressReporterInterface::report()` carries. */
enum ProgressEvent: string
{
    case PipelineStarted = 'pipeline.started';
    case StageStarted = 'stage.started';
    case StageCompleted = 'stage.completed';
    case PipelineCompleted = 'pipeline.completed';
    case AuditStarted = 'audit.started';
    case AuditIterationStarted = 'audit.iteration.started';
    case AttackerChunkStarted = 'attacker.chunk.started';
    case AttackerChunkCompleted = 'attacker.chunk.completed';
    case AttackerFindingRecorded = 'attacker.finding.recorded';
    case ReviewStarted = 'review.started';
    case ReviewSkipped = 'review.skipped';
    case ReviewFindingReviewed = 'review.finding.reviewed';
    case BaselineFindingSkipped = 'baseline.finding.skipped';
    case ReviewCompleted = 'review.completed';
}
