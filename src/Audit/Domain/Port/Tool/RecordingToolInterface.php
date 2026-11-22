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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool;

/**
 * A tool that hands the model's answer (a finding, a verdict) to the collector
 * instead of reading anything back. A last allowed round that made a call one
 * took in concludes the conversation.
 *
 * A call the tool took in is answered with `RECORDED`; any other answer (an
 * `Error: …` text) is a refusal the model may retry, not a recording.
 */
interface RecordingToolInterface extends ToolInterface
{
    public const string RECORDED = 'recorded';
}
