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
 * A tool that hands the model's answer to the collector (a finding, a verdict)
 * instead of reading anything back: a conversation whose last allowed round
 * made a call one took in has concluded.
 *
 * A call the tool took in is answered with `RECORDED`; any other answer (an
 * `Error: …` text) is a refusal the model reads and may retry, which is not a
 * recording.
 */
interface RecordingToolInterface extends ToolInterface
{
    public const string RECORDED = 'recorded';
}
