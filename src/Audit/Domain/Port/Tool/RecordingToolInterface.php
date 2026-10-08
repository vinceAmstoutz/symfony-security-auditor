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
 * calls one has concluded.
 */
interface RecordingToolInterface extends ToolInterface {}
