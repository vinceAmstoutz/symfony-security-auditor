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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;

/**
 * The optional token-usage and budget bookkeeping sinks.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformAccountingConfig
{
    public function __construct(
        public ?TokenUsageRecorder $tokenUsageRecorder = null,
        public ?BudgetTracker $budgetTracker = null,
    ) {}
}
