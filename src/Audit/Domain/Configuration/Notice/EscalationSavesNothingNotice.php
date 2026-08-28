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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\Notice;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\AuditExecutionConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\LLMConfiguration;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class EscalationSavesNothingNotice implements ConfigurationNoticeInterface
{
    #[Override]
    public function noticesFor(AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $lLMConfiguration): array
    {
        if (!$auditExecutionConfiguration->escalationEnabled) {
            return [];
        }

        if ($auditExecutionConfiguration->effectiveEscalationCheapModel($lLMConfiguration->reviewerModel()) !== $lLMConfiguration->attackerModel()) {
            return [];
        }

        return ['Cheap-then-expensive escalation is enabled but its cheap model resolves to the attacker model, so the cheap sweep costs as much as the expensive pass and saves nothing. Set audit.escalation.cheap_model to a genuinely cheaper model (e.g. claude-haiku-4-5-20251001).'];
    }
}
