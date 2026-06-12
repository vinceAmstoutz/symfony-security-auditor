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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration;

/**
 * Derives the pre-flight notices `audit:run` prints for configuration
 * combinations that silently disable a cost saver.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ConfigurationNotices
{
    /**
     * @return list<string>
     */
    public static function of(CacheConfiguration $cacheConfiguration, AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $lLMConfiguration): array
    {
        $notices = [];

        if ($cacheConfiguration->enabled && $auditExecutionConfiguration->reviewerBatchSize > 1) {
            $notices[] = 'The reviewer-verdict cache does not apply to batched reviews (audit.reviewer_batch_size > 1): every finding is re-reviewed by the LLM on each run. Set audit.reviewer_batch_size: 1 to reuse cached verdicts.';
        }

        if ($auditExecutionConfiguration->escalationEnabled && self::escalationCheapModel($auditExecutionConfiguration, $lLMConfiguration) === $lLMConfiguration->attackerModel()) {
            $notices[] = 'Cheap-then-expensive escalation is enabled but its cheap model resolves to the attacker model, so the cheap sweep costs as much as the expensive pass and saves nothing. Set audit.escalation.cheap_model to a genuinely cheaper model (e.g. claude-haiku-4-5-20251001).';
        }

        return $notices;
    }

    private static function escalationCheapModel(AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $lLMConfiguration): string
    {
        return $auditExecutionConfiguration->escalationCheapModel ?? $lLMConfiguration->reviewerModel();
    }
}
