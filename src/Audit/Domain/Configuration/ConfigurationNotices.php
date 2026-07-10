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
    public static function of(AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $lLMConfiguration): array
    {
        $notices = [];

        if (self::escalationSavesNothing($auditExecutionConfiguration, $lLMConfiguration)) {
            $notices[] = 'Cheap-then-expensive escalation is enabled but its cheap model resolves to the attacker model, so the cheap sweep costs as much as the expensive pass and saves nothing. Set audit.escalation.cheap_model to a genuinely cheaper model (e.g. claude-haiku-4-5-20251001).';
        }

        if (self::concurrentReviewsHaveNoEffect($auditExecutionConfiguration)) {
            $notices[] = 'audit.reviewer_max_concurrent > 1 has no effect while audit.reviewer_tools_enabled is true: tool-using reviews run sequentially. Drop reviewer_tools_enabled to review concurrently, or set reviewer_max_concurrent: 1 to silence this.';
        }

        if (self::concurrentAttackerHasNoEffect($auditExecutionConfiguration)) {
            $notices[] = 'audit.attacker_max_concurrent > 1 has no effect while audit.structured_collection is false: the JSON-parsing attacker analyses chunks sequentially. Re-enable structured_collection to analyse concurrently, or set attacker_max_concurrent: 1 to silence this.';
        }

        if (self::leanModeHasNoEffect($auditExecutionConfiguration)) {
            $notices[] = 'audit.static_prescan.lean_mode has no effect while audit.static_prescan.enabled is false: with no risk markers, lean mode would drop every file, so all files are analysed instead. Enable static_prescan to use lean mode, or set lean_mode: false to silence this.';
        }

        return $notices;
    }

    private static function escalationSavesNothing(AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $lLMConfiguration): bool
    {
        return $auditExecutionConfiguration->escalationEnabled
            && self::escalationCheapModel($auditExecutionConfiguration, $lLMConfiguration) === $lLMConfiguration->attackerModel();
    }

    private static function concurrentReviewsHaveNoEffect(AuditExecutionConfiguration $auditExecutionConfiguration): bool
    {
        return $auditExecutionConfiguration->reviewerMaxConcurrent > 1 && $auditExecutionConfiguration->reviewerToolsEnabled;
    }

    private static function concurrentAttackerHasNoEffect(AuditExecutionConfiguration $auditExecutionConfiguration): bool
    {
        return $auditExecutionConfiguration->attackerMaxConcurrent > 1 && !$auditExecutionConfiguration->structuredCollection;
    }

    private static function leanModeHasNoEffect(AuditExecutionConfiguration $auditExecutionConfiguration): bool
    {
        return $auditExecutionConfiguration->staticPreScanLeanMode && !$auditExecutionConfiguration->staticPreScanEnabled;
    }

    private static function escalationCheapModel(AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $lLMConfiguration): string
    {
        return $auditExecutionConfiguration->escalationCheapModel ?? $lLMConfiguration->reviewerModel();
    }
}
