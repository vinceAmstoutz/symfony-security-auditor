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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AnthropicOptionDialect;

/**
 * Reports a raised `max_output_tokens` on a model whose bridge would reject it.
 * Keyed on model *and* cap, so a split cap on one shared model reports both
 * roles instead of the second overwriting the first.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class IgnoredOutputCapNotice implements ConfigurationNoticeInterface
{
    #[Override]
    public function noticesFor(AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $lLMConfiguration): array
    {
        $notices = [];
        foreach ($this->ignoredRoleCaps($auditExecutionConfiguration, $lLMConfiguration) as ['model' => $model, 'cap' => $cap]) {
            $notices[] = \sprintf('max_output_tokens is set to %d but %s does not use the Anthropic option dialect, and its own bridge would reject the max_tokens option — so the option is not sent and the cap is not applied. Remove the key, or cap output on a model whose bridge honors it.', $cap, $model);
        }

        return $notices;
    }

    /**
     * @return list<array{model: string, cap: int}>
     */
    private function ignoredRoleCaps(AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $lLMConfiguration): array
    {
        $ignored = [];
        foreach ($this->roleCaps($auditExecutionConfiguration, $lLMConfiguration) as [$model, $cap]) {
            if (LLMConfiguration::DEFAULT_MAX_OUTPUT_TOKENS === $cap || AnthropicOptionDialect::honoredBy($model)) {
                continue;
            }

            $ignored[\sprintf('%s|%d', $model, $cap)] = ['model' => $model, 'cap' => $cap];
        }

        return array_values($ignored);
    }

    /**
     * @return list<array{0: string, 1: int}>
     */
    private function roleCaps(AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $lLMConfiguration): array
    {
        $roleCaps = [
            [$lLMConfiguration->attackerModel(), $lLMConfiguration->attackerMaxOutputTokens()],
            [$lLMConfiguration->reviewerModel(), $lLMConfiguration->reviewerMaxOutputTokens()],
        ];

        if ($auditExecutionConfiguration->escalationEnabled) {
            $roleCaps[] = [$auditExecutionConfiguration->effectiveEscalationCheapModel($lLMConfiguration->reviewerModel()), $lLMConfiguration->attackerMaxOutputTokens()];
        }

        return $roleCaps;
    }
}
