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
final readonly class ConcurrentAttackerHasNoEffectNotice implements ConfigurationNoticeInterface
{
    #[Override]
    public function noticesFor(AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $llmConfiguration): array
    {
        if ($auditExecutionConfiguration->attackerMaxConcurrent <= 1 || $auditExecutionConfiguration->structuredCollection) {
            return [];
        }

        return ['audit.attacker_max_concurrent > 1 has no effect while audit.structured_collection is false: the JSON-parsing attacker analyses chunks sequentially. Re-enable structured_collection to analyse concurrently, or set attacker_max_concurrent: 1 to silence this.'];
    }
}
