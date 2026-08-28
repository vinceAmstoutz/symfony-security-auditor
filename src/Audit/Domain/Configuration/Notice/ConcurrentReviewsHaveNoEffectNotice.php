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
final readonly class ConcurrentReviewsHaveNoEffectNotice implements ConfigurationNoticeInterface
{
    #[Override]
    public function noticesFor(AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $lLMConfiguration): array
    {
        if ($auditExecutionConfiguration->reviewerMaxConcurrent <= 1 || !$auditExecutionConfiguration->reviewerToolsEnabled) {
            return [];
        }

        return ['audit.reviewer_max_concurrent > 1 has no effect while audit.reviewer_tools_enabled is true: tool-using reviews run sequentially. Drop reviewer_tools_enabled to review concurrently, or set reviewer_max_concurrent: 1 to silence this.'];
    }
}
