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
final readonly class LeanModeHasNoEffectNotice implements ConfigurationNoticeInterface
{
    #[Override]
    public function noticesFor(AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $llmConfiguration): array
    {
        if (!$auditExecutionConfiguration->staticPreScanLeanMode || $auditExecutionConfiguration->staticPreScanEnabled) {
            return [];
        }

        return ['audit.static_prescan.lean_mode has no effect while audit.static_prescan.enabled is false: with no risk markers, lean mode would drop every file, so all files are analysed instead. Enable static_prescan to use lean mode, or set lean_mode: false to silence this.'];
    }
}
