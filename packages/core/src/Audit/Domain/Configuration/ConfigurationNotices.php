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

namespace VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration;

use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\Notice\ConcurrentAttackerHasNoEffectNotice;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\Notice\ConcurrentReviewsHaveNoEffectNotice;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\Notice\ConfigurationNoticeInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\Notice\EscalationSavesNothingNotice;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\Notice\IgnoredOutputCapNotice;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\Notice\LeanModeHasNoEffectNotice;

/**
 * Collects every {@see ConfigurationNoticeInterface} rule and emits the
 * pre-flight notices `audit:run` prints. A new footgun is a new rule class
 * listed in {@see self::defaultNotices()}; nothing else changes.
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
        foreach (self::defaultNotices() as $configurationNotice) {
            foreach ($configurationNotice->noticesFor($auditExecutionConfiguration, $lLMConfiguration) as $message) {
                $notices[] = $message;
            }
        }

        return $notices;
    }

    /**
     * @return list<ConfigurationNoticeInterface>
     */
    private static function defaultNotices(): array
    {
        return [
            new EscalationSavesNothingNotice(),
            new ConcurrentReviewsHaveNoEffectNotice(),
            new ConcurrentAttackerHasNoEffectNotice(),
            new LeanModeHasNoEffectNotice(),
            new IgnoredOutputCapNotice(),
        ];
    }
}
