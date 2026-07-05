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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;

/**
 * The severity partition shared by the SARIF and GitHub-annotations
 * renderers: CRITICAL/HIGH map to `error` and MEDIUM to `warning` in both
 * formats; only the low tier's label differs (SARIF `note`, GitHub `notice`).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SeverityLevelMapper
{
    public static function level(VulnerabilitySeverity $vulnerabilitySeverity, string $lowTierLabel): string
    {
        return match ($vulnerabilitySeverity) {
            VulnerabilitySeverity::CRITICAL, VulnerabilitySeverity::HIGH => 'error',
            VulnerabilitySeverity::MEDIUM => 'warning',
            VulnerabilitySeverity::LOW, VulnerabilitySeverity::INFO => $lowTierLabel,
        };
    }
}
