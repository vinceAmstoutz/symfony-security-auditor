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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;

/**
 * The Symfony Console foreground color of a severity.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class SeverityColor
{
    public static function for(VulnerabilitySeverity $vulnerabilitySeverity): string
    {
        return match ($vulnerabilitySeverity) {
            VulnerabilitySeverity::CRITICAL => 'red',
            VulnerabilitySeverity::HIGH => 'bright-red',
            VulnerabilitySeverity::MEDIUM => 'yellow',
            VulnerabilitySeverity::LOW => 'green',
            VulnerabilitySeverity::INFO => 'blue',
        };
    }
}
