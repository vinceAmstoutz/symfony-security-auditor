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
 * Maps a vulnerability severity to a Symfony Console foreground color, so the
 * decorated findings feed is colored by risk. Lives in Infrastructure because
 * the color scheme is a presentation concern — the Domain enum stays free of
 * rendering details.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
