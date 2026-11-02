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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;

/**
 * What the cost a human report shows rests on: the rates it was priced at,
 * and, when calls were cut before their answer ended, that it is a minimum,
 * since a provider may bill such a call beyond the usage it reported.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CostRateLabel
{
    public static function of(AuditCost $auditCost): string
    {
        $rates = $auditCost->hasPublishedPricing() ? 'published rates' : 'no published pricing, or a self-hosted model';

        return match ($auditCost->interruptedCalls()) {
            0 => $rates,
            1 => \sprintf('%s; at least: 1 call was cut before its answer ended and may be billed more', $rates),
            default => \sprintf('%s; at least: %d calls were cut before their answer ended and may be billed more', $rates, $auditCost->interruptedCalls()),
        };
    }
}
