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
 * States the rates a human report's cost was priced at and, when calls were
 * cut mid-answer, that the cost is a minimum.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CostRateLabel
{
    /**
     * @param ?string $subscription the subscription a coding agent's CLI ran the audit on, such as "your Claude subscription", which is not priced per call
     */
    public static function of(AuditCost $auditCost, ?string $subscription = null): string
    {
        $rates = match (true) {
            null !== $subscription => \sprintf('not priced per call: billed to %s, or to an API key the CLI uses in its place', $subscription),
            $auditCost->hasPublishedPricing() => 'published rates',
            default => 'no published pricing, or a self-hosted model',
        };

        return match ($auditCost->interruptedCalls()) {
            0 => $rates,
            1 => \sprintf('%s; at least: 1 call was cut before its answer ended and may be billed more', $rates),
            default => \sprintf('%s; at least: %d calls were cut before their answer ended and may be billed more', $rates, $auditCost->interruptedCalls()),
        };
    }
}
